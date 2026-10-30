"""
role_registry.py
Role registry: prompt template, CodeQL validation script template, validation
policy and retry limits for each specification role.
"""
from dataclasses import dataclass, field
from typing import Optional


# ============================================================
#  CodeQL validation script templates
# ============================================================

# Shared by source / sink
# The agent generates: predicate is_{spec_id}(DataFlow::Node node) { ... }
NODE_FETCH_TEMPLATE = """\
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.ExternalFlow
import java

// ===== LLM-generated matching logic =====
{predicate_implication}
// ===== end of matching logic =====

// Relative path helper
bindingset[node]
string getRelativePath(DataFlow::Node node) {{
  exists(File f | f = node.getLocation().getFile() |
    result = f.getRelativePath()
  )
}}

from DataFlow::Node node
where {predicate_name}(node)
select
  getRelativePath(node) + ":" + node.getLocation().getStartLine().toString() + ":" + node.getLocation().getStartColumn().toString() as location
"""

# Summary template
# The agent generates: predicate is_{spec_id}(Call c) { ... }
SUMMARY_FETCH_TEMPLATE = """
import java

// ===== LLM-generated matching logic =====
{predicate_implication}
// ===== end of matching logic =====

// Relative path helper for Call
bindingset[c]
string getRelativePath(Call c) {{
    exists(File f | f = c.getLocation().getFile() |
        result = f.getRelativePath()
    )
}}

// Query Call c directly instead of wrapping it in DataFlow::Node, so that
// void methods (e.g. map.put) still yield a location and pass the non-empty check
from Call c
where {predicate_name}(c)
select
    getRelativePath(c) + ":" + c.getLocation().getStartLine().toString() + ":" + c.getLocation().getStartColumn().toString() as location
"""

# FlowStep template
# The agent generates: predicate is_{spec_id}(DataFlow::Node node1, DataFlow::Node node2) { ... }
FLOWSTEP_FETCH_TEMPLATE = """\
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.ExternalFlow
import java

// ===== LLM-generated matching logic =====
{predicate_implication}
// ===== end of matching logic =====

// Relative path helper
bindingset[node]
string getRelativePath(DataFlow::Node node) {{
  exists(File f | f = node.getLocation().getFile() |
    result = f.getRelativePath()
  )
}}

from DataFlow::Node node1, DataFlow::Node node2
where {predicate_name}(node1, node2)
select
  getRelativePath(node1) + ":" + node1.getLocation().getStartLine().toString() + ":" + node1.getLocation().getStartColumn().toString() as location1,
  getRelativePath(node2) + ":" + node2.getLocation().getStartLine().toString() + ":" + node2.getLocation().getStartColumn().toString() as location2
"""

# ============================================================
#  Role configuration
# ============================================================

@dataclass
class RoleConfig:
    """All configuration for one role."""
    role: str

    # --- Prompt ---
    system_prompt_file: str          # prompt template path
    predicate_signature: str         # predicate signature the LLM must generate
    predicate_name_template: str     # predicate naming template, e.g. "is_{spec_id}"

    # --- CodeQL script ---
    fetch_template: str              # validation script template (one of the constants above)

    # --- Validation policy ---
    # Counter semantics are uniformly "exceeding the limit exhausts it": after
    # count += 1, stop when count > max_xxx, i.e. max_xxx + 1 attempts are allowed.
    max_compile_retries: int = 3     # retries for compile errors
    max_empty_retries: int = 3       # retries for empty results
    max_gt_retries: int = 2          # retries when GT is not hit (declaration vs call side)
    max_runtime_retries: int = 2     # retries for code-level runtime failures; environmental failures are not retried (see retry_policy)
    max_scope_retries: int = 2       # rewrites for abnormal match scope (too many results / unconstrained nodes)
    max_total_attempts: int = 7      # total attempt ceiling per spec (cost cap), including 2 scope rewrites

    # --- Final assembly ---
    assembler_target: str = ""       # target predicate name in ConfigSig
    needs_wrapper: bool = False      # whether extra wrapping is needed (Summary only)


# ============================================================
#  Registry
# ============================================================

ROLE_REGISTRY: dict[str, RoleConfig] = {
    "source": RoleConfig(
        role="source",
        system_prompt_file="prompts/source_sink.jinja2",
        predicate_signature="predicate is_{spec_id}(DataFlow::Node node)",
        predicate_name_template="is_{spec_id}",
        fetch_template=NODE_FETCH_TEMPLATE,
        assembler_target="isSource",
    ),
    "sink": RoleConfig(
        role="sink",
        system_prompt_file="prompts/source_sink.jinja2",
        predicate_signature="predicate is_{spec_id}(DataFlow::Node node)",
        predicate_name_template="is_{spec_id}",
        fetch_template=NODE_FETCH_TEMPLATE,
        assembler_target="isSink",
    ),
    "summary": RoleConfig(
        role="summary",
        system_prompt_file="prompts/summary.jinja2",
        predicate_signature="predicate is_{spec_id}(Call c)",
        predicate_name_template="is_{spec_id}",
        fetch_template=SUMMARY_FETCH_TEMPLATE,
        assembler_target="isAdditionalTaintStep",
        needs_wrapper=True,
    ),
    "flow_step": RoleConfig(
        role="flow_step",
        system_prompt_file="prompts/flow_step.jinja2",
        predicate_signature="predicate is_{spec_id}(DataFlow::Node node1, DataFlow::Node node2)",
        predicate_name_template="is_{spec_id}",
        fetch_template=FLOWSTEP_FETCH_TEMPLATE,
        assembler_target="isAdditionalTaintStep",
    ),
}