"""
Direction Builder

Produces K differentiated "exploration directions" for one Analyzer run.
- Validation side: pure template rendering, no LLM.
- Trigger side: rule selection plus CWE trigger-pattern knowledge (CWE-094 yields two sub-directions).
- Business-logic side: one LLM call diverges 1-3 project-specific directions from the macro context;
  the directions already fixed by the other two sides (name + goal) are injected as an "already covered"
  list so the model avoids them instead of guessing from generic patterns. Falls back to a fixed template.

Direction slots are capped per source (`SEED2_MAX_DIRECTIONS` / `SEED3_MAX_DIRECTIONS`) with no global cap:
the business-logic slots are not squeezed when the trigger rule library grows. The cost is that a CWE split
into several trigger sub-directions (CWE-094) yields 1 + 2 + 3 = 6 directions, while other CWEs yield 4-5.

This module performs no code search, uses no tools, and names no concrete classes or methods; a direction
description is only a searchlight for the downstream Explorer.
"""
import csv
import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.language_models import BaseChatModel

from logger import StdoutLogger, log_json, log_message
from analysis_agent.data_model.direction_data import DirectionDraftList
from analysis_agent.prompts.direction_prompt import (
    DIRECTION_BUILDER_SYSTEM_PROMPT,
    DIRECTION_BUILDER_USER_PROMPT_TEMPLATE,
)

# Stdout Log Phase
STDOUT_LOG_PHASE = "Vul_Detect_Agent"

# Slots are capped per source, with no global cap. The LLM-driven business-logic side keeps a fixed
# SEED3_MAX_DIRECTIONS slots regardless of trigger-library growth. The rule-driven trigger side
# (whose count grows with the CWE table; CWE-094 splits into 2) still needs a hard cap: every direction
# corresponds to a full Analyzer->CodeQL sub-pipeline, so an unbounded count would let a future rule
# addition explode the number of directions (and the cost) of a single run.
# Result: regular CWE = 1 (validation) + 1 (trigger) + <=3 (business) = <=5; CWE-094 = 1 + 2 + <=3 = <=6.
SEED2_MAX_DIRECTIONS = 3
SEED3_MAX_DIRECTIONS = 3
# README truncation limit (only very long READMEs are cut)
README_TRUNCATE_LIMIT = 8000
# Top-level package prefix depth and display count
TOP_PACKAGE_PREFIX_DEPTH = 5
TOP_PACKAGE_LIMIT = 15
# Maximum LLM retries for the business-logic side
MAX_RETRIES = 3

# Execution-step cap per direction (the validation side has fixed patterns and needs fewer steps)
_SEED_MAX_OBJECTIVES = {
    "seed1_validation": 8,
    "seed2_trigger": 12,
    "seed3_business": 16,
}


@dataclass
class Direction:
    """One exploration direction.

    direction_id is assigned by the orchestration layer (e.g. "D01") and used for log
    directories and specification provenance.
    """
    name: str                    # Short direction name
    seed: str                    # Source: seed1_validation / seed2_trigger / seed3_business
    injection_text: str          # Full direction guidance injected into the planning/global prompt
    goal: str = ""               # Goal (used to render the covered-direction list for avoidance)
    direction_id: str = ""       # Assigned during post-processing

    @property
    def max_executed_objectives(self) -> int:
        return _SEED_MAX_OBJECTIVES.get(self.seed, 6)


@dataclass
class ProjectContext:
    """Macro inputs for the direction builder (deterministic stage-0 artifacts)."""
    cwe_id: str
    project_name: str
    readme: str
    top_level_layout: str
    top_packages: str


# ==========================================
# Stage 0: project macro context (no LLM)
# ==========================================
def _read_readme(project_root: str, limit: int = README_TRUNCATE_LIMIT) -> str:
    readme_path = os.path.join(project_root, "README.md")
    if not os.path.exists(readme_path):
        return "The target project provides no README"
    try:
        with open(readme_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return "Failed to read the target project README"
    if len(content) > limit:
        return content[:limit] + "\n...[Truncated]"
    return content


def _extract_top_packages(project_data_path: Optional[str]) -> str:
    """Aggregate top-level package names from the symbol index fetch_class_details.csv (module-area hint only, no counts)."""
    if not project_data_path:
        return "(No symbol index supplied; cannot extract the top-level package structure)"
    csv_path = Path(project_data_path) / "symbol_index" / "fetch_class_details.csv"
    if not csv_path.exists():
        return "(Symbol index not found; cannot extract the top-level package structure)"

    counter: Counter = Counter()
    try:
        with open(csv_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                qualified_name = (row.get("qualified_name") or "").strip()
                if not qualified_name:
                    continue
                # Strip nested classes (after $), then strip the last class-name segment to get the package
                outer = qualified_name.split("$", 1)[0]
                if "." not in outer:
                    continue
                package = outer.rsplit(".", 1)[0]
                parts = package.split(".")
                if len(parts) < 2:
                    continue
                counter[".".join(parts[:TOP_PACKAGE_PREFIX_DEPTH])] += 1
    except Exception:
        return "(Failed to parse the top-level package structure)"

    if not counter:
        return "(No top-level package structure could be extracted)"

    top_packages = [pkg for pkg, _ in counter.most_common(TOP_PACKAGE_LIMIT)]
    return "\n".join(f"- {pkg}" for pkg in top_packages)


def _build_project_context(
    cwe_id: str,
    project_name: str,
    project_root: str,
    project_data_path: Optional[str],
) -> ProjectContext:
    # Deferred import to avoid a module-level circular dependency
    from analysis_agent.utils.text_process import get_top_level_layout

    return ProjectContext(
        cwe_id=cwe_id,
        project_name=project_name,
        readme=_read_readme(project_root),
        top_level_layout=get_top_level_layout(project_root),
        top_packages=_extract_top_packages(project_data_path),
    )


# ==========================================
# Direction text rendering
# ==========================================
def _render_direction_text(name: str, goal: str, strategy: str, roles: str = "") -> str:
    text = (
        f"[Direction name] {name}\n"
        f"[Goal] {goal}\n"
        f"[Strategy] {strategy}"
    )
    if roles:
        text += f"\n[Expected output roles (reference only, not a hard constraint)] {roles}"
    return text


def _render_covered_directions(covered: List[Direction]) -> str:
    """Render fixed directions as an "already covered" list for the business-logic side to avoid.

    Only name and goal are emitted, not injection_text: the latter contains long strategy text that
    would significantly lengthen the input without adding information for the duplication judgment.
    """
    return "\n".join(f"- [{d.seed}] {d.name}：{d.goal}" for d in covered)


# ==========================================
# Validation side (pure template, no LLM)
# ==========================================
_VALIDATION_CWE_HINT: Dict[str, str] = {
    "CWE-022": "Pay special attention to path validation, '..' filtering, absolute-path rejection, symlink handling, and path normalization (normalize / canonicalize).",
    "CWE-079": "Pay special attention to HTML escaping, character/output encoding, and allow-list tag filtering.",
    "CWE-078": "Pay special attention to command-argument escaping/quoting, shell metacharacter filtering, and whether the shell is disabled.",
    "CWE-094": "Pay special attention to expression-content filtering, class-loading allow-lists, script sandboxing, and whether black/white lists can be bypassed.",
}


def _build_seed1_validation(cwe_id: str) -> Direction:
    name = "Validation and sanitization coverage"
    goal = "Audit the project's custom security validation / filtering / escaping logic for gaps that can be bypassed."
    hint = _VALIDATION_CWE_HINT.get(
        cwe_id,
        "Pay special attention to the validation / filtering / escaping logic that corresponds to the target CWE.",
    )
    strategy = (
        "Analyze the code related to input validation, data filtering, character escaping and path normalization.\n"
        "Focus on:\n"
        "1. whether validation coverage is complete;\n"
        "2. whether a specific input pattern can bypass validation;\n"
        "3. whether failure handling is safe;\n"
        "4. third-party library functions called inside custom validation/sanitization logic -- their bodies live "
        "outside the target project's source, are out of scope for this analysis, and break the taint chain here.\n"
        f"{hint}\n"
        "Handling rule for item 4 (must follow):\n"
        "If a third-party library function called by custom validation/sanitization logic meets all of the following, "
        "record [the third-party function itself] as a summary (method-level propagation rule) to restore the taint analysis:\n"
        "  (a) it lies on the [source -> sink path currently under investigation], not on any unrelated third-party call;\n"
        "  (b) it is called by the project's custom validation/sanitization method, so tainted data really flows through it;\n"
        "  (c) there is evidence that data flows from its input argument to its return value / out-parameter / field "
        "(e.g. the return value is used in a later dangerous concatenation, assigned back to the original variable, "
        "or returned upward as the processed result).\n"
        "State explicitly: the method's matching characteristics, which input argument taint flows in from, which return value / "
        "out-parameter it flows out through (mapping_type), and which project source supports the judgment. Never output a summary without evidence.\n"
        "⚠️ Converse rule: a summary means only [taint passes through it], never [it is safe / it blocks taint]. "
        "When a validation/sanitization function looks like it \"can block\" but actually cannot in this scenario, "
        "that is exactly when it should be recorded as a summary.\n"
        "If no relevant validation code exists, report that clearly and stop."
    )
    return Direction(
        name=name,
        seed="seed1_validation",
        goal=goal,
        injection_text=_render_direction_text(
            name=name,
            goal=goal,
            strategy=strategy,
            roles="source / sink (when validation is insufficient: its input is a source, its unsanitized return/output is a sink); "
                  "summary (the third-party library function called inside the custom logic)",
        ),
    )


# ==========================================
# Trigger side (rule selection + CWE trigger-pattern knowledge)
# Note: only lists operation categories that may constitute trigger points; no concrete class/method
# names and no target modules are specified.
# ==========================================
_TRIGGER_SPECS: Dict[str, List[Dict[str, str]]] = {
    "CWE-022": [
        {
            "name": "Filesystem path sources and write points",
            "goal": "Locate every business operation that uses a path string for filesystem access, and where those path strings come from.",
            "strategy": (
                "For path traversal, the following operations may be trigger points:\n"
                "- reading, writing, creating, deleting, moving or copying files/directories;\n"
                "- archive extraction/compression (entry names used directly as destination paths);\n"
                "- writing uploaded/downloaded file names to disk;\n"
                "- loading resources/templates/configuration files (locating local resources by name).\n"
                "Use the project's business context to see how externally controllable strings (request parameters, "
                "configuration fields, entry names, upload names) are concatenated/constructed into the final access path."
            ),
        }
    ],
    "CWE-078": [
        {
            "name": "External process and command execution chains",
            "goal": "Locate every operation that ultimately executes an external process / system command, and where the command string comes from.",
            "strategy": (
                "For command injection, the following operations may be trigger points:\n"
                "- directly executing an external process / system command;\n"
                "- executing a shell script / batch file (including assembly of the script path);\n"
                "- the command-string assembly point and the final execution point being separate (through layers of utility methods / constant concatenation);\n"
                "- external strings reaching the command indirectly via environment variables, configuration files or network parameters.\n"
                "Look at both command-string assembly and final execution, not just the execution point."
            ),
        }
    ],
    "CWE-079": [
        {
            "name": "Output rendering and unescaped echo",
            "goal": "Locate every point that outputs data into a presentation context (HTML / XML / JSON / templates) and judge its escaping coverage.",
            "strategy": (
                "For XSS, the following operations may be trigger points:\n"
                "- writing to the HTTP response body / output stream;\n"
                "- variable interpolation in template rendering;\n"
                "- serialized XML / HTML / JSON output;\n"
                "- echoing user content in logs, mail, error messages, redirects and headers;\n"
                "- a point that outputs a whole concatenated string.\n"
                "Check whether escaping/encoding covers every output context (HTML text, attributes, scripts, URLs)."
            ),
        }
    ],
    "CWE-094": [
        {
            "name": "Dynamic evaluation and load-by-name execution",
            "goal": (
                "Locate points that interpret an external string as executable semantics -- both evaluating a string as a script / "
                "expression / template and loading/calling a string as a class name / method name / property name."
            ),
            "strategy": (
                "For code injection, the following operations may be trigger points:\n"
                "[Evaluation]\n"
                "- script-engine execution;\n"
                "- expression-language evaluation (EL / SpEL / OGNL, etc.);\n"
                "- rendering executable expressions in a template engine;\n"
                "[Load and call by name]\n"
                "- loading and instantiating a class by name;\n"
                "- invoking a method / setting a field by name via reflection, and dynamic evaluation of parameters as method/property names;\n"
                "- restoring objects by type name during serialization/deserialization;\n"
                "- choosing an implementation class by string during dependency injection / plugin loading.\n"
                "Both share one essence: a string is promoted from data to code / identifier. Use the business context to decide "
                "which entry points truly receive externally controllable strings."
            ),
        },
        {
            "name": "Dynamic parsing of configuration and connection parameters",
            "goal": "Locate points where configuration / properties / connection strings are parsed dynamically and may be interpreted as executable semantics.",
            "strategy": (
                "For code injection, the following operations may be trigger points:\n"
                "- dynamic parsing of configuration files (properties / YAML / XML);\n"
                "- database connection parameters or URL parameters carrying initialization / executable content;\n"
                "- third-party components that may trigger class loading or expression evaluation while parsing configuration.\n"
                "Check whether configuration values come from external input and whether parsing has execution side effects."
            ),
        },
    ],
}

_TRIGGER_FALLBACK: List[Dict[str, str]] = [
    {
        "name": "Dangerous-operation trigger points",
        "goal": "Locate the final trigger operation for the target CWE and where the data needed to trigger it comes from.",
        "strategy": (
            "Starting from the business logic, find the operations that actually trigger this vulnerability class "
            "(dangerous calls, dangerous output, dangerous parsing) and trace how externally controllable data reaches them."
        ),
    }
]


def _build_seed2_trigger(cwe_id: str) -> List[Direction]:
    specs = _TRIGGER_SPECS.get(cwe_id, _TRIGGER_FALLBACK)
    directions: List[Direction] = []
    for spec in specs:
        directions.append(Direction(
            name=spec["name"],
            seed="seed2_trigger",
            goal=spec["goal"],
            injection_text=_render_direction_text(
                name=spec["name"],
                goal=spec["goal"],
                strategy=spec["strategy"],
                roles="sink / source",
            ),
        ))
    return directions


# ==========================================
# Business-logic side (one LLM call + fallback template)
# ==========================================
def _seed3_fallback() -> Direction:
    name = "Core business data-flow boundaries"
    goal = "Identify atypical Source / Sink data-flow patterns in the project's core business."
    strategy = (
        "Analyze the project's core business functionality and identify the key paths where data flows in and out.\n"
        "Focus on whether data entering from outside is sufficiently sanitized, and whether external outputs "
        "(API return values, network requests, file writes) may carry unsanitized data."
    )
    return Direction(
        name=name,
        seed="seed3_business",
        goal=goal,
        injection_text=_render_direction_text(
            name=name,
            goal=goal,
            strategy=strategy,
            roles="source / sink / summary",
        ),
    )


def _build_seed3_business(
    context: ProjectContext,
    llm: BaseChatModel,
    log_dir: Optional[str],
    covered: List[Direction],
    max_output: int = 3,
) -> List[Direction]:
    system_prompt = DIRECTION_BUILDER_SYSTEM_PROMPT
    # The template is rendered with .format(), so injected text must escape braces first: current
    # direction text contains none, but any future "{}" (e.g. a JSON snippet in an example) would
    # raise IndexError/KeyError at render time and abort the whole project.
    user_prompt = DIRECTION_BUILDER_USER_PROMPT_TEMPLATE.format(
        project_name=context.project_name,
        cwe_id=context.cwe_id,
        readme=context.readme,
        top_level_layout=context.top_level_layout,
        top_packages=context.top_packages,
        covered_directions=_render_covered_directions(covered).replace("{", "{{").replace("}", "}}"),
        seed3_max_output=max_output,
    )

    if log_dir:
        log_json(log_dir, "seed3_direction_prompt", {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
        })

    StdoutLogger.info("Direction Builder: business-logic divergence (LLM)", STDOUT_LOG_PHASE)

    direction_llm = llm.with_structured_output(
        DirectionDraftList,
        method="json_mode",
        include_raw=True,
    )

    messages_list = []
    parsed_output: Optional[DirectionDraftList] = None
    if_response_success = False
    for i in range(MAX_RETRIES):
        StdoutLogger.info(f"    Generation Tries: {i + 1}", STDOUT_LOG_PHASE)
        msgs = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
            *messages_list,
        ]
        # Do not let exceptions from the LLM call itself (timeout, content filter, length limit, etc.)
        # escape to the caller: build_directions runs before the direction loop, so an exception would
        # abort the whole project. Treat it as a failed generation; after retries are exhausted the
        # code falls through to _seed3_fallback() below.
        try:
            whole_response = direction_llm.invoke(msgs)
        except Exception as e:
            StdoutLogger.warning(
                f"    LLM call failed for the business-logic side (attempt {i + 1}): {type(e).__name__}: {e}",
                STDOUT_LOG_PHASE,
            )
            continue
        raw_msg = whole_response["raw"]
        parsed_output = whole_response["parsed"]
        parsing_error = whole_response.get("parsing_error")

        if log_dir:
            log_message(log_dir, f"seed3_tries_{i + 1}_response.json", raw_msg)

        messages_list = [raw_msg]

        if parsed_output is None:
            messages_list.append(HumanMessage(
                f"Structured output parsing failed: {parsing_error}\nOutput a strictly valid JSON object."
            ))
            continue

        if not parsed_output.directions:
            messages_list.append(HumanMessage(
                "Validation failed: `directions` is empty. Provide at least one exploration direction for this project."
            ))
            continue

        if_response_success = True
        break

    # Fallback: use the fixed template when retries fail
    if not if_response_success or parsed_output is None:
        StdoutLogger.warning(
            "Business-logic direction generation failed; falling back to the fixed template.", STDOUT_LOG_PHASE
        )
        return [_seed3_fallback()]

    directions: List[Direction] = []
    for draft in parsed_output.directions[:max_output]:
        name = (draft.name or "").strip()
        goal = (draft.goal or "").strip()
        strategy = (draft.strategy or "").strip()
        if not (name and goal and strategy):
            continue
        directions.append(Direction(
            name=name,
            seed="seed3_business",
            goal=goal,
            injection_text=_render_direction_text(
                name=name, goal=goal, strategy=strategy, roles="source / sink / summary"
            ),
        ))

    if not directions:
        StdoutLogger.warning(
            "Generated directions have incomplete fields; falling back to the fixed template.", STDOUT_LOG_PHASE
        )
        return [_seed3_fallback()]

    return directions


# ==========================================
# Orchestration entry point
# ==========================================
def build_directions(
    cwe_id: str,
    project_name: str,
    project_root: str,
    project_data_path: Optional[str],
    llm: BaseChatModel,
    log_dir: Optional[str] = None,
) -> List[Direction]:
    """Produce the exploration directions for this run (stages 0-4). Unknown CWEs fall back to generic directions."""
    context = _build_project_context(cwe_id, project_name, project_root, project_data_path)

    directions: List[Direction] = []
    # Stage 1: validation side (pure template)
    directions.append(_build_seed1_validation(cwe_id))

    # Stage 2: trigger side (rule selection), bounded by its own hard cap.
    # Each direction corresponds to a full Analyzer->CodeQL sub-pipeline; the trigger-side count grows
    # with the rule library, so without a guard the number of directions (and cost) per run explodes.
    seed2_directions = _build_seed2_trigger(cwe_id)
    if len(seed2_directions) > SEED2_MAX_DIRECTIONS:
        StdoutLogger.warning(
            f"Trigger-side direction count {len(seed2_directions)} exceeds the cap {SEED2_MAX_DIRECTIONS}; truncating.",
            STDOUT_LOG_PHASE,
        )
        seed2_directions = seed2_directions[:SEED2_MAX_DIRECTIONS]
    directions.extend(seed2_directions)

    # Stage 3: business-logic side (one LLM divergence), bounded only by its own cap, not squeezed by
    # a remaining global slot count. Pass the already fixed directions as the covered list so it does
    # not regenerate directions of the same family as the validation/trigger sides.
    directions.extend(_build_seed3_business(
        context, llm, log_dir,
        covered=list(directions),
        max_output=SEED3_MAX_DIRECTIONS,
    ))

    # Stage 4: summarize (assign direction IDs). Each stage already converged to its cap, so no global truncation here.
    for i, direction in enumerate(directions):
        direction.direction_id = f"D{i + 1:02d}"

    StdoutLogger.info(
        "Direction Builder produced "
        + ", ".join(f"{d.direction_id}[{d.seed}] {d.name}" for d in directions),
        STDOUT_LOG_PHASE,
    )
    return directions
