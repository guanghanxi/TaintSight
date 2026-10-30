"""
assembler.py
Final assembler: deterministically splices validated predicates into a complete
DataFlow::ConfigSig. Only Summary predicates need mapping_type-based propagation
rules; others are concatenated directly.
"""
from dataclasses import dataclass, field
from typing import Optional, List

from codeql_agent.codeql_agent_data import SpecResult
# Reuse script_builder's predicate-name regex and rename logic: definition and
# reference names must be governed by one set of rules; duplicating them causes
# definition/reference mismatches.
from codeql_agent.script_builder import PREDICATE_HEAD_RE, replace_predicate_name
from logger import StdoutLogger

from global_data_model.analysis_result import SummarySpecification


STDOUT_LOG_PHASE = "codeql_agent/assembler"


# ============================================================
#  Assembler
# ============================================================

class ConfigAssembler:
    """Deterministic assembly; no LLM involved."""

    def assemble(
        self,
        validated_specs: List[SpecResult],
    ) -> str:
        """
        Splice all validated predicates into the final CodeQL taint-analysis script.
        """
        sources: List[SpecResult] = []
        sinks: List[SpecResult] = []
        flow_steps: List[SpecResult] = []
        summaries: List[SpecResult] = []

        for r in validated_specs:
            if r.role == "source":
                sources.append(r)
            elif r.role == "sink":
                sinks.append(r)
            elif r.role == "flow_step":
                flow_steps.append(r)
            elif r.role == "summary":
                summaries.append(r)

        parts: List[str] = []
        parts.append(self._header())

        parts.append(self._predicate_block(sources, "Source"))
        parts.append(self._predicate_block(sinks, "Sink"))
        parts.append(self._predicate_block(flow_steps, "FlowStep"))
        parts.append(self._predicate_block(summaries, "Summary"))
        parts.append(self._config_class(sources, sinks, flow_steps, summaries))

        script = "\n\n".join(p for p in parts if p)

        # Post-assembly invariant self-check (logs only; no control-flow change)
        self._check_definition_reference_consistency(
            script, sources, sinks, flow_steps, summaries
        )

        return script

    # ----------------------------------------------------------
    #  Assembly parts
    # ----------------------------------------------------------

    @staticmethod
    def _header() -> str:
        return (
            "import java\n"
            "import semmle.code.java.dataflow.DataFlow\n"
            "import semmle.code.java.dataflow.ExternalFlow\n"
            "import semmle.code.java.dataflow.TaintTracking\n"
        )

    @staticmethod
    def _predicate_block(specs: List[SpecResult], label: str) -> str:
        if not specs:
            return ""
        block = f"// ===== {label} Predicates =====\n"
        for r in specs:
            # Defensive: force the definition name to is_{r.spec_id} so it matches
            # the reference built by _config_class. Normally agent.py has already
            # normalized it, making this a no-op; if a rename is needed, upstream
            # missed it and this is logged as an error.
            code, renamed_from = replace_predicate_name(r.predicate_code, f"is_{r.spec_id}")
            if renamed_from is not None:
                StdoutLogger.error(
                    f"Assembly fallback rename: spec {r.spec_id}(role={r.role}) definition "
                    f"`{renamed_from}` != reference `is_{r.spec_id}` (upstream normalization missed)",
                    STDOUT_LOG_PHASE,
                )
            elif PREDICATE_HEAD_RE.search(code) is None:
                StdoutLogger.error(
                    f"Assembly: spec {r.spec_id}(role={r.role}) has no `predicate <name>(` "
                    f"declaration in predicate_code, so the definition cannot be aligned "
                    f"with reference is_{r.spec_id}; Phase 4 will fail with "
                    f"'could not resolve predicate' and produce no SARIF",
                    STDOUT_LOG_PHASE,
                )
            block += f"{code}\n\n"
        return block

    @classmethod
    def _check_definition_reference_consistency(
        cls,
        script: str,
        sources: List[SpecResult],
        sinks: List[SpecResult],
        flow_steps: List[SpecResult],
        summaries: List[SpecResult],
    ) -> List[str]:
        """
        Invariant: the set of definition names must be a superset of the set of
        reference names.

        Definitions are scanned from the generated script text
        (`predicate <name>(`); references are computed independently from
        _config_class's rules. Because the two sources differ, this is a real
        cross-check rather than duplicating one calculation.

        A violation makes Phase 4 fail with "could not resolve predicate" and
        produce no SARIF. Only an error is logged; no exception is raised and
        control flow is unchanged.

        Returns: referenced but undefined names (empty = pass).
        """
        defs = {m.group(2) for m in PREDICATE_HEAD_RE.finditer(script)}

        refs = {f"is_{r.spec_id}" for r in sources}
        refs |= {f"is_{r.spec_id}" for r in sinks}
        refs |= {f"is_{r.spec_id}" for r in flow_steps}
        for r in summaries:
            # _summary_to_taint_step emits an is_<spec_id>(...) call only when the
            # spec is a SummarySpecification with a known mapping_type; otherwise it
            # writes `false // ...` with no reference. Ask the generator itself
            # instead of duplicating the mapping_type whitelist here.
            if f"is_{r.spec_id}(" in cls._summary_to_taint_step(r):
                refs.add(f"is_{r.spec_id}")

        missing = sorted(refs - defs)
        if missing:
            StdoutLogger.error(
                f"Assembly invariant broken: referenced but undefined {missing} "
                f"({len(refs)} references / {len(defs)} definitions) -- "
                f"Phase 4 will report could not resolve predicate and produce no SARIF",
                STDOUT_LOG_PHASE,
            )
        return missing

    def _config_class(
        self,
        sources: List[SpecResult],
        sinks: List[SpecResult],
        flow_steps: List[SpecResult],
        summaries: List[SpecResult],
    ) -> str:
        """Build the final DataFlow::ConfigSig class."""
        lines: List[str] = []
        lines.append("module VulDetectConfig implements DataFlow::ConfigSig {")

        # --- isSource ---
        lines.append("  predicate isSource(DataFlow::Node node) {")
        lines.extend(self._or_body(sources, "node"))
        lines.append("  }")
        lines.append("")

        # --- isSink ---
        lines.append("  predicate isSink(DataFlow::Node node) {")
        lines.extend(self._or_body(sinks, "node"))
        lines.append("  }")
        lines.append("")

        # --- isAdditionalTaintStep ---
        has_additional = flow_steps or summaries
        if has_additional:
            lines.append(
                "  predicate isAdditionalFlowStep("
                "DataFlow::Node node1, DataFlow::Node node2) {"
            )
            body_parts: List[str] = []

            # FlowStep: call predicate(node1, node2) directly
            for r in flow_steps:
                body_parts.append(f"    is_{r.spec_id}(node1, node2)")

            # Summary: deterministic conversion by mapping_type
            for r in summaries:
                body_parts.append(self._summary_to_taint_step(r))

            lines.append("\n    or\n".join(body_parts))
            lines.append("  }")

        lines.append("}")
        lines.append("")
        lines.append("module VulDetectFlow = TaintTracking::Global<VulDetectConfig>;")

        return "\n".join(lines)

    @staticmethod
    def _or_body(specs: List[SpecResult], arg: str) -> List[str]:
        """Build the or-joined call body."""
        if not specs:
            return ["    false  // no matching rules"]
        calls = [f"    is_{r.spec_id}({arg})" for r in specs]
        return ["\n    or\n".join(calls)]

    # ----------------------------------------------------------
    #  Summary -> isAdditionalTaintStep deterministic conversion
    # ----------------------------------------------------------

    @staticmethod
    def _summary_to_taint_step(r: SpecResult) -> str:
        """
        Build a propagation rule from the SummarySpecification's mapping_type.

        mapping_type semantics:
          arg_to_return  : Argument[source_arg_index] -> Return
          this_to_return : Qualifier (this)           -> Return
          arg_to_this    : Argument[source_arg_index] -> Qualifier (this)
          this_to_arg    : Qualifier (this)           -> Argument[target_arg_index]

        In CodeQL DataFlow a call's return value is represented by the Call
        expression itself, so node.asExpr() = c denotes the return-value node.
        """
        spec = r.spec
        if not isinstance(spec, SummarySpecification):
            return "    false  // not a Summary spec; skipped"

        pred_name = f"is_{r.spec_id}"
        mapping = spec.mapping_type
        src_idx = spec.source_arg_index
        tgt_idx = spec.target_arg_index

        if mapping == "arg_to_return":
            # Taint flows from argument src_idx to the return value
            return (
                f"    exists(Call c | {pred_name}(c) |\n"
                f"      node1.asExpr().(Argument) = c.getArgument({src_idx}) and\n"
                f"      node2.asExpr() = c\n"
                f"    )"
            )

        elif mapping == "this_to_return":
            # Taint flows from this (Qualifier) to the return value
            return (
                f"    exists(Call c | {pred_name}(c) |\n"
                f"      node1.asExpr() = c.getQualifier() and\n"
                f"      node2.asExpr() = c\n"
                f"    )"
            )

        elif mapping == "arg_to_this":
            # Taint flows from argument src_idx into this (Qualifier)
            return (
                f"    exists(Call c | {pred_name}(c) |\n"
                f"      node1.asExpr().(Argument) = c.getArgument({src_idx}) and\n"
                f"      node2.asExpr() = c.getQualifier()\n"
                f"    )"
            )

        elif mapping == "this_to_arg":
            # Taint flows from this (Qualifier) into argument tgt_idx
            return (
                f"    exists(Call c | {pred_name}(c) |\n"
                f"      node1.asExpr() = c.getQualifier() and\n"
                f"      node2.asExpr().(Argument) = c.getArgument({tgt_idx})\n"
                f"    )"
            )

        else:
            return f"    false  // unknown mapping_type: {mapping}"