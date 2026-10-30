"""
validator.py
Result validator: parses query output, compares with ground truth, and returns
pass/fail plus feedback.
"""
import csv
import io
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from global_data_model.analysis_result import SpecificationUnion

from codeql_agent.codeql_agent_data import ValidationResult
from codeql_agent.predicate_guard import check_predicate


# ============================================================
#  Match-scope limits
# ============================================================
# Only endpoint roles multiply directly into the result set: CodeQL results are
# reachable (source, sink) pairs, while isAdditionalFlowStep / summary only add
# propagation edges whose blowup is absorbed by reachability. Gate source/sink only.
COUNT_GATED_ROLES = ("source", "sink")

# Absolute floor so legitimately broad rules on small projects are not blocked:
# a high ratio with a small absolute count is still acceptable.
OVERSIZED_ABS_FLOOR = 500

# Ratio against method count rather than API call count: method count is a more
# stable denominator and keeps discriminating power for flow steps.
OVERSIZED_METHOD_RATIO = 1.0


class ResultValidator:

    def __init__(self, project_method_count: int = 0):
        """
        Args:
            project_method_count: number of Java methods in the target project
                (from symbol_index/fetch_func_locs.csv). When 0 (index missing),
                count gating degrades to the absolute threshold only.
        """
        self.project_method_count = project_method_count

    def validate(
        self,
        query_output: str,
        spec: SpecificationUnion,
        predicate_code: str = "",
    ) -> ValidationResult:
        """
        Validation order is significant:
        1. Empty result -> fail (empty_result)
        2. Predicate has a disjunct with unconstrained node variables
           -> fail (scope_abnormal / unbound_node)
        3. Endpoint role (source/sink) match count exceeds the limit
           -> fail (scope_abnormal / oversized_result)
        4. Non-empty result: check whether a ground_truth file_path with
           is_from_project=True is hit -> fail if none (gt_not_hit)
        5. No is_from_project=True example -> non-empty passes

        Steps 2/3 must run before step 4: a predicate that matches everything
        trivially satisfies both "non-empty" and "hits a GT path", so a
        degraded predicate would otherwise pass silently.
        """
        locations = self._parse_csv(query_output)
        diagnostics: Dict[str, object] = {}

        # Step 1: non-empty check
        if not locations:
            return ValidationResult(
                passed=False,
                failure_type="empty_result",
                result_count=0,
                feedback="Query returned no results; no nodes matched.",
                diagnostics=diagnostics,
            )

        result_count = len(locations)
        diagnostics["result_count"] = result_count

        # Step 2: predicate soundness (all roles) -- an unconstrained disjunct is proof of a defect
        soundness = check_predicate(predicate_code)
        diagnostics["soundness_checked"] = soundness.checked
        if soundness.checked:
            diagnostics["node_vars"] = soundness.vars
        if soundness.unbound:
            diagnostics["reason"] = "unbound_node"
            diagnostics["unbound"] = soundness.unbound
            return ValidationResult(
                passed=False,
                failure_type="scope_abnormal",
                result_count=result_count,
                diagnostics=diagnostics,
                feedback=(
                    f"The predicate has a disjunct with unconstrained node variables "
                    f"({sorted({u['var'] for u in soundness.unbound})}); it accepts any "
                    f"node in the program, yielding {result_count} results."
                ),
            )

        # Step 3: count gating (endpoint roles only)
        ratio = (
            result_count / self.project_method_count
            if self.project_method_count > 0 else None
        )
        diagnostics["project_method_count"] = self.project_method_count
        diagnostics["method_ratio"] = ratio

        oversized = result_count > OVERSIZED_ABS_FLOOR and (
            ratio is None or ratio > OVERSIZED_METHOD_RATIO
        )
        if oversized and spec.role in COUNT_GATED_ROLES:
            diagnostics["reason"] = "oversized_result"
            return ValidationResult(
                passed=False,
                failure_type="scope_abnormal",
                result_count=result_count,
                diagnostics=diagnostics,
                feedback=(
                    f"{spec.role} match count is abnormal: {result_count} results"
                    + (f", {ratio * 100:.0f}% of project methods" if ratio is not None else "")
                ),
            )

        if oversized:
            # flow_step / summary only add propagation edges; warn but do not block
            diagnostics["health_warning"] = {
                "kind": "oversized_non_endpoint_role",
                "role": spec.role,
                "result_count": result_count,
                "method_ratio": ratio,
                "detail": (
                    f"{spec.role} matched {result_count} results in one round, above the "
                    f"{OVERSIZED_ABS_FLOOR} floor; non-endpoint role, so no rewrite is "
                    "triggered and this only counts toward run health."
                ),
            }

        # Step 4/5: GT hit check
        gt_file_paths = self._extract_gt_paths(spec)

        if not gt_file_paths:
            # No project-derived GT; non-empty passes
            return ValidationResult(
                passed=True, result_count=result_count, diagnostics=diagnostics,
            )

        # Check whether any GT file_path appears in the results
        hit_paths = set()
        for loc in locations:
            for gt_path in gt_file_paths:
                # Fuzzy match: the GT path may be a substring of a relative path
                if gt_path in loc or loc in gt_path:
                    hit_paths.add(gt_path)

        if hit_paths:
            return ValidationResult(
                passed=True, result_count=result_count, diagnostics=diagnostics,
            )
        else:
            return ValidationResult(
                passed=False,
                failure_type="gt_not_hit",
                result_count=result_count,
                diagnostics=diagnostics,
                feedback=(
                    f"Query returned {result_count} results but none hit a ground-truth "
                    f"file path.\n"
                    f"Expected paths: {gt_file_paths}\n"
                    f"Matched paths: {locations[:5]}...\n"
                    f"Likely cause: the spec's GT example is declaration-side code while "
                    f"the matching rule targets the call site, so the file paths differ."
                ),
            )

    @staticmethod
    def _parse_csv(csv_text: str) -> list[str]:
        """Parse CSV output and extract the location column."""
        locations = []
        try:
            reader = csv.reader(io.StringIO(csv_text))
            header = next(reader, None)
            for row in reader:
                if row:
                    # location value, e.g. "src/main/java/...:42:5"
                    locations.append(row[0])
        except Exception:
            pass
        return locations

    # ----------------------------------------------------------
    #  GT path extraction (used by validate and by the agent)
    # ----------------------------------------------------------
    @staticmethod
    def _extract_gt_paths(spec: SpecificationUnion) -> List[str]:
        """
        Extract the file paths used for GT hit checking from ground_truth_examples.
        Keep only entries with is_from_project=True, a non-empty file_path and
        purpose == "validation"; illustration examples are not checked.
        """
        return [
            gt.file_path
            for gt in spec.ground_truth_examples
            if gt.is_from_project and gt.file_path
            and getattr(gt, "purpose", "validation") == "validation"
        ]
