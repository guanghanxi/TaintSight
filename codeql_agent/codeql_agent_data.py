from global_data_model.analysis_result import TaintSpecificationList, SpecificationUnion
from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class SpecResult:
    """Result of processing one specification."""
    spec_id: str
    role: str
    spec: SpecificationUnion
    success: bool
    predicate_code: str = ""           # full predicate code after validation passed
    error_summary: str = ""            # short failure summary
    attempts: int = 0                  # number of attempts made
    gt_verified: bool = False          # passed ground-truth validation
    failure_kind: str = ""             # outcome class; see retry_policy.FailureKind
    oversized: bool = False            # accepted despite an oversized match set

@dataclass
class ValidationResult:
    passed: bool
    feedback: str = ""
    failure_type: str = ""  # "empty_result" | "gt_not_hit" | "scope_abnormal"
    result_count: int = 0               # query result count (0 = empty or unparsed)
    diagnostics: dict = field(default_factory=dict)  # scope diagnostics; see validator.ResultValidator.validate

@dataclass
class CodeQLAgentOutput:
    """
    Structured output of the CodeQL Agent.

    Besides the final script, keeps the per-spec scripts for debugging and reuse.
    """
    final_script: str                                        # final taint-analysis script
    validated: List[SpecResult] = field(default_factory=list)
    failed: List[SpecResult] = field(default_factory=list)
    not_attempted: List[str] = field(default_factory=list)   # spec_ids skipped by the circuit breaker
    circuit_break: dict = None                               # circuit-break record (None if not tripped)
    assembly_guard: dict = None                              # missing-role self-check after assembly (None if clean)

    @property
    def spec_scripts(self) -> Dict[str, Dict[str, object]]:
        """spec_id -> {"role", "predicate_code", "gt_verified", "oversized"}"""
        return {
            r.spec_id: {
                "role": r.role,
                "predicate_code": r.predicate_code,
                "gt_verified": r.gt_verified,
                "oversized": r.oversized,
            }
            for r in self.validated
        }
