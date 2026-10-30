from typing import TypedDict, Annotated, List, Literal, Optional, Union, Tuple

from pydantic import BaseModel, Field

from analysis_agent.data_model.plan_data_model import AnalysisPlan, InvestigationObjective

# Data structures used by the Review Agent Node

# Final result format
# Code result format
class CodeResult(BaseModel):
    code_description: str = Field(description="Business/security meaning of the code snippet")
    is_from_project: bool = Field(description="Whether the snippet comes from the target project's real source")
    file_path: Optional[str] = Field(None, description="Relative path (required when is_from_project=True)")
    
    # Core field: purified code skeleton, also used as the verification anchor
    code_snippet: List[str] = Field(
        description=(
            "Key code lines or blocks ordered as they appear in the source. "
            "Extract only the most distinctive core statements (method signatures, "
            "key assignments, dangerous operations, etc.); ignore long unrelated "
            "logic, log statements, and boilerplate."
        )
    )
    
    # --- Filled in by post-processing; the LLM need not care ---
    id: Optional[str] = None
    # target_line_ranges: Optional[List[Tuple[int, int]]] = Field(
    #     None, 
    #     description="Real line ranges computed by post-processing; ranges[i] is (start_line, end_line) for code_snippet[i]"
    # )
    # is_verified: bool = Field(
    #     False, 
    #     description="Whether post-processing matched all snippets in order in the real source"
    # )

class ExecutionResult(BaseModel):
    execution_summary: str = Field(description="Summary of the execution result, at most 150 characters")
    execution_report: str = Field(description="Execution report describing the analysis process, key clues and conclusions in detail.")
    code_results: Optional[List[CodeResult]] = Field(
        default=None, 
        description="List of code results. Fill only when the task explicitly asks for snippets; otherwise null or an empty list."
    )

    # Nature of this report (used by ReviewNode to choose a merge strategy)
    is_self_contained: bool = Field(
        default=False,
        description="True: this round's result is complete and can replace history; False: incremental supplement only"
    )

class ReviewVerdict(BaseModel):
    """Unified ReviewNode output: assessment + integration + refinement instructions"""
    
    # === Assessment ===
    status: Literal["COMPLETE", "NEEDS_REFINEMENT", "FAILED"] = Field(
        description="COMPLETE=result sufficient, close now; NEEDS_REFINEMENT=right direction but missing key details; FAILED=off track or cannot complete"
    )
    reason: str = Field(description="Reason for the verdict (<= 150 characters)")
    
    # === Result integration (required every time, including the first execution) ===
    integrated_summary: str = Field(
        description="Integrated execution summary (<= 150 characters). On the first execution it equals this round's execution_summary; on refinement, merge the previous summary with this round's addition"
    )
    integrated_report: str = Field(
        description="Integrated execution report. On the first execution it equals this round's execution_report; on refinement, append this round's addition to the previous report"
    )
    
    # === Code-snippet selection ===
    reserve_all_existing: bool = Field(
        default=True,
        description="Whether to keep all existing snippets in cur_result. True=keep all (ignore reserved_code_ids); False=keep only those listed in reserved_code_ids"
    )
    reserved_code_ids: List[str] = Field(
        default_factory=list,
        description="When reserve_all_existing=False, IDs of existing snippets to keep. Leave empty when reserve_all_existing=True"
    )
    
    add_all_new: bool = Field(
        default=True,
        description="Whether to add all new snippets from this round's ExecutionResult. True=add all (ignore added_code_ids); False=add only those listed in added_code_ids"
    )
    added_code_ids: List[str] = Field(
        default_factory=list,
        description="When add_all_new=False, IDs of new snippets to add. Leave empty when add_all_new=True"
    )
    
    # === Refinement instructions (only when NEEDS_REFINEMENT) ===
    refinement_goal: Optional[str] = Field(
        default=None,
        description="Refinement goal. Must state the specific missing information"
    )
    refinement_expected_output: Optional[str] = Field(
        default=None,
        description="Expected output contract for the refinement goal"
    )


class RefinementRecord(BaseModel):
    """Complete record of one refinement round."""
    refinement_reason: str = Field(description="Why ReviewNode decided NEEDS_REFINEMENT")
    refinement_goal: str = Field(description="Specific description of the refinement goal")
    refinement_expected_output: str = Field(description="Expected output of the refinement goal")
    # The execution result is None before this refinement runs
    execution_result: Optional[ExecutionResult] = Field(
        default=None,
        description="Execution result of this refinement"
    )


class ActiveObjectiveContext(BaseModel):
    """Full context and iteration history of the objective currently being executed."""
    objective: InvestigationObjective = Field(description="Initial objective definition (id, goal, expected_output)")

    status: Literal["INITIATING", "COMPLETE", "NEEDS_REFINEMENT", "FAILED"] = Field(
        description="INITIATING=first execution just started; COMPLETE=result sufficient, close now; NEEDS_REFINEMENT=right direction but missing key details; FAILED=off track or cannot complete"
    )
    reason: str = Field(description="Reason for the current status")
    
    initial_result: Optional[ExecutionResult] = Field(
        default=None, 
        description="Complete result of the first execution"
    )

    # Latest integrated result maintained by ReviewNode
    cur_result: Optional[ExecutionResult] = Field(
        default=None,
        description="Latest complete execution result for the current objective (maintained by ReviewNode)"
    )
    
    refinements: List[RefinementRecord] = Field(
        default_factory=list,
        description="Refinement records in chronological order"
    )
    
    @property
    def refinement_count(self) -> int:
        return len(self.refinements)
    
    @property
    def can_refine(self) -> bool:
        return self.refinement_count < 3