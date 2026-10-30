from typing import TypedDict, Annotated, List, Literal, Optional, Union, Tuple
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage
from pydantic import Field
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from analysis_agent.data_model.review_node_data import RefinementRecord, CodeResult, ExecutionResult
from analysis_agent.data_model.plan_data_model import AnalysisPlan, InvestigationObjective

class FinalResult(BaseModel):
    execution_summary: str = Field(description="Summary of the execution result, at most 150 characters")
    execution_report: str = Field(description="Execution report describing the analysis process, key findings and conclusions in detail.")
    reserve_all_code_results: bool = Field(description="Whether to keep all code results in the current state in the final result; when True, reserved_code_result_ids is ignored")
    reserved_code_result_ids: Optional[List[str]] = Field(
        default=None, 
        description="Code results from the current state to keep in the final result; only used when reserve_all_code_results is False"
    )

    # Nature of this report (used by ReviewNode to choose a merge strategy)
    is_self_contained: bool = Field(
        default=False,
        description="True: this round's result is complete and can replace history; False: incremental supplement only"
    )

class UpdateResult(BaseModel):
    execution_narrative_update: str = Field(description="Update to the execution narrative for this round, at most 100 characters")

    new_code_results: Optional[List[CodeResult]] = Field(
        default=None, 
        description="New code results"
    )

    delete_code_ids: Optional[List[str]] = Field(
        default=None, 
        description="List of cr_ids to delete from code_results"
    )

    final_result: Optional[FinalResult] = Field(
        default=None, 
        description="Final result, filled only when the analysis task is complete; non-None means the objective is done and the task ends"
    )


# State of the Executor Agent graph
class ExecutorState(TypedDict):
    # --- Environment inputs (read-only) ---
    project_root: str
    project_name: str
    cwe_id: str
    max_steps: int
    
    # --- Core memory and plan (read-only) ---
    plan: AnalysisPlan

    # --- Current objective (read-only) ---
    cur_objective: InvestigationObjective

    # --- Refinement request: empty on the first execution, so result is always None ---
    pending_refinement: Optional[RefinementRecord]

    # --- Refinement round number; 1 on the first execution ---
    execution_count: int

    # --- Short-term working memory (sliding window) ---
    # add_messages appends messages automatically
    messages: Annotated[List[BaseMessage], add_messages] 
    
    # --- Control flow ---
    step_count: int
    status: Literal["executing", "finished"] # , "step_count_exceed_limit"] 

    # --- Execution result: initially the previous round's result (for REFINEMENT;
    #     empty on the first execution), replaced when execution completes
    result: ExecutionResult

    # --- Snapshot mechanism (pre_ prefixed fields) ---
    # Intermediate snapshot taken after M*N steps
    pre_execution_narrative_snapshot: str
    pre_code_results_snapshot: List[CodeResult]

    # Snapshot activated after M*N+K steps (used to build the history prompt)
    execution_narrative_snapshot: str
    code_results_snapshot: List[CodeResult]

    # --- Code snippets recorded in real time ---
    cur_code_results: List[CodeResult]