from analysis_agent.data_model.review_node_data import ReviewVerdict, ActiveObjectiveContext, RefinementRecord
from analysis_agent.executor_agent.executor_data_model import CodeResult, ExecutorState
from analysis_agent.state import AnalyzerState
from analysis_agent.utils import fallback

# State conversion functions between the parent graph and the executor subgraph

def transfer_analyzer_to_executor(analyzer_state: AnalyzerState) -> dict:
    """
    Build the executor subgraph state from the parent Analyzer Agent state.
    """
    # Determine the current execution round (the first execution is round 1)
    active_objective = analyzer_state.get("active_objective")
    execution_count = active_objective.refinement_count + 1
    return {
        "project_root": analyzer_state.get("project_root"),
        "project_name": analyzer_state.get("project_name"),
        "cwe_id": analyzer_state.get("cwe_id"),
        "max_steps": 60,
        "plan": analyzer_state.get("plan"), # read-only, no copy needed
        "cur_objective": active_objective.objective.model_copy(deep=True), # execution_narrative is mutated, so deep-copy
        "pending_refinement": None if execution_count == 1 else active_objective.refinements[-1], # read-only, no copy needed
        "execution_count": execution_count,
        "messages": [],
        "step_count": 0,
        "status": "executing",
        "result": None if execution_count == 1 else active_objective.cur_result.model_copy(deep=True), # deep copy
        "cur_code_results": [] # initialize the code-memory pool
    }

def update_analyzer_from_executor(analyzer_state: AnalyzerState, executor_state: ExecutorState) -> dict:
    """
    Update the parent state from the executor subgraph result.
    """
    # 1. Deep-copy the whole ActiveObjectiveContext to keep updates immutable
    new_active_objective: ActiveObjectiveContext = analyzer_state.get("active_objective").model_copy(deep=True)
    
    # 2. Sync execution_narrative (the plan's objective is updated by a
    #    downstream node once the current objective finishes)
    new_active_objective.objective.execution_narrative = executor_state["cur_objective"].execution_narrative

    # 3. Fetch and validate the result (fallback covers abnormal paths such as
    #    early subgraph termination so the whole direction is not dropped)
    executor_result = executor_state.get("result", None)
    if executor_result is None:
        executor_result = fallback.executor_missing_result(
            executor_state.get("cur_objective"),
            executor_state.get("cur_code_results"),
            detail=(
                f"Objective {analyzer_state.get('active_objective').objective.id}: "
                f"the executor subgraph finished with an empty result; synthesizing a fallback result"
            ),
        )
    # 4. Update the result based on the round (handling nested objects safely)
    if analyzer_state.get("active_objective").refinement_count == 0:
        new_active_objective.initial_result = executor_result.model_copy(deep=True)
    else:
        updated_refinements = list(new_active_objective.refinements)
        last_ref = updated_refinements[-1].model_copy(deep=True)
        last_ref.execution_result = executor_result.model_copy(deep=True)
        updated_refinements[-1] = last_ref
        new_active_objective.refinements = updated_refinements

    # 5. Return the updated fields
    return {
        "active_objective": new_active_objective
    }