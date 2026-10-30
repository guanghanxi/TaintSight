import json
import os
from typing import List, Literal, Optional, Dict, Any
from langchain_core.tools import tool
from pydantic import ValidationError
from langchain_core.runnables import RunnableConfig, ensure_config

from analysis_agent.data_model.review_node_data import RefinementRecord, ExecutionResult, CodeResult

# Tools specific to the executor agent

@tool
def update_execution_narrative(narrative_update: str) -> str:
    """
    Update the status, exploration narrative, and conclusion of the [objective currently under investigation].
    Call this tool when you finish investigating the current objective (confirmed or refuted)
    or reach a milestone worth recording in the micro exploration narrative.

    Args:
        narrative_update: real-time exploration narrative update for the current objective (<= 150 characters).
            Record what was just done and which micro-level clues were found.
    """
    if len(narrative_update) == 0:
        return "Validation failed: the narrative update must not be empty."
        
    payload = {
        "tool_type": "update_execution_narrative",
        "narrative_update": narrative_update
    }
    return f"✅ [update_current_objective] Registered. Payload: {json.dumps(payload, ensure_ascii=False)}"

@tool
def submit_execution_result(
    execution_summary: str,
    execution_report: str,
    is_self_contained: bool,
    code_results: Optional[List[Dict[str, Any]]] = None,
    config: RunnableConfig = None
) -> str:
    """
    [Termination tool] Call this to submit the final result when the current Objective is
    completely finished (whether it succeeded or failed). The Agent stops immediately after.

    Args:
        execution_summary: short execution summary (<= 150 characters) for a quick overview of
            the outcome and key findings.

        execution_report: detailed execution report.
            Core requirement: content, structure, and emphasis must strictly follow the
            current Objective's `expected_output`.
            - If expected_output asks for vulnerability proof, focus on the attack path and trigger conditions.
            - If expected_output asks for a data-flow walkthrough, focus on the Source/Sink/Propagation chain.
            - If expected_output only asks whether an API exists, give a clear conclusion and evidence.
            Do not use a fixed template; expected_output is always the highest authority.

        is_self_contained: nature of this result. True: this round's result contains all
            information and can replace the historical result; must be True on the first execution.
            False: incremental addition to the existing result.

        code_results: list of code snippets. Provide only when the task explicitly asks for
            snippets; otherwise pass null or [].
            Each snippet must contain:
            - code_description (str): what the snippet is for
            - code_snippet (str): complete snippet with context (3-20 lines)
            - is_from_project (bool): [required] whether it comes from the target project's real source
            - file_path (str | null): relative path. Required when is_from_project=true; null otherwise
            - target_line_range (list[int] | null): line range [start, end] of the core trigger point; null if unknown

    """
    # Ensure config is available
    config = ensure_config(config)
    project_root = config.get("configurable", {}).get("project_root", "")

    # 1. Validate CodeResults
    validated_code_results = []
    if code_results:
        for i, cr_dict in enumerate(code_results):
            try:
                validated_cr = CodeResult(**cr_dict)
                
                # Check: file_path is required when is_from_project=True
                if validated_cr.is_from_project and not validated_cr.file_path:
                    return (
                        f"Validation failed: code_results item {i+1} is invalid.\n"
                        f"Detail: `is_from_project` is true but `file_path` is empty.\n"
                        f"Provide the real file path or set `is_from_project` to false."
                    )
                
                # Check: the real file path must exist
                if validated_cr.is_from_project and validated_cr.file_path and project_root:
                    full_path = os.path.join(project_root, validated_cr.file_path)
                    if not os.path.exists(full_path):
                        return (
                            f"Validation failed: code_results item {i+1} is invalid.\n"
                            f"Detail: file `{validated_cr.file_path}` does not exist in the project.\n"
                            f"Check the path or locate it again with grep/read_file."
                        )
                
                validated_cr.id = f"cr_{i+1:03d}" # deterministic id
                validated_code_results.append(validated_cr.model_dump())
                
            except ValidationError as e:
                return (
                    f"Validation failed: code_results item {i+1} is malformed.\n"
                    f"Detail: {e.errors()}\n"
                    f"Check that the required fields (code_description, code_snippet, is_from_project) are present."
                )

    # 2. Assemble the payload
    payload = {
        "tool_type": "submit_execution_result",
        "summary": execution_summary,
        "report": execution_report,
        "is_self_contained": is_self_contained,
        "code_results": validated_code_results
    }
    
    return f"✅ [submit_execution_result] Registered. Payload: {json.dumps(payload, ensure_ascii=False)}"

from langchain_core.tools import tool

@tool
def signal_exploration_done(reason: str) -> str:
    """
    [Exploration termination signal] Call this when the code evidence collected so far is
    sufficient (to prove or refute the vulnerability), or when the current path can yield
    no further clues. After this call you stop searching and the system wakes the
    Updater to prepare the final report.

    Args:
        reason: brief explanation of why exploration stops (e.g. "complete taint path found"
            or "confirmed that this API has no risk").
    """
    return f"[Signal] Exploration termination received. Reason: {reason}. Waking the evaluator to generate the final report..."