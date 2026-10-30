import json
from typing import List, Optional, Tuple
from langchain_core.messages import ToolMessage, BaseMessage, HumanMessage

# analysis agent module
from analysis_agent.data_model.review_node_data import RefinementRecord, ExecutionResult, CodeResult
from analysis_agent.data_model.plan_data_model import InvestigationObjective, AnalysisPlan

from analysis_agent.utils import text_process, message_process, code_verify

# executor agent local module
from analysis_agent.executor_agent.prompts.executor_prompts import (
    # Global User Prompt
    EXECUTION_USER_GLOBAL_INITIAL_TEMPLATE,
    EXECUTION_USER_GLOBAL_REFINEMENT_TEMPLATE,
)
from analysis_agent.executor_agent.prompts.analyzer_prompts import (
    # Analyzer History Prompt
    ANALYZER_HISTORY_INITIAL_TEMPLATE,
    ANALYZER_HISTORY_REFINEMENT_TEMPLATE,
    # Analyzer Action Prompt
    ANALYZER_ACTION_INITIAL_TEMPLATE,
    ANALYZER_ACTION_REFINEMENT_TEMPLATE
)
from analysis_agent.executor_agent.prompts.updater_prompts import (
    # Updater History Prompt 
    UPDATER_HISTORY_INITIAL_TEMPLATE,
    UPDATER_HISTORY_REFINEMENT_TEMPLATE,
    # Updater Action Prompt
    UPDATER_ACTION_INITIAL_TEMPLATE,
    UPDATER_ACTION_REFINEMENT_TEMPLATE,
)


from analysis_agent.executor_agent.executor_data_model import UpdateResult

# ==========================================
# 1. Global User Prompt -- build the global user prompt, distinguishing first execution from refinement
# ==========================================
def gen_global_user_prompt(is_refinement: bool, state: dict):
    # Read the key information from the graph state
    plan: AnalysisPlan = state["plan"]

    # (1) Render the global plan text, completed objectives only
    global_objectives_text = text_process.gen_global_objectives_text(plan, False)

    # (2) Get the objective currently being executed
    cur_objective = state["cur_objective"]

    # Build the prompt
    if is_refinement:
        # === Refinement mode ===
        # Previous result
        prev_result: ExecutionResult = state.get("result")  # None = first execution; ExecutionResult = refinement
        pending_refinement: RefinementRecord = state.get("pending_refinement")  # refinement requirements

        # Wrap the code snippets of the previous result
        prev_code_results = "*No code snippets in the previous execution result*"
        if prev_result.code_results:
            prev_code_results = f"```json\n{json.dumps([cr.model_dump() for cr in prev_result.code_results], indent=2, ensure_ascii=False)}\n```" 

        return EXECUTION_USER_GLOBAL_REFINEMENT_TEMPLATE.format(
            # Global task information
            project_name=state["project_name"],
            project_profile=plan.project_profile,
            cwe_id=state["cwe_id"],
            # Core hypotheses and completed objectives are omitted here to save tokens: the
            # previous execution result already provides enough context.
            # # Core hypotheses
            # core_hypotheses="\n".join([f"- {h}" for h in plan.core_hypotheses]) or "None",
            # # Completed/discarded objectives
            # completed_objectives_text=global_objectives_text or "Analysis just started; no completed objectives yet.",
            # Current original task information
            objective_id=cur_objective.id,
            objective_goal=cur_objective.goal,
            expected_output=cur_objective.expected_output or "Provide a detailed security analysis report with key code slices",
            # Previous execution results (from the last round)
            prev_execution_summary=prev_result.execution_summary or "None",
            prev_execution_report=prev_result.execution_report or "None",
            prev_code_results=prev_code_results,
            # Refinement requirements
            refinement_reason=pending_refinement.refinement_reason or "None",
            refinement_goal=pending_refinement.refinement_goal or "None",
            refinement_expected_output=pending_refinement.refinement_expected_output or "None",
        )
        
    else:
        # === Initial execution mode ===
        return EXECUTION_USER_GLOBAL_INITIAL_TEMPLATE.format(
            # Global task information
            project_name=state["project_name"],
            project_profile=plan.project_profile,
            cwe_id=state["cwe_id"],
            # Core hypotheses
            core_hypotheses="\n".join([f"- {h}" for h in plan.core_hypotheses]) or "None",
            # Completed/discarded objectives
            completed_objectives_text=global_objectives_text or "Analysis just started; no completed objectives yet.",
            # Current objective information
            objective_id=cur_objective.id,
            objective_goal=cur_objective.goal,
            expected_output=cur_objective.expected_output or "Provide a detailed security analysis report with key code slices"
        )

# ==========================================
# 2. Analyzer History Prompt -- based on the snapshot
# ==========================================
def gen_analyzer_history_prompt(is_refinement: bool, state: dict) -> str:
    """
    Build the Analyzer history prompt.

    Logic:
    - When execution_narrative_snapshot exists (truncation has occurred), use the snapshot as
      background to restore the early interactions missing from the truncated messages.
    - When no snapshot exists (nothing truncated yet), return an empty string (no history
      prompt is inserted) because messages already contains the full history.
    """
    narrative_snapshot = state.get("execution_narrative_snapshot", "")
    code_results_snapshot = state.get("code_results_snapshot", [])

    # Not truncated yet: messages already contains the full history
    if not narrative_snapshot:
        return ""

    # Truncated: use the snapshot as background
    narrative_source = narrative_snapshot
    code_pool_source = code_results_snapshot

    # Cap the narrative length
    if len(narrative_source) > 2000:
        narrative_source = "...[earlier narrative truncated]\n" + narrative_source[-2000:]

    # Format the code pool
    code_pool_text = "*No code snippets in the snapshot's code memory pool*"
    if code_pool_source:
        code_pool_text = f"```json\n{json.dumps([cr.model_dump() for cr in code_pool_source], indent=2, ensure_ascii=False)}\n```"

    kwargs = {
        "current_execution_narrative": narrative_source,
        "cur_code_results": code_pool_text,
    }

    if is_refinement:
        return ANALYZER_HISTORY_REFINEMENT_TEMPLATE.format(**kwargs)
    else:
        return ANALYZER_HISTORY_INITIAL_TEMPLATE.format(**kwargs)


# ==========================================
# 3. Updater History Prompt -- always uses live data
# ==========================================
def gen_updater_history_prompt(is_refinement: bool, state: dict) -> str:
    """
    Build the Updater's history prompt.
    Always reads the [latest] execution_narrative and cur_code_results from state.
    Snapshots are not used because the Updater's message list is an independent short list
    that is never truncated.

    Purpose: give the Updater the already-summarized history as the baseline for incremental
    comparison, so it can distinguish what has been recorded from what this round must summarize.
    """
    cur_objective = state["cur_objective"]

    # Always use the latest narrative
    latest_narrative = cur_objective.execution_narrative or "Exploration is at an early stage; no execution narrative yet. Summarize based on this round's tool results."
    if len(latest_narrative) > 2000:
        latest_narrative = "...[earlier narrative truncated]\n" + latest_narrative[-2000:]

    # Always use the latest code pool
    code_pool_text = "*No code snippets in the current code memory pool*"
    cur_code_results = state.get("cur_code_results", [])
    if cur_code_results:
        code_pool_text = f"```json\n{json.dumps([cr.model_dump() for cr in cur_code_results], indent=2, ensure_ascii=False)}\n```"

    kwargs = {
        "current_execution_narrative": latest_narrative,
        "cur_code_results": code_pool_text,
    }

    if is_refinement:
        return UPDATER_HISTORY_REFINEMENT_TEMPLATE.format(**kwargs)
    else:
        return UPDATER_HISTORY_INITIAL_TEMPLATE.format(**kwargs)


# ==========================================
# 4. Action Prompt -- separate variants for the Analyzer and the Updater
# ==========================================
def gen_analyzer_action_prompt(is_refinement: bool, state: dict) -> str:
    """
    Build the Analyzer action guide, appended at the end of the message list.
    Contains: objective reminder (anchored at both ends), action guide and discipline.
    """
    cur_objective = state["cur_objective"]

    if is_refinement:
        pending_refinement: RefinementRecord = state.get("pending_refinement")
        return ANALYZER_ACTION_REFINEMENT_TEMPLATE.format(
            refinement_reason=pending_refinement.refinement_reason if pending_refinement else "",
            refinement_goal=pending_refinement.refinement_goal if pending_refinement else "",
            refinement_expected_output=pending_refinement.refinement_expected_output if pending_refinement else "",
        )
    else:
        return ANALYZER_ACTION_INITIAL_TEMPLATE.format(
            objective_id=cur_objective.id,
            objective_goal=cur_objective.goal,
            expected_output=cur_objective.expected_output or "Provide a detailed security analysis report with key code slices",
        )


def gen_updater_action_prompt(is_refinement: bool, state: dict) -> str:
    """
    Build the Updater action guide, appended at the end of the message list.
    Contains: objective reminder, focus instruction and a condensed JSON-format reminder.
    """
    cur_objective = state["cur_objective"]

    if is_refinement:
        pending_refinement: RefinementRecord = state.get("pending_refinement")
        return UPDATER_ACTION_REFINEMENT_TEMPLATE.format(
            refinement_reason=pending_refinement.refinement_reason if pending_refinement else "",
            refinement_goal=pending_refinement.refinement_goal if pending_refinement else "",
            refinement_expected_output=pending_refinement.refinement_expected_output if pending_refinement else "",
        )
    else:
        return UPDATER_ACTION_INITIAL_TEMPLATE.format(
            objective_id=cur_objective.id,
            objective_goal=cur_objective.goal,
            expected_output=cur_objective.expected_output or "Provide a detailed security analysis report with key code slices",
        )

def check_update_result(
    parsed_output: UpdateResult,
    cur_objective: InvestigationObjective,
    cur_code_results: List[CodeResult],
    project_root: str
) -> Tuple[bool, Optional[HumanMessage], Optional[InvestigationObjective], Optional[List[CodeResult]], Optional[ExecutionResult]]:
    """
    Strictly validate the UpdateResult produced by the Updater and assemble the new state.
    Core idea: a temp_code_results buffer avoids the semantic conflict between delete and reserve.
    """
    # 0. Basic non-empty checks
    if not parsed_output.execution_narrative_update and not parsed_output.final_result:
        return False, \
            HumanMessage("❌ Validation failed: `execution_narrative_update` and `final_result` cannot both be empty. Provide at least a narrative update, or a final report when the evidence is complete.\n"), \
            None, None, None

    new_cur_objective = cur_objective.model_copy(deep=True)
    verifier = code_verify.get_verifier(project_root) if project_root else None
    
    # ==========================================
    # Step 1: validate new_code_results and buffer them in temp_code_results
    # ==========================================
    temp_code_results: List[CodeResult] = []
    if parsed_output.new_code_results:
        for i, cr in enumerate(parsed_output.new_code_results):
            # Required-field checks
            if not cr.code_description or not cr.code_snippet:
                return False, \
                    HumanMessage(f"❌ Validation failed: item {i+1} of `new_code_results` is missing required field `code_description` or `code_snippet`.\n"), \
                    None, None, None
            
            if cr.is_from_project and not cr.file_path:
                return False, \
                    HumanMessage(f"❌ Validation failed: item {i+1} of `new_code_results` has `is_from_project` True but an empty `file_path`.\n"), \
                    None, None, None
            
            # Strict checks: file existence and fuzzy code matching
            if verifier and cr.is_from_project:
                verify_res = verifier.verify(cr)
                if verify_res.status == code_verify.VerifyStatus.FILE_NOT_FOUND:
                    return False, \
                        HumanMessage(f"❌ Validation failed: file path `{cr.file_path}` of item {i+1} in `new_code_results` does not exist. Verify the path.\n"), \
                        None, None, None
                if verify_res.status == code_verify.VerifyStatus.NOT_A_FILE:
                    return False, \
                        HumanMessage(f"❌ Validation failed: the path in item {i+1} of `new_code_results` is not a concrete file!\n"
                            f"Path you provided: `{cr.file_path}`\n"
                            f"Path resolved by the system: `{verify_res.resolved_file_path}`\n"
                            f"Reason: the path points to a [directory], or is not a regular readable file.\n"
                            f"How to fix:\n"
                            f"1. To capture code or configuration, provide a [concrete file path] (e.g. `src/.../UserDao.java` or `pom.xml`); never use a directory path.\n"
                            f"2. If you are capturing non-file content such as a directory tree (e.g. the output of list_directory), set `is_from_project` to `false` and `file_path` to `null`.\n"
                        ), \
                        None, None, None
                elif verify_res.status == code_verify.VerifyStatus.CODE_MISMATCH:
                    return False, \
                        HumanMessage(
                            f"❌ Validation failed: the code in item {i+1} of `new_code_results` does not match the file!\n"
                            f"Path you provided: `{cr.file_path}`\n"
                            f"File resolved by the system: `{verify_res.resolved_file_path}`\n"
                            f"Check whether you picked the wrong file, over-trimmed the code, or hallucinated.\n"
                        ), \
                        None, None, None
            
            # Passed: deep-copy into the buffer (no final id yet, so the LLM cannot reference
            # not-yet-assigned ids in delete/reserve)
            temp_code_results.append(cr.model_copy(deep=True))

    # ==========================================
    # Steps 2 & 3: branch on final_result (finalize vs keep exploring) for the memory pool
    # ==========================================
    
    # Find the highest existing id number so new buffered results get fresh ids
    max_id_num = 0
    for cr in cur_code_results:
        if cr.id and cr.id.startswith("cr_"):
            try:
                max_id_num = max(max_id_num, int(cr.id.split("_")[-1]))
            except ValueError:
                pass
    
    # Assign globally unique ids to the buffered results
    for i, cr in enumerate(temp_code_results):
        cr.id = f"cr_{max_id_num + i + 1:03d}"

    execution_result = None
    updated_pool = list(cur_code_results) # defaults to the existing pool

    if parsed_output.final_result:
        # Case A/B: finalize mode (produce the final report)
        fr = parsed_output.final_result
        if not fr.execution_summary or not fr.execution_report:
            return False, \
                HumanMessage("❌ Validation failed: `execution_summary` and `execution_report` in `final_result` must not be empty.\n"), \
                None, None, None
        
        final_code_results = []
        
        if fr.reserve_all_code_results:
            # Case A: keep everything (apply the delete_code_ids blacklist to remove false positives)
            delete_set = set(parsed_output.delete_code_ids or [])
            filtered_pool = [cr for cr in cur_code_results if cr.id not in delete_set]
            final_code_results = filtered_pool + temp_code_results
        else:
            # Case B: select explicitly (apply the reserved_code_result_ids whitelist, ignore delete_code_ids)
            if not fr.reserved_code_result_ids:
                 # Neither "keep all" nor a whitelist: only the newly found buffered results are kept
                 final_code_results = temp_code_results
            else:
                pool_map = {cr.id: cr for cr in cur_code_results}
                missing_ids = [cid for cid in fr.reserved_code_result_ids if cid not in pool_map]
                if missing_ids:
                    return False, \
                        HumanMessage(f"❌ Validation failed: `final_result.reserved_code_result_ids` contains ids not present in the current memory pool: {', '.join(missing_ids)}. Check the existing pool ids.\n"), \
                        None, None, None
                
                # Select in whitelist order and append the newly found results
                selected_pool = [pool_map[cid] for cid in fr.reserved_code_result_ids]
                final_code_results = selected_pool + temp_code_results

        # Build the final ExecutionResult
        execution_result = ExecutionResult(
            execution_summary=fr.execution_summary,
            execution_report=fr.execution_report,
            code_results=final_code_results,
            is_self_contained=fr.is_self_contained
        )
        
    else:
        # Case C: keep exploring (update the memory pool)
        # First apply the blacklist to remove false positives
        delete_set = set(parsed_output.delete_code_ids or [])
        filtered_pool = [cr for cr in cur_code_results if cr.id not in delete_set]
        # Add newly found results to the pool
        updated_pool = filtered_pool + temp_code_results

    # ==========================================
    # Step 4: update the execution narrative
    # ==========================================
    if parsed_output.execution_narrative_update:
        if not new_cur_objective.execution_narrative:
            new_cur_objective.execution_narrative = parsed_output.execution_narrative_update
        else:
            new_cur_objective.execution_narrative += f"\n{parsed_output.execution_narrative_update}"

    return True, None, new_cur_objective, updated_pool, execution_result
