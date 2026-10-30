import json
import os
from typing import List, Optional, Dict

from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage, RemoveMessage
from langchain_deepseek import ChatDeepSeek
from langchain_core.runnables import RunnableConfig

# global module
from logger import StdoutLogger, log_local, log_json, log_message
from global_data_model.analysis_result import TaintSpecificationList, SpecificationUnion, ResultDeduplication
from llm_model import get_llm_based_on_config

# analysis agent local module
from analysis_agent.data_model.plan_data_model import AnalysisPlan, InvestigationObjective
from analysis_agent.data_model.review_node_data import ReviewVerdict, ActiveObjectiveContext, RefinementRecord

from analysis_agent.prompts.global_prompt import render_global_system_prompt
from analysis_agent.prompts.review_agent_prompt import REVIEW_AGENT_SYSTEM_PROMPT_FORMAT, REVIEW_USER_INITIAL_TEMPLATE, REVIEW_USER_REFINEMENT_TEMPLATE
from analysis_agent.prompts.result_extract_prompt import EXTRACT_SYSTEM_PROMPT, EXTRACT_USER_PROMPT_TEMPLATE, RESULT_DATA_PROMPT, \
DEDUP_SYSTEM_PROMPT, DEDUP_USER_PROMPT_TEMPLATE

from analysis_agent.utils import text_process, message_process, result_check, result_update, fallback

# Stdout Log Phase
STDOUT_LOG_PHASE = "analysis_agent"

# Maximum retries
MAX_RETRIES = 5
# Maximum refinement rounds
MAX_REFINEMENT = 5

# ==========================================
# Agent Node 1: Review Agent
# ==========================================
def review_agent_node(state: dict, config: RunnableConfig) -> dict:
    """Review the execution result produced by the Executor Agent and issue a refinement verdict."""

    # 1. Load state
    plan: AnalysisPlan = state["plan"]
    active_objective: ActiveObjectiveContext = state["active_objective"]

    # 2. Build prompts
    # (1) Review Agent system prompt
    global_objectives_text = text_process.gen_global_objectives_text(plan, False)
    review_agent_system_prompt = REVIEW_AGENT_SYSTEM_PROMPT_FORMAT.format(# Global task information
            project_name=state["project_name"],
            project_profile=plan.project_profile,
            cwe_id=state["cwe_id"],
            # Current exploration direction
            exploration_direction=state.get("exploration_direction", "") or "(not specified; review against the general global task)",
            # Global core hypotheses
            core_hypotheses="\n".join([f"- {h}" for h in plan.core_hypotheses]) or "none",
            # Completed/discarded objectives
            completed_objectives_text=global_objectives_text or "Early stage; no completed objectives yet."
            )
    
    # Prepend the global prompt to the Review Agent prompt
    global_system_prompt = render_global_system_prompt(
        state.get("exploration_direction", ""),
        state.get("direction_id", ""),
    )
    system_prompt = f"{global_system_prompt}\n\n---\n\n# Current node instructions\n\n{review_agent_system_prompt}"

    # Log the review system prompt for this objective
    log_target_dir = os.path.join(config["configurable"].get("loggging_path"), f"{active_objective.objective.id}_review")
    log_json(log_target_dir, 
            f"{active_objective.objective.id}_review_system_prompt", 
            {"system_prompt": system_prompt}
    )

    # stdout log: objective id
    StdoutLogger.info(f"{active_objective.objective.id}: review node: round {active_objective.refinement_count + 1}", STDOUT_LOG_PHASE)
    
    # (2) The user prompt has two variants, chosen by whether the objective has refinements
    is_refinement = active_objective.refinement_count > 0
    if is_refinement:
        # === Refinement mode ===
        # This round's refinement requirement and its result
        pending_refinement: RefinementRecord = active_objective.refinements[-1]

        prev_codes = "*No code snippets in the previous result*"
        if active_objective.cur_result.code_results:
            prev_codes = f"```json\n{json.dumps([cr.model_dump() for cr in active_objective.cur_result.code_results], indent=2, ensure_ascii=False)}\n```" 
        
        new_codes = "*No code snippets in this round's result*"
        if pending_refinement.execution_result.code_results:
            new_codes = f"```json\n{json.dumps([cr.model_dump() for cr in pending_refinement.execution_result.code_results], indent=2, ensure_ascii=False)}\n```"

        # Previous refinement requirements
        prev_refinements="\n".join([f"- {r.refinement_goal}" for r in active_objective.refinements]) or "none",
        
        user_prompt =  REVIEW_USER_REFINEMENT_TEMPLATE.format(
            # Original task information
            objective_id=active_objective.objective.id,
            objective_goal=active_objective.objective.goal,
            expected_output=active_objective.objective.expected_output or "",
            # Previous refinement requirements
            prev_refinement_block=prev_refinements,
            # Previous integrated result
            prev_execution_summary=active_objective.cur_result.execution_summary,
            prev_execution_report=active_objective.cur_result.execution_report,
            prev_code_results_block=prev_codes,
            # This round's refinement requirement
            refinement_reason=pending_refinement.refinement_reason,
            refinement_goal=pending_refinement.refinement_goal,
            refinement_expected_output=pending_refinement.refinement_expected_output,
            # This round's execution result
            is_self_contained=pending_refinement.execution_result.is_self_contained,
            new_execution_summary=pending_refinement.execution_result.execution_summary,
            new_execution_report=pending_refinement.execution_result.execution_report,
            new_code_results_block=new_codes
        )
    else:
        # === Initial review mode ===
        initial_codes = "*No code snippets in the initial result*"
        if active_objective.initial_result.code_results:
            initial_codes = f"```json\n{json.dumps([cr.model_dump() for cr in active_objective.initial_result.code_results], indent=2, ensure_ascii=False)}\n```" 

        user_prompt =  REVIEW_USER_INITIAL_TEMPLATE.format(
            # Task information
            objective_id=active_objective.objective.id,
            objective_goal=active_objective.objective.goal,
            expected_output=active_objective.objective.expected_output or "",
            # Initial execution result
            is_self_contained=active_objective.initial_result.is_self_contained,
            execution_summary=active_objective.initial_result.execution_summary,
            execution_report=active_objective.initial_result.execution_report,
            code_results_block=initial_codes
        )
    
    # Log this round's review user prompt
    cur_log_target_dir = os.path.join(log_target_dir, f"review_{active_objective.refinement_count + 1}")
    log_json(cur_log_target_dir, 
            f"review_{active_objective.refinement_count + 1}_user_prompt", 
            {"user_local_prompt": user_prompt}
    )

    # Message history carried into retries
    messages_list = []
    # Only active_objective is updated here; plan-level objective changes are applied by later nodes
    # new_active_objective = active_objective.model_copy(deep=True)
    new_active_objective = active_objective # unchanged by default
    if_response_success = False
    for i in range(MAX_RETRIES):
        StdoutLogger.info(f"    Generation Tries: {i + 1}", STDOUT_LOG_PHASE)
        # (1) Build the message list
        plan_prompt = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
            *messages_list
        ]

        # (2) Configure the LLM
        plan_llm = get_llm_based_on_config(config).with_structured_output(
            ReviewVerdict,
            method="json_mode",    # force the json_object protocol to avoid json_schema errors
            include_raw=True    # keep the raw output
        )

        # (3) Generate the response
        # Backoff retries inside; a total failure returns None (no exception escapes to abort the
        # direction), so this is treated as a failed round and retried below
        whole_response = fallback.invoke_llm_with_fallback(
            plan_llm, plan_prompt,
            node="AnalysisAgent.review_agent_node",
            log_dir=cur_log_target_dir,
            spec_id="analysis:review_agent",
        )
        if whole_response is None:
            messages_list = [HumanMessage(content=(
                "System notice: the previous LLM call did not return successfully (server queue timeout / network error), so this round produced nothing. Please generate again."
            ))]
            continue

        raw_msg = whole_response["raw"]
        parsed_output: ReviewVerdict = whole_response["parsed"]
        parsing_error = whole_response.get("parsing_error")

        # Log the response
        log_message(cur_log_target_dir, f"tries_{i+1}_response.json", raw_msg)

        # Multiple validation checks
        # messages_list.append(raw_msg) # would keep every prior attempt
        messages_list = [raw_msg] # keep only the current attempt's response and error
        # a. Parsing of the structured output
        if parsed_output is None:
            messages_list.append(result_check.get_parse_error_message(parsing_error))
            continue # retry
        
        # Other checks
        if_response_success, error_message, new_active_objective = result_check.check_review_agent_result(parsed_output, active_objective, is_refinement)
        if if_response_success and not error_message:
            break # success
        else:
            messages_list.append(error_message) # validation failed; generate again

    # All retries failed: force a conservative FAILED verdict instead of aborting the direction
    # (fallback details in utils/fallback.py)
    if not if_response_success:
        new_active_objective = fallback.review_verdict(
            active_objective,
            is_refinement,
            log_dir=log_target_dir,
            detail=f"Review generation failed validation {MAX_RETRIES} times; forcing FAILED while keeping the existing result",
        )

    # Force termination when the refinement round limit is exceeded
    if new_active_objective.refinement_count >= MAX_REFINEMENT:
        new_active_objective.status = "FAILED"
        new_active_objective.reason += f"\n[System-forced termination]\nThe refinement round limit for the current objective has been exceeded: {MAX_REFINEMENT}. The system stops execution, review and refinement of this objective."

    return {
        "active_objective": new_active_objective # only active_objective needs updating
    }

# ==========================================
# Helper node: advance the plan when the current objective finishes, or finish the whole flow
# ==========================================
def plan_promotion_node(state: dict, config: RunnableConfig) -> dict:
    active_objective: ActiveObjectiveContext = state["active_objective"]
    plan: AnalysisPlan = state["plan"]
    # No-op while the current objective still needs refinement
    if active_objective.status == "NEEDS_REFINEMENT":
        return {}
    
    # On COMPLETE or FAILED, update the state
    new_objectives = [obj.model_copy() for obj in plan.objectives]
    for obj in new_objectives:
        if obj.id == active_objective.objective.id:
            if active_objective.status == "COMPLETE":
                obj.status = "resolved"
            else:
                obj.status = "discarded"

            obj.execution_narrative = active_objective.objective.execution_narrative # carry over the narrative
            obj.resolution_summary = active_objective.cur_result.execution_summary # record the conclusion
            break

    # Find the first pending objective
    next_obj  = None
    for obj in new_objectives:
        if obj.status == "pending":
            obj.status = "investigating"
            next_obj = obj
            break
    
    if next_obj is None: # no pending objective; the plan is complete
        new_plan = plan.model_copy(update={
            "objectives": new_objectives,
            "is_completed": True
        })
        return {
            "status": "finished",
            "plan": new_plan
        }
    else:
        new_plan = plan.model_copy(update={
            "objectives": new_objectives,
            "current_objective_id": next_obj.id,
            "is_completed": False
        })
        new_active_objective = ActiveObjectiveContext(
            objective = next_obj.model_copy(deep=True),
            status = "INITIATING",
            reason = "",
            initial_result=None,
            cur_result=None,
            refinements=[]
        )
        return {
            "status": "executing",
            "plan": new_plan,
            "active_objective": new_active_objective
        }
    


# ==========================================
# Agent Node 2: Result Extract Agent
# ==========================================
def result_extract_agent_node(state: dict, config: RunnableConfig) -> dict:
    """Extract structured taint specifications from the reviewed execution result."""

    # 1. Load state
    plan: AnalysisPlan = state["plan"]
    active_objective: ActiveObjectiveContext = state["active_objective"]

    # 2. Build prompts
    # (1) Result Extract Agent system prompt
    system_prompt = EXTRACT_SYSTEM_PROMPT.format(
        global_system_prompt=render_global_system_prompt(
            state.get("exploration_direction", ""),
            state.get("direction_id", ""),
        ),
        result_data_prompt=RESULT_DATA_PROMPT,
    )

    # (2) User prompt
    # Global objective context
    global_objectives_text = text_process.gen_global_objectives_text(plan, False)

    # Render code_results as an evidence block 
    code_results_block = "*No code snippets in the execution result*"
    if active_objective.cur_result.code_results:
        code_results_block = f"```json\n{json.dumps([cr.model_dump() for cr in active_objective.cur_result.code_results], indent=2, ensure_ascii=False)}\n```" 
    
    user_prompt = EXTRACT_USER_PROMPT_TEMPLATE.format(
        project_name=state["project_name"],
        project_profile=plan.project_profile,
        cwe_id=state["cwe_id"],
        # # Global core hypotheses
        # core_hypotheses="\n".join([f"- {h}" for h in plan.core_hypotheses]) or "none",
        # Completed/discarded objectives
        completed_objectives_text=global_objectives_text or "Early stage; no completed objectives yet.",
        # Task information
        objective_id=active_objective.objective.id,
        objective_goal=active_objective.objective.goal,
        expected_output=active_objective.objective.expected_output or "",
        # Review Agent verdict
        review_status = active_objective.status,
        review_reason = active_objective.reason,
        # Execution result
        execution_summary=active_objective.cur_result.execution_summary,
        execution_report=active_objective.cur_result.execution_report,
        code_results_block=code_results_block,
        # # Output format requirements
        # result_format_requirements = RESULT_DATA_PROMPT
    )
    
    # Log the prompt for this objective
    log_target_dir = os.path.join(config["configurable"].get("loggging_path"), f"{active_objective.objective.id}_result_extarct")
    log_json(log_target_dir, 
            f"{active_objective.objective.id}_result_extract_prompt", 
            {"system_prompt": system_prompt, "user_prompt": user_prompt}
    )

    # stdout log: objective id
    StdoutLogger.info(f"{active_objective.objective.id}: result extract node", STDOUT_LOG_PHASE)

    # Evidence pool: each example's source_code_result_id must reference an entry here (provenance anchoring)
    code_results_pool = active_objective.cur_result.code_results or []

    # Message history carried into retries
    messages_list = []
    if_response_success = False
    parsed_output: Optional[TaintSpecificationList] = None
    for i in range(MAX_RETRIES):
        StdoutLogger.info(f"    Generation Tries: {i + 1}", STDOUT_LOG_PHASE)
        # (1) Build the message list
        plan_prompt = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
            *messages_list
        ]

        # (2) Configure the LLM
        extractor_llm = get_llm_based_on_config(config).with_structured_output(
            TaintSpecificationList,
            method="json_mode",    # force the json_object protocol to avoid json_schema errors
            include_raw=True    # keep the raw output
        )

        # (3) Generate the response
        # Backoff retries inside; a total failure returns None (no exception escapes to abort the
        # direction), so this is treated as a failed round and retried below
        whole_response = fallback.invoke_llm_with_fallback(
            extractor_llm, plan_prompt,
            node="AnalysisAgent.result_extract_agent_node",
            log_dir=log_target_dir,
            spec_id="analysis:result_extract",
        )
        if whole_response is None:
            messages_list = [HumanMessage(content=(
                "System notice: the previous LLM call did not return successfully (server queue timeout / network error), so this round produced nothing. Please generate again."
            ))]
            continue

        raw_msg = whole_response["raw"]
        parsed_output: TaintSpecificationList = whole_response["parsed"]
        parsing_error = whole_response.get("parsing_error")

        # Log the response
        log_message(log_target_dir, f"tries_{i+1}_response.json", raw_msg)

        # Multiple validation checks
        # messages_list.append(raw_msg) # would keep every prior attempt
        messages_list = [raw_msg] # keep only the current attempt's response and error
        # a. Parsing of the structured output
        if parsed_output is None:
            messages_list.append(result_check.get_parse_error_message(parsing_error))
            continue # retry
        
        # Other checks
        is_valid, error_message, new_specs = result_check.check_extract_result(
            parsed_output, state["project_root"], code_results_pool
        )
        if is_valid and not error_message:
            if_response_success = True
            break # success
        else:
            messages_list.append(error_message) # validation failed; generate again

    # All retries failed: use the two-level fallback instead of aborting the direction
    # (details in utils/fallback.py)
    if not if_response_success:
        new_specs = fallback.extract_specs(
            parsed_output,
            state["project_root"],
            code_results_pool,
            objective_id=active_objective.objective.id,
            log_dir=log_target_dir,
        )

    result_update.gen_spec_ids(new_specs.specifications, prefix = active_objective.objective.id) # deterministic spec_id assignment

    return {
        "cur_obj_specifications": new_specs.specifications # stage new specifications for dedup
    }


# ==========================================
# Agent Node 3: Result Deduplication Agent
# ==========================================
def result_deduplication_node(state: dict, config: RunnableConfig) -> dict:
    historical_specs: List[SpecificationUnion] = state.get("taint_specifications", [])
    cur_obj_specifications: List[SpecificationUnion] = state.get("cur_obj_specifications", [])
    active_objective: ActiveObjectiveContext = state["active_objective"]
    # Entering this node counts as one finished objective, whether or not specifications were extracted
    executed_count = state.get("executed_objectives_count", 0) + 1

    # ==========================================
    # Rule 1: nothing to do when cur_obj_specifications is empty
    # ==========================================
    if not cur_obj_specifications:
        return {"status": "dedup_finished", "executed_objectives_count": executed_count}

    # Group by role (O(N))
    pending_by_role: Dict[str, List[SpecificationUnion]] = {}
    for spec in cur_obj_specifications:
        pending_by_role.setdefault(spec.role, []).append(spec)
        
    historical_by_role: Dict[str, List[SpecificationUnion]] = {}
    for spec in historical_specs:
        historical_by_role.setdefault(spec.role, []).append(spec)
        
    all_roles = set(pending_by_role.keys()) | set(historical_by_role.keys())
    
    specs_to_keep_directly = []  # kept without an LLM check
    specs_to_dedup = []          # sent to the LLM for comparison
    historical_context = []      # historical baseline sent to the LLM
    
    # ==========================================
    # Rule 2: prune orthogonally by role
    # a. if historical_specs is empty, add all cur_obj_specifications directly
    # b. if a role appears only in cur_obj_specifications, no dedup check is needed for it
    # c. if a role appears only in historical_specs, it is neither deduplicated nor added to the prompt
    # ==========================================
    for role in all_roles:
        p_specs = pending_by_role.get(role, [])
        h_specs = historical_by_role.get(role, [])
        
        if p_specs and not h_specs:
            # Case A: present only in pending (also covers the empty-history case)
            # keep everything without dedup
            specs_to_keep_directly.extend(p_specs)
            
        elif h_specs and not p_specs:
            # Case B: present only in historical
            # nothing to do; history stays as-is and is not part of this update
            pass 
            
        else:
            # Case C: the role exists on both sides; duplicates are possible, so ask the LLM
            specs_to_dedup.extend(p_specs)
            historical_context.extend(h_specs)

    # ==========================================
    # Semantic dedup via the LLM (only when both sides share a role)
    # ==========================================
    specs_kept_after_llm = []
    if specs_to_dedup:
        # Build compact summaries
        h_summaries = [text_process.extract_spec_summary(s) for s in historical_context]
        p_summaries = [text_process.extract_spec_summary(s) for s in specs_to_dedup]

        system_prompt = DEDUP_SYSTEM_PROMPT.format(
            global_system_prompt=render_global_system_prompt(
                state.get("exploration_direction", ""),
                state.get("direction_id", ""),
            )
        )

        user_prompt = DEDUP_USER_PROMPT_TEMPLATE.format(
            historical_specs_json=json.dumps(h_summaries, indent=2, ensure_ascii=False),
            new_specs_json=json.dumps(p_summaries, indent=2, ensure_ascii=False)
        )

        dedup_llm = get_llm_based_on_config(config).with_structured_output(ResultDeduplication, method="json_mode", include_raw=True)

        # Log the prompt for this objective
        log_target_dir = os.path.join(config["configurable"].get("loggging_path"), f"{active_objective.objective.id}_result_dedup")
        log_json(log_target_dir, 
                f"{active_objective.objective.id}_result_deduplication_prompt", 
                {"system_prompt": system_prompt, "user_prompt": user_prompt}
        )

        # stdout log: objective id
        StdoutLogger.info(f"{active_objective.objective.id}: result deduplication node", STDOUT_LOG_PHASE)

        valid_dedup_ids = {s.spec_id for s in specs_to_dedup} # legal discardable ids, used for validation

        messages_list = []
        parsed_output = None
        if_response_success = False
        for i in range(MAX_RETRIES):
            StdoutLogger.info(f"    Generation Tries: {i + 1}", STDOUT_LOG_PHASE)
            msgs = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt),
                *messages_list
            ]
            # Backoff retries inside; a total failure returns None, treated as a failed round
            # (parsed_output stays None) and retried; when exhausted, dedup_keep_all below applies.
            whole_response = fallback.invoke_llm_with_fallback(
                dedup_llm, msgs,
                node="AnalysisAgent.result_deduplication_node",
                log_dir=log_target_dir,
                spec_id="analysis:result_dedup",
            )
            if whole_response is None:
                messages_list = [HumanMessage(content=(
                    "System notice: the previous LLM call did not return successfully (server queue timeout / network error), so this round produced nothing. Please generate again."
                ))]
                continue

            raw_msg = whole_response["raw"]
            parsed_output = whole_response["parsed"]
            parsing_error = whole_response.get("parsing_error")

            # Log the response
            log_message(log_target_dir, f"tries_{i+1}_response.json", raw_msg)

            messages_list = [raw_msg]
            if parsed_output is None:
                messages_list.append(result_check.get_parse_error_message(parsing_error))
                continue
            
            # Validate discarded_new_result_ids (anti-hallucination)
            if not parsed_output.reserve_new_results and parsed_output.discarded_new_result_ids:
                invalid_ids = [sid for sid in parsed_output.discarded_new_result_ids if sid not in valid_dedup_ids]
                if invalid_ids:
                    messages_list.append(
                        HumanMessage(
                            f"Validation failed: `discarded_new_result_ids` contains IDs that do not exist in the current dedup candidate list: {invalid_ids}.\n"
                            f"The legal specification IDs you may discard are: {sorted(list(valid_dedup_ids))}.\n"
                            f"Fix your output so that only IDs from that list are discarded.\n"
                        )
                    )
                    continue # trigger a retry
                    
            # All checks passed
            if_response_success = True 
            break
            
        # Apply the LLM verdict
        if not if_response_success:
            # All retries failed: the verdict is untrustworthy, so keep everything (redundancy over wrongful deletion)
            specs_kept_after_llm = fallback.dedup_keep_all(
                specs_to_dedup,
                log_dir=log_target_dir,
                objective_id=active_objective.objective.id,
                detail=f"Semantic dedup failed validation {MAX_RETRIES} times; all specifications from this objective are kept",
            )
        elif parsed_output and not parsed_output.reserve_new_results:
            discard_set = set(parsed_output.discarded_new_result_ids)
            specs_kept_after_llm = [s for s in specs_to_dedup if s.spec_id not in discard_set]
        else:
            # The LLM explicitly kept everything
            specs_kept_after_llm = specs_to_dedup

    # ==========================================
    # Assemble the new specifications to append to the global state
    # ==========================================
    final_new_specs = specs_to_keep_directly + specs_kept_after_llm
    result_update.gen_spec_ids(final_new_specs, prefix = active_objective.objective.id) # renumber

    # The state reducer (e.g. operator.add) appends these to taint_specifications
    return {
        "taint_specifications": final_new_specs, 
        "cur_obj_specifications": [],  # clear the staging area
        "executed_objectives_count": executed_count # update the executed-objective count
    }
