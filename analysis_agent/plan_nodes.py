import json
import os
from typing import List
from collections import Counter

from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage, RemoveMessage

from langchain_deepseek import ChatDeepSeek
from langchain_core.runnables import RunnableConfig

# global module
from logger import StdoutLogger, log_local, log_json, log_message
from llm_model import get_llm_based_on_config

# analysis agent local module
from analysis_agent.data_model.plan_data_model import AnalysisPlan, InitialPlanOutput, InvestigationObjective, PlanUpdateResult
from analysis_agent.data_model.review_node_data import ReviewVerdict, ActiveObjectiveContext

from analysis_agent.prompts.global_prompt import render_global_system_prompt
from analysis_agent.prompts.plan_prompt import PLANNING_SYSTEM_PROMPT, PLANNING_USER_PROMPT_TEMPLATE, PLAN_UPDATE_SYSTEM_PROMPT, PLAN_UPDATE_USER_PROMPT_TEMPLATE

from analysis_agent.utils import result_check, text_process, result_update, fallback

# Stdout Log Phase
STDOUT_LOG_PHASE = "analysis_agent"

# Maximum retry generation times
MAX_RETRIES = 5

# README truncation limit for the planning node (only very long READMEs are cut)
README_TRUNCATE_LIMIT = 8000

# ==========================================
# Node 1: Plan
# ==========================================
def initial_planning_node(state: dict, config: RunnableConfig) -> dict:
    """Generate the initial hypothesis-driven plan."""

    # 1. Load the project README
    readme_path = os.path.join(state["project_root"], "README.md")
    project_readme = "The target project provides no README" # default content
    if os.path.exists(readme_path):
        try:
            with open(readme_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                project_readme = content[:README_TRUNCATE_LIMIT] + ("\n...[Truncated]" if len(content) > README_TRUNCATE_LIMIT else "")
        except Exception:
            pass

    # Load the target project's top-level layout
    top_level_layout = text_process.get_top_level_layout(state["project_root"])

    system_prompt = PLANNING_SYSTEM_PROMPT.format(
        global_system_prompt=render_global_system_prompt(
            state.get("exploration_direction", ""),
            state.get("direction_id", ""),
        )
    )

    # 3. Format the user prompt safely (avoid LangChain template parsing, which would break on {} in the README)
    user_prompt = PLANNING_USER_PROMPT_TEMPLATE.format(
        cwe_id=state["cwe_id"],
        project_name=state["project_name"],
        exploration_direction=state.get("exploration_direction", ""),
        readme=project_readme,
        # additional_information = state["additional_information"]
        top_level_layout=top_level_layout, # inject the top-level directory tree
    )

    # Log the prompt
    log_target_dir = os.path.join(config["configurable"].get("loggging_path"), f"initia_plan")
    log_json(log_target_dir, f"user_prompt", {"user_prompt": user_prompt})

    # stdout log: objective id
    StdoutLogger.info("Analysis Agnet: initial planning node", STDOUT_LOG_PHASE)

    # Configure the LLM
    plan_llm = get_llm_based_on_config(config).with_structured_output(
        InitialPlanOutput,
        method="json_mode",    # force the json_object protocol to avoid json_schema errors
        include_raw=True    # keep the raw output
    )

    # Generate the response
    messages_list = []
    objectives = []
    if_response_success = False
    for i in range(MAX_RETRIES):
        StdoutLogger.info(f"    Generation Tries: {i + 1}", STDOUT_LOG_PHASE)
        # Build the message list
        plan_prompt = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
            *messages_list
        ]

        # Backoff retries inside; a total failure returns None (no exception escapes to abort the
        # direction), so this is treated as a failed round and retried below
        whole_response = fallback.invoke_llm_with_fallback(
            plan_llm, plan_prompt,
            node="AnalysisAgent.initial_planning_node",
            log_dir=log_target_dir,
            spec_id="analysis:initial_planning",
        )
        if whole_response is None:
            messages_list = [HumanMessage(content=(
                "System notice: the previous LLM call did not return successfully (server queue timeout / network error), so this round produced nothing. Please generate again."
            ))]
            continue

        raw_msg = whole_response["raw"]
        parsed_output: InitialPlanOutput = whole_response["parsed"]
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
        
        # b. Validate the goals and build objectives deterministically
        if len(parsed_output.initial_goals) == 0:
            messages_list.append(HumanMessage("Validation failed: the goal list `initial_goals` is empty; generate again.\n"))
            continue # retry
        
        # c. Validate every goal and build each objective
        objectives = []
        if_validation_passed = True
        error_msg = HumanMessage("OK")
        for idx, obj in enumerate(parsed_output.initial_goals):
            missed_fields = [] if obj.goal else ["`goal`"]
            missed_fields.extend([] if obj.expected_output else ["`expected_output`"])
            if len(missed_fields) !=0:
                error_msg = HumanMessage(f"Validation failed: goal {idx+1} in `initial_goals` has empty field(s): {", ".join(missed_fields)}. Re-check the goal definition.\n")
                
                if_validation_passed = False
                break

            obj_id = f"obj_{idx+1:04d}" # obj_0001, obj_0002, ...
            objectives.append(
                InvestigationObjective(
                    id=obj_id,
                    goal=obj.goal,
                    expected_output=obj.expected_output,
                    status="pending",
                    execution_narrative="",
                    resolution_summary=None
                )
            )

        if not if_validation_passed:
            messages_list.append(error_msg)
            continue # retry
        else:
            if_response_success = True
            break # success

    # All retries failed: fall back to a deterministic default plan instead of aborting the direction
    if not if_response_success:
        return fallback.initial_plan(
            state,
            log_dir=log_target_dir,
            detail=f"Initial planning failed validation {MAX_RETRIES} times; continuing with the default plan",
        )

    # Activate the first objective
    if objectives:
        objectives[0].status = "investigating"
        current_id = objectives[0].id
    else:
        current_id = ""

    active_objective = ActiveObjectiveContext(
        objective = objectives[0],
        status = "INITIATING",
        reason = "",
        initial_result=None,
        cur_result=None,
        refinements=[],
        specifications=[]
    )

    # Assemble the final AnalysisPlan
    final_plan = AnalysisPlan(
        project_profile=parsed_output.project_profile,
        core_hypotheses=parsed_output.core_hypotheses,
        objectives=objectives,
        current_objective_id=current_id,
        is_completed=False
    )

    return {
        "plan": final_plan, 
        "taint_specifications": [], # initialize the result collection
        "active_objective": active_objective, # the first objective becomes the active one
        "status": "executing",
        "step_count": 0,
        "compressed_summary": ""
        # Never return messages here; keep the interaction trace clean
    }

# ==========================================
# Node 2: Plan Update
# ==========================================
def plan_update_node(state: dict, config: RunnableConfig) -> dict:
    plan: AnalysisPlan = state["plan"]
    active_objective: ActiveObjectiveContext = state["active_objective"]
    cur_result = active_objective.cur_result

    # Number of executed objectives (defaults to 0)
    executed_count = state.get("executed_objectives_count", 0)

    # Build the global objective context
    global_objectives_text = text_process.gen_global_objectives_text(plan, True)

    # 2. Summarize the extracted specifications
    taint_specs = state.get("taint_specifications", [])
    role_counter = Counter(spec.role for spec in taint_specs)
    source_count = role_counter.get('source', 0)
    sink_count = role_counter.get('sink', 0)
    arsenal_stats = f"source: {source_count}, sink: {sink_count}, summary: {role_counter.get('summary', 0)}"
    
    if taint_specs:
        spec_lines = [f"- [{s.spec_id}] ({s.role}) {s.description}" for s in taint_specs]
        extracted_specs_summary = "\n".join(spec_lines)
    else:
        extracted_specs_summary = "No specifications extracted yet."

    # ==========================================
    #  Soft reminder only (no hard requirement, no validation).
    #  Under multi-direction parallel exploration a single direction need not cover every role,
    #  and is not forced to avoid finishing early.
    # ==========================================
    missing_parts = []
    if source_count == 0:
        missing_parts.append("Source (taint entry)")
    if sink_count == 0:
        missing_parts.append("Sink (taint trigger point)")
    missing_desc = ", ".join(missing_parts)

    exploration_reminder = ""
    if missing_parts:
        exploration_reminder = (
            "Soft reminder: a core element has not been produced yet.\n"
            f"The specification library has no {missing_desc} yet (source: {source_count}, sink: {sink_count}).\n"
            "If this direction still has an unverified high-value hypothesis pointing at that element, prefer adding it; "
            "if the element does not naturally belong to this direction, or the direction has converged, the plan may end normally -- do not force an inference just to fill a role."
        )
    elif executed_count < 2:
        exploration_reminder = (
            "Soft reminder: early exploration stage.\n"
            f"{executed_count} objectives executed so far. If this direction still has uncovered core hypotheses, you may extend the plan; "
            "if pending objectives already cover this direction's core hypotheses, the plan may end naturally."
        )

    # Prepend the global system prompt to the planning prompt
    system_prompt = PLAN_UPDATE_SYSTEM_PROMPT.format(
        global_system_prompt=render_global_system_prompt(
            state.get("exploration_direction", ""),
            state.get("direction_id", ""),
        )
    )

    # Build the user prompt
    user_prompt = PLAN_UPDATE_USER_PROMPT_TEMPLATE.format(
        project_name=state["project_name"],
        project_profile=plan.project_profile,
        cwe_id=state["cwe_id"],
        exploration_direction=state.get("exploration_direction", ""),
        core_hypotheses="\n".join([f"- {h}" for h in plan.core_hypotheses]),
        all_objectives_text=global_objectives_text,
        objective_id=active_objective.objective.id,
        objective_goal=active_objective.objective.goal,
        objective_expected_output=active_objective.objective.expected_output or "none",
        review_status=active_objective.status,
        review_reason=active_objective.reason or "none",
        execution_summary=cur_result.execution_summary if cur_result else "none",
        execution_report=cur_result.execution_report if cur_result else "none",
        # Current global specification summary
        extracted_specs_summary=extracted_specs_summary,
        arsenal_stats = arsenal_stats,
        exploration_reminder=exploration_reminder,
    )

    # 4. Call the LLM
    plan_update_llm = get_llm_based_on_config(config).with_structured_output(
        PlanUpdateResult,
        method="json_mode",
        include_raw=True
    )

    # Log the prompt for this objective
    log_target_dir = os.path.join(config["configurable"].get("loggging_path"), f"{active_objective.objective.id}_plan_update")
    log_json(log_target_dir, 
            f"{active_objective.objective.id}_plan_update_prompt", 
            {"system_prompt": system_prompt, "user_prompt": user_prompt}
    )

    # stdout log: objective id
    StdoutLogger.info(f"{active_objective.objective.id}: plan update node", STDOUT_LOG_PHASE)

    messages_list = []
    if_response_success = False
    for i in range(MAX_RETRIES):
        StdoutLogger.info(f"    Generation Tries: {i + 1}", STDOUT_LOG_PHASE)
        msgs = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
            *messages_list
        ]

        # Backoff retries inside; a total failure returns None (no exception escapes to abort the
        # direction), so this is treated as a failed round and retried below
        whole_response = fallback.invoke_llm_with_fallback(
            plan_update_llm, msgs,
            node="AnalysisAgent.plan_update_node",
            log_dir=log_target_dir,
            spec_id="analysis:plan_update",
        )
        if whole_response is None:
            messages_list = [HumanMessage(content=(
                "System notice: the previous LLM call did not return successfully (server queue timeout / network error), so this round produced nothing. Please generate again."
            ))]
            continue

        raw_msg = whole_response["raw"]
        parsed_output: PlanUpdateResult = whole_response["parsed"]
        parsing_error = whole_response.get("parsing_error")
        
        # Log the response
        log_message(log_target_dir, f"tries_{i+1}_response.json", raw_msg)

        messages_list = [raw_msg]

        if parsed_output is None:
            messages_list.append(result_check.get_parse_error_message(parsing_error))
            continue

        is_valid, error_msg = result_check.check_plan_update_result(
            parsed_output, plan, active_objective.objective.id
        )
        if not is_valid:
            messages_list.append(error_msg)
            continue
        
        new_plan = result_update.apply_plan_update(plan, parsed_output)

        if_response_success = True
        break
        
    # All retries failed: keep the plan unchanged and continue instead of aborting the direction
    if not if_response_success:
        new_plan = fallback.plan_update(
            plan,
            log_dir=log_target_dir,
            objective_id=active_objective.objective.id,
            detail=f"Plan update failed validation {MAX_RETRIES} times; keeping the plan unchanged and continuing",
        )

    return {
        "plan": new_plan
    }
