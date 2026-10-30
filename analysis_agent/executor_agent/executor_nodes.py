import json
import os
from typing import List

from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage, RemoveMessage, BaseMessage
from langchain_deepseek import ChatDeepSeek
from langchain_core.runnables import RunnableConfig

# global module
from logger import StdoutLogger, log_json, log_message
from llm_model import get_llm_based_on_config

# analysis agent  module
from analysis_agent.data_model.plan_data_model import AnalysisPlan, InvestigationObjective
from analysis_agent.data_model.review_node_data import RefinementRecord, ExecutionResult

from analysis_agent.tools.file_ops import list_directory_structure, grep_code, read_file_content
from analysis_agent.tools.symbol_ops import search_class, get_class_outline, search_method, get_method_definition, search_usage

from analysis_agent.utils import text_process, message_process, fallback

# executor agent local module
import analysis_agent.executor_agent.executor_utils as executor_utils
from analysis_agent.executor_agent.executor_tool import signal_exploration_done
from analysis_agent.executor_agent.executor_data_model import UpdateResult

from analysis_agent.executor_agent.prompts.analyzer_prompts import ANALYZER_SYSTEM_PROMPT
from analysis_agent.executor_agent.prompts.updater_prompts import UPDATER_SYSTEM_PROMPT

# Stdout Log Phase
STDOUT_LOG_PHASE = "analysis_agent/executor_agent"

# Initiate Tools List
TOOLS = [list_directory_structure, grep_code, read_file_content, 
         search_class, get_class_outline, search_method, get_method_definition, search_usage,
         signal_exploration_done]

# Global constants
N = 4   # Snapshot period (save pre_snapshot every N steps)
K = 2   # Number of turns kept on truncation (keep only the last K turns of messages)

# Updater inspection period: the Updater Agent is invoked once every UPDATER_INTERVAL turns
# (the router in executor_graph.py shares this constant). Non-inspection turns skip the
# Updater LLM call, but after_update_node still runs every turn, so step_count and the
# snapshot/truncation bookkeeping are unaffected; on an inspection turn the Updater sees the
# UPDATER_INTERVAL turns accumulated since the previous inspection.
UPDATER_INTERVAL = 2

# Maximum number of retries
MAX_RETRIES = 5

# ==========================================
# Node 1: execution node (Execute)
# ==========================================
def analyze_agent_node(state: dict, config: RunnableConfig) -> dict:
    """Execution node: read the current plan, build the prompt, and ask the LLM for a tool call"""
    plan: AnalysisPlan = state["plan"]
    messages: List[BaseMessage] = list(state["messages"])
    cur_objective = state["cur_objective"]

    #  Determine whether this is the first execution or a refinement round
    prev_result: ExecutionResult = state.get("result")
    pending_refinement: RefinementRecord = state.get("pending_refinement")
    execution_count = state.get("execution_count", 1)
    is_refinement = prev_result is not None and pending_refinement is not None and execution_count >= 0

    # 1. Termination check (defensive)
    if plan.is_completed or state.get("step_count", 0) >= state.get("max_steps", 20):
        return {"status": "finished"}

    # 2. Build the system prompt
    system_content = ANALYZER_SYSTEM_PROMPT

    # 3. Build the prompt parts (history_prompt + action_prompt)
    global_prompt = executor_utils.gen_global_user_prompt(is_refinement, state)
    history_prompt = executor_utils.gen_analyzer_history_prompt(is_refinement, state)
    action_prompt = executor_utils.gen_analyzer_action_prompt(is_refinement, state) 

    # Persist the prompt
    step_num = state.get("step_count", 0) + 1
    log_target_dir = os.path.join(
        config["configurable"].get("loggging_path"),
        f"execution_{cur_objective.id}",
        f"execution_{execution_count}"
    )
    log_json(log_target_dir,
             f"step_{step_num}_analyzer_user_prompt",
             {"history_prompt": history_prompt, "action_prompt": action_prompt})

    # Log the system prompt and global user prompt only on the first step
    if step_num == 1:
        log_json(log_target_dir,
                 "global_prompt",
                 {"system_prompt": system_content, "global_user_prompt": global_prompt})

    # 4. Define the model and bind tools
    #    bind_tools_compat is used because some relay providers reject the combination of
    #    function tools and reasoning on /v1/chat/completions with HTTP 400. It prefers the
    #    /v1/responses endpoint (see use_responses_api in llm_model.py) where both coexist,
    #    so no reasoning_effort is added; only when that endpoint is unavailable does it fall
    #    back to explicitly passing reasoning_effort='none'.
    #    The decision and handling live in retry_policy; the import is lazy to avoid
    #    import-time ordering coupling between analysis_agent and codeql_agent (same pattern
    #    as utils/fallback.py). For the default provider this is equivalent to the previous
    #    `bind_tools(TOOLS)` with no extra arguments.
    from codeql_agent.retry_policy import bind_tools_compat
    execution_llm = bind_tools_compat(get_llm_based_on_config(config), TOOLS)

    # Intermediate messages carried into retries
    messages_list = []
    if_response_success = False
    response = None

    # stdout log: execution step and message count
    StdoutLogger.info(f"{cur_objective.id}:execution {execution_count}: step {step_num} analysis node: {len(messages)}", STDOUT_LOG_PHASE)

    for i in range(MAX_RETRIES):
        StdoutLogger.info(f"Generation Tries: {i + 1}")
        # a. Assemble the messages (head / middle / tail; only middle is token-budget trimmed)
        head = [
            SystemMessage(content=system_content),        # 1. global persona
            HumanMessage(content=global_prompt),          # 2. background profile
        ]
        middle = list(messages)                           # 4. conversation history
        # History summary: inserted only after truncation (i.e. when a snapshot exists);
        # otherwise messages already contains the full history
        if history_prompt:
            middle.insert(0, HumanMessage(content=history_prompt))
        tail = [
            HumanMessage(content=action_prompt),          # 5. action guide
            *messages_list,                               # 6. retry and error messages
        ]

        # Token guard: trim by estimated tokens **before** invoke (not relying solely on the
        # step-based truncation in after_update; an oversized single ToolMessage is truncated
        # in place here). Byte-identical when under budget.
        full_msgs = message_process.budget_guard(
            head, middle, tail,
            log_dir=log_target_dir,
            tag=f"{cur_objective.id}_step_{step_num}_analyzer",
        )

        # Pairing invariant: check (and dump evidence) then repair tool_calls pairing before
        # invoke, instead of letting a provider 400 kill the run
        message_process.dump_pairing_violation(
            full_msgs, log_target_dir, tag=f"{cur_objective.id}_step_{step_num}_analyzer")
        full_msgs, _pairing_repairs = message_process.repair_tool_call_pairing(full_msgs)

        # b. Invoke the LLM
        # Retries with backoff; returns None if everything fails (no bare exception that would
        # abort the whole direction) -- treated as a failed generation for this try, moving on to
        # the next of MAX_RETRIES attempts; when exhausted, analyzer_forced_done takes over below.
        response = fallback.invoke_llm_with_fallback(
            execution_llm, full_msgs,
            node="AnalysisAgent.analyze_agent_node",
            log_dir=log_target_dir,
            spec_id="analysis:analyze_agent",
        )
        if response is None:
            messages_list = [HumanMessage(content=(
                "⚠️ [System notice] The previous LLM call did not return successfully (server-side queue timeout / network error), so this attempt produced nothing. Regenerate the response."
            ))]
            continue

        # Persist the response
        log_message(log_target_dir,
                    f"step_{step_num}_tries_{i+1}_analyzer_response.json",
                    response)

        # c. Check for tool calls
        if hasattr(response, "tool_calls") and response.tool_calls:
            if_response_success = True
            break

        # No tool call: issue a correction
        correction_msg = HumanMessage(content=(
            "⚠️ [System correction]\n"
            "You did not call a tool, which violates the system protocol; you must call a tool even if you believe the task is done.\n"
            "When you believe enough evidence has been collected for this stage, or that the current path cannot yield more leads, "
            "you **must call the `signal_exploration_done` tool** to hand control to the Updater for evidence consolidation.\n"
            "Regenerate now."
        ))
        messages_list = [response, correction_msg]

    # All generation attempts failed: synthesize signal_exploration_done and let the Updater finalize
    if not if_response_success:
        response = fallback.analyzer_forced_done(
            objective_id=cur_objective.id,
            log_dir=log_target_dir,
            attempts=MAX_RETRIES,
        )

    return {
        "messages": [response],
        # "step_count": incremented by after_update_node, the last node of every turn
        "status": "executing"
    }

# ==========================================
# Node 2: Updater Agent node, summarizes the analysis process
# ==========================================
def updater_agent_node(state: dict, config: RunnableConfig) -> dict:
    plan: AnalysisPlan = state["plan"]
    messages: List[BaseMessage] = list(state["messages"])
    cur_objective = state["cur_objective"]

    # Determine whether this is the first execution or a refinement round
    prev_result: ExecutionResult = state.get("result")
    pending_refinement: RefinementRecord = state.get("pending_refinement")
    execution_count = state.get("execution_count", 1)
    is_refinement = prev_result is not None and pending_refinement is not None and execution_count >= 0

    # The message list must end with a ToolMessage
    if not messages or not isinstance(messages[-1], ToolMessage):
        raise ValueError("[System] Router Error: after_tool_node Found No ToolMessage")

    # 1. Collect the turns accumulated since the last Updater inspection
    #    (UPDATER_INTERVAL AIMessages plus their following ToolMessages)
    #    while detecting whether signal_exploration_done was called
    if_signal_exploration_done = False
    current_round_msgs: List[BaseMessage] = []
    ai_seen = 0

    for i in range(len(messages) - 1, -1, -1):
        if isinstance(messages[i], ToolMessage):
            current_round_msgs.insert(0, messages[i])
            if messages[i].name == "signal_exploration_done":
                if_signal_exploration_done = True
        elif isinstance(messages[i], AIMessage):
            current_round_msgs.insert(0, messages[i])
            ai_seen += 1
            if ai_seen >= UPDATER_INTERVAL:
                break  # UPDATER_INTERVAL turns covered; stop scanning backwards
        else:
            break

    # 2. Build the Updater-specific prompt parts
    system_content = UPDATER_SYSTEM_PROMPT

    global_prompt = executor_utils.gen_global_user_prompt(is_refinement, state)
    history_prompt = executor_utils.gen_updater_history_prompt(is_refinement, state)
    action_prompt = executor_utils.gen_updater_action_prompt(is_refinement, state)

    # When signal_exploration_done is present, append a high-priority system hint to action_prompt
    if if_signal_exploration_done:
        action_prompt += (
            "\n\n⚠️ [High-priority system hint - forced finalization]\n"
            "The explorer called `signal_exploration_done` in this round and ended the search. "
            "You **must** produce `final_result` in this output to finalize!"
        )

    # Persist the prompt
    step_num = state.get("step_count", 0) + 1

    log_target_dir = os.path.join(
        config["configurable"].get("loggging_path"),
        f"execution_{cur_objective.id}",
        f"execution_{execution_count}"
    )
    # Log the system prompt only on the first step; the global user prompt is shared with the analyzer
    if step_num == 1:
        log_json(log_target_dir, "global_prompt", {"system_prompt": system_content})

    # stdout log: execution step
    StdoutLogger.info(f"{cur_objective.id}:execution {execution_count}: step {step_num} update node", STDOUT_LOG_PHASE)
        
    log_json(log_target_dir,
             f"step_{step_num}_updater_prompt",
             {
                 "history_prompt": history_prompt,
                 "action_prompt": action_prompt
             })

    # 3. Define the model with a structured output type
    updater_llm = get_llm_based_on_config(config).with_structured_output(
        UpdateResult,
        method="json_mode",
        include_raw=True
    )

    # Intermediate messages carried into retries
    messages_list = []
    if_response_success = False

    for i in range(MAX_RETRIES):
        StdoutLogger.info(f"Generation Tries: {i + 1}", STDOUT_LOG_PHASE)
        # a. Assemble the Updater's short message list (head / middle / tail)
        head = [
            SystemMessage(content=system_content),          # 1. Updater system prompt (full JSON schema)
            HumanMessage(content=global_prompt),            # 2. global user prompt (shared with the Analyzer)
            HumanMessage(content=history_prompt),           # 3. live narrative + live code pool (changes slightly each step)
        ]
        middle = list(current_round_msgs)                   # 4. turns accumulated since the last inspection
        tail = [
            HumanMessage(content=action_prompt),            # 5. objective reminder + focus instruction + JSON format reminder
            *messages_list                                  # 6. retry and error messages
        ]

        # Token guard: this is where HTTP 400 overflow errors actually occur, so the guard must run before invoke
        full_msgs = message_process.budget_guard(
            head, middle, tail,
            log_dir=log_target_dir,
            tag=f"{cur_objective.id}_step_{step_num}_updater",
        )

        # Pairing invariant: check plus repair before this invoke
        message_process.dump_pairing_violation(
            full_msgs, log_target_dir, tag=f"{cur_objective.id}_step_{step_num}_updater")
        full_msgs, _pairing_repairs = message_process.repair_tool_call_pairing(full_msgs)

        # b. Invoke the LLM
        # Retries with backoff; None means the generation failed for this try, so move on to the
        # next of MAX_RETRIES attempts (updater_forced_finalize takes over when exhausted; never
        # raise bare exceptions that would discard the whole direction).
        whole_response = fallback.invoke_llm_with_fallback(
            updater_llm, full_msgs,
            node="AnalysisAgent.updater_agent_node",
            log_dir=log_target_dir,
            spec_id="analysis:updater_agent",
        )
        if whole_response is None:
            messages_list = [HumanMessage(content=(
                "⚠️ [System notice] The previous LLM call did not return successfully (server-side queue timeout / network error), so this attempt produced nothing. Regenerate the response."
            ))]
            continue

        raw_msg = whole_response["raw"]
        parsed_output: UpdateResult = whole_response["parsed"]

        # Persist the response
        log_message(log_target_dir,
                    f"step_{step_num}_tries_{i+1}_updater_response.json",
                    raw_msg)

        # c. Run the validation checks
        messages_list = [raw_msg]

        # Check 1: structured output parsed successfully
        if parsed_output is None:
            messages_list.append(
                HumanMessage("❌ Validation failed: could not parse the result JSON; regenerate the output\n")
            )
            continue

        # Check 2: final_result is required after signal_exploration_done
        if if_signal_exploration_done and parsed_output.final_result is None:
            messages_list.append(
                HumanMessage(
                    "❌ Validation failed: the explorer called `signal_exploration_done` and ended the search. "
                    "You **must** produce `final_result` in this output to finalize! Regenerate now.\n"
                )
            )
            continue

        # Check 3: run the core validation helper
        is_valid, error_msg, new_obj, new_pool, exec_res = executor_utils.check_update_result(
            parsed_output, cur_objective, state["cur_code_results"], state["project_root"]
        )

        if not is_valid:
            messages_list.append(error_msg)
            continue

        # Validation passed: exit the retry loop
        if_response_success = True
        break

    # All generation attempts failed: finalize deterministically from the existing narrative and code pool
    if not if_response_success:
        return fallback.updater_forced_finalize(
            state,
            log_dir=log_target_dir,
            detail=f"the Updater failed validation in all {MAX_RETRIES} attempts; the system finalized using the existing narrative and code pool",
        )

    # 5. Assemble the return value
    result = {
        "cur_code_results": new_pool,
        "cur_objective": new_obj,
    }

    if exec_res:
        result["result"] = exec_res
        result["status"] = "finished"
    else:
        result["status"] = "executing"

    # Step limit reached: terminate and produce a fallback report
    step_count = state.get("step_count", 0) + 1  # include the current step
    max_steps = state.get("max_steps", 20)
    if step_count >= max_steps:
        from analysis_agent.executor_agent.executor_data_model import ExecutionResult
        result["result"] = ExecutionResult(
            execution_summary="The task stopped at the step limit before a complete report was produced.",
            execution_report=f"Current execution narrative:\n{new_obj.execution_narrative}",
            code_results=new_pool if new_pool else []
        )
        result["status"] = "finished"

    return result


def after_tool_node(state: dict, config: RunnableConfig) -> dict:
    """
    Post-tool node:
    1. Persist this round's ToolMessage logs
    2. Do not modify any state; this node only writes logs
    """
    messages: List[BaseMessage] = list(state["messages"])
    cur_objective = state["cur_objective"]
    execution_count = state.get("execution_count", 1)

    log_target_dir = os.path.join(
        config["configurable"].get("loggging_path"),
        f"execution_{cur_objective.id}",
        f"execution_{execution_count}"
    )

    # Scan backwards from the end and persist every ToolMessage of this round
    tool_count = 0
    for i in range(len(messages) - 1, -1, -1):
        if isinstance(messages[i], ToolMessage):
            tool_msg = messages[i]
            tool_count += 1
            step_num = state.get("step_count", 0)
            log_message(
                log_target_dir,
                f"step_{step_num + 1}_tool_{tool_msg.name}_{tool_count:02d}.json",
                tool_msg
            )
        else:
            break  # first non-ToolMessage is the AIMessage that issued these tool calls

    return {}  # no state changes; logging only


def after_update_node(state: dict, config: RunnableConfig) -> dict:
    """
    Post-processing node that runs after the Updater. The current step is complete only
    after this node finishes.

    Responsibilities:
    1. Increment step_count
    2. At a snapshot point (step % N == 0): save pre_snapshot (deep copy)
    3. At a truncation point (step % N == K): promote pre_snapshot to snapshot (deep copy)
       and truncate messages
    """
    messages: List[BaseMessage] = list(state["messages"])
    cur_objective = state["cur_objective"]

    # 1. Increment step_count
    new_step_count = state.get("step_count", 0) + 1

    result = {
        "step_count": new_step_count,
    }

    # 2. Snapshot point: step_count is a multiple of N
    #    Save the live narrative and code pool into pre_snapshot
    if new_step_count > 0 and new_step_count % N == 0:
        # Strings are immutable, so direct assignment is safe
        result["pre_execution_narrative_snapshot"] = cur_objective.execution_narrative or ""
        # Deep-copy the CodeResult list so later mutations cannot affect the snapshot
        result["pre_code_results_snapshot"] = [
            cr.model_copy(deep=True) for cr in state.get("cur_code_results", [])
        ]

    # 3. Truncation point: step_count % N == K
    #    Promote pre_snapshot to the official snapshot and truncate messages
    if new_step_count > 0 and new_step_count % N == K:
        pre_narrative = state.get("pre_execution_narrative_snapshot", "")
        pre_code_results = state.get("pre_code_results_snapshot", [])

        # Truncate only when a pre_snapshot exists
        if pre_narrative:
            # Strings are immutable, so direct assignment is safe
            result["execution_narrative_snapshot"] = pre_narrative
            # Deep-copy the CodeResult list so snapshot and pre_snapshot are fully independent
            result["code_results_snapshot"] = [
                cr.model_copy(deep=True) for cr in pre_code_results
            ]

            # Truncate messages: locate the start of the last K turns
            ai_count = 0
            split_idx = len(messages)
            for i in range(len(messages) - 1, -1, -1):
                if isinstance(messages[i], AIMessage):
                    ai_count += 1
                    if ai_count >= K:
                        split_idx = i
                        break

            # Remove all messages before split_idx
            older_messages = messages[:split_idx]
            if older_messages:
                result["messages"] = [
                    RemoveMessage(id=m.id) for m in older_messages
                    if hasattr(m, 'id') and m.id
                ]

    return result