import os
from typing import List, Optional
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_core.messages import ToolMessage, BaseMessage
from langchain_deepseek import ChatDeepSeek

# analysis agent module
from analysis_agent.executor_agent.executor_data_model import ExecutorState
from analysis_agent.executor_agent.executor_nodes import (
    analyze_agent_node, updater_agent_node, after_tool_node, after_update_node, UPDATER_INTERVAL,
)
from analysis_agent.tools.file_ops import list_directory_structure, grep_code, read_file_content
from analysis_agent.tools.symbol_ops import search_class, get_class_outline, search_method, get_method_definition, search_usage

# executor agent local module
from analysis_agent.executor_agent.executor_tool import signal_exploration_done

TOOLS = [list_directory_structure, grep_code, read_file_content, 
         search_class, get_class_outline, search_method, get_method_definition, search_usage,
         signal_exploration_done]

# ==========================================
# Routing functions
# ==========================================
def route_after_analyze(state: ExecutorState) -> str:
    """
    Routing after analyze_agent_node:
    - LLM requested tool calls -> tools (after_tool then decides whether to run the Updater)
    - LLM produced plain text without tool calls -> end the subgraph
    """
    # If already finished, stop (defensive; normally the updater node ends the run)
    if state.get("status") == "finished":
        return "end"
    
    messages = state.get("messages", [])
    if not messages: # should not normally happen
        return "end"
        
    last_msg = messages[-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
        return "tools"
    
    # Fallback for unexpected message shapes
    return "end"


def route_after_tool(state: ExecutorState) -> str:
    """
    Routing after after_tool_node: the Updater Agent runs every UPDATER_INTERVAL rounds.
    - Updater round   -> update (summarize accumulated interaction, maintain the code-memory pool, decide completion)
    - Non-updater round -> after_update (advance step_count and snapshot/truncation bookkeeping without an LLM call)

    Non-updater rounds must not skip after_update: step_count advances there, and
    snapshots and truncation depend on it; otherwise messages accumulate without
    the step counter moving.
    """
    round_number = state.get("step_count", 0) + 1   # step_count is the number of completed rounds
    if round_number % UPDATER_INTERVAL == 0:
        return "update"
    return "after_update"


def route_after_updater(state: ExecutorState) -> str:
    """
    Routing after the Updater Agent:
    - status == "finished" (final result submitted or step limit reached) -> end the subgraph
    - otherwise -> continue to after_update
    """
    if state.get("status") == "finished":
        return "end"
    return "after_update"


# ==========================================
# 4. Build and compile the subgraph
# ==========================================
def build_executor_subgraph():
    """
    Build the ObjectiveExecutorAgent subgraph.
    It takes a single Objective and outputs a structured ExecutionResult.
    """
    workflow = StateGraph(ExecutorState)
    
    # Register nodes
    workflow.add_node("analyze", analyze_agent_node)
    workflow.add_node("tools", ToolNode(TOOLS))
    workflow.add_node("update", updater_agent_node)
    workflow.add_node("after_tool", after_tool_node)       # logging
    workflow.add_node("after_update", after_update_node)   # update history snapshots
    
    # Entry point
    workflow.set_entry_point("analyze")
    
    # Edges and conditional routing
    workflow.add_edge("tools", "after_tool")        # always log ToolMessages after tool calls
    workflow.add_edge("after_update", "analyze")    # return to analysis after snapshot bookkeeping

    workflow.add_conditional_edges(
        "analyze", route_after_analyze,
        {"tools": "tools",  "end": END}
    )

    workflow.add_conditional_edges(
        "after_tool", route_after_tool,
        {"update": "update", "after_update": "after_update"}
    )

    workflow.add_conditional_edges(
        "update",
        route_after_updater,
        {"after_update": "after_update", "end": END}
    )
    
    return workflow.compile()


# ==========================================
# Exported singleton used by the parent graph
# ==========================================
executor_subgraph = build_executor_subgraph()