# analyzer_agent/graph.py
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from typing import Literal
from langchain_core.runnables import RunnableConfig

from analysis_agent.state import AnalyzerState
from analysis_agent.plan_nodes import initial_planning_node, plan_update_node
from analysis_agent.process_nodes import review_agent_node, result_extract_agent_node, plan_promotion_node, result_deduplication_node
import analysis_agent.state_transfer as state_transfer

from analysis_agent.executor_agent.executor_graph import executor_subgraph 

def executor_wrapper_node(
    analyzer_state: AnalyzerState, 
    config: RunnableConfig  # required so it can be passed to the subgraph
) -> dict:
    """
    Wrapper node: converts state and invokes the Executor subgraph from the Analyzer graph.
    """
    # 1. Parent state -> subgraph state
    executor_input = state_transfer.transfer_analyzer_to_executor(analyzer_state)
    
    # 2. Invoke the subgraph
    # config is required so the subgraph inherits the parent's thread_id, callbacks, etc.
    executor_output = executor_subgraph.invoke(executor_input, config)
    
    # 3. Subgraph state -> parent state
    # Produce only the fields that need updating.
    parent_update = state_transfer.update_analyzer_from_executor(analyzer_state, executor_output)
    
    # 4. Return the update dict; LangGraph merges it into the parent state
    return parent_update

def route_after_review(state: AnalyzerState) -> str:
    # Route according to the active objective status
    active_objective = state["active_objective"]
    if active_objective is None:
        return "end"
    
    if active_objective.status == 'NEEDS_REFINEMENT':
        return "execute" # needs refinement, keep executing
    else:
        return "extract" # otherwise extract the result
    
def route_after_result_dedup(state: AnalyzerState) -> str:
    # Route according to the number of executed objectives
    execution_count = state.get("executed_objectives_count", 0)
    max_execution_count = state.get("max_executed_objectives_count", 15)
    if execution_count >= max_execution_count: # objective limit reached, stop
        return "end"
    else:
        return "plan_update" # otherwise update the plan

def route_after_plan_promotion(state: AnalyzerState) -> str:
    # Check the explicit status flag
    if state.get("status") == "finished":
        return "end"
    
    return "execute" # otherwise continue the Agent flow

# def route_after_tool(state: AnalyzerState) -> str:
#     if len(state["messages"]) > 8:
#         return "compress"
#     return "agent"

def build_analyzer_agent():
    workflow = StateGraph(AnalyzerState)
    
    workflow.add_node("planning", initial_planning_node)
    workflow.add_node("execute", executor_wrapper_node)
    workflow.add_node("review", review_agent_node)
    workflow.add_node("plan_promotion", plan_promotion_node)
    workflow.add_node("result_extract", result_extract_agent_node)
    workflow.add_node("result_deduplication", result_deduplication_node)
    workflow.add_node("plan_update", plan_update_node)
    
    workflow.set_entry_point("planning")   # start with initial planning
    workflow.add_edge("planning", "execute")   # after planning, enter the Executor ReAct loop
    workflow.add_edge("execute", "review")   # review after each Executor round

    workflow.add_conditional_edges("review", route_after_review, { # continue or extract based on the objective status
        "execute": "execute",
        "extract": "result_extract",
        "end": END
    })

    workflow.add_edge("result_extract", "result_deduplication")   # deduplicate after extraction

    # After deduplication, continue only while the objective limit is not reached
    workflow.add_conditional_edges("result_deduplication", route_after_result_dedup, {
        "plan_update": "plan_update",
        "end": END
    })

    # workflow.add_edge("result_deduplication", "plan_update") # plan update after deduplication
    workflow.add_edge("plan_update", "plan_promotion")   # promote the plan after updating it
    
    workflow.add_conditional_edges("plan_promotion", route_after_plan_promotion, { # deterministic continue/stop decision
        "execute": "execute",
        "end": END
    })
    
    return workflow.compile()