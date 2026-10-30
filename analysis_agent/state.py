from typing import TypedDict, Annotated, List, Literal
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage
from pydantic import Field
from langchain_core.tools import BaseTool
import operator

# global module
from global_data_model.analysis_result import SpecificationUnion

# analysis agent local module
from analysis_agent.data_model.plan_data_model import AnalysisPlan
from analysis_agent.data_model.review_node_data import ActiveObjectiveContext

class AnalyzerState(TypedDict):
    # --- Environment inputs (read-only) ---
    project_root: str
    project_name: str
    cwe_id: str
    max_steps: int

    # --- Multi-direction exploration inputs (read-only) ---
    # direction_id: identifier of the current exploration direction (e.g. "D01"),
    #               used for per-direction log directories and spec provenance
    # exploration_direction: direction guidance injected into plan/global prompts
    direction_id: str = Field(default="", description="Identifier of the current exploration direction (e.g. D01)")
    exploration_direction: str = Field(default="", description="Exploration-direction guidance injected into the prompts")

    # --- Core memory and plan (read/write) ---
    plan: AnalysisPlan

    # --- Number of executed objectives ---
    executed_objectives_count: int
    # --- Maximum number of objectives that may be executed ---
    max_executed_objectives_count: int

    # --- Objective currently being executed
    active_objective: ActiveObjectiveContext

    # Core output: the taint-specification library (a top-level field instead of
    # a blackboard, which in the current design holds only this field)
    taint_specifications: Annotated[List[SpecificationUnion], operator.add]

    # Newly extracted specifications from the current objective; deduplicate
    # before adding them to taint_specifications
    cur_obj_specifications: List[SpecificationUnion]
    
    # --- Short-term working memory (sliding window) ---
    # add_messages appends messages automatically
    messages: Annotated[List[BaseMessage], add_messages] 
    
    # --- Control flow ---
    status: Literal["init", "planning", "executing", "finished"] # "reflecting", "compressing",

    # --- Additional information
    additional_information: str = Field(default="no additional information", description="Additional information")