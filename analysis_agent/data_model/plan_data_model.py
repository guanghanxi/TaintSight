from pydantic import BaseModel, Field
from typing import List, Optional, Literal

# ==========================================
# I. Global plan
# ==========================================
# (1) Investigation objectives
class InvestigationObjective(BaseModel):
    """A hypothesis to verify or a question to settle."""
    id: str = Field(description="Objective ID, e.g. 'obj_1'")
    goal: str = Field(description="Goal to achieve, e.g. 'verify whether FileUtils has a path traversal flaw'")

    # Expected output
    expected_output: str = Field(description="Expected output of this objective")

    status: Literal["pending", "investigating", "resolved", "discarded"] = "pending"

    # Real-time execution narrative for the current objective; meaningful only when status == "investigating"
    execution_narrative: str = Field(
        default="", 
        description="Real-time exploration thread, trial-and-error process and micro focus for the current objective (<= 300 characters)"
    )

    resolution_summary: Optional[str] = Field(None, description="Conclusion once resolved, e.g. 'flaw confirmed; sink spec generated'")

# (2) Overall analysis plan
class AnalysisPlan(BaseModel):
    """Dynamic analysis plan built on an objective stack."""
    project_profile: str = Field(description="Project profile")
    core_hypotheses: List[str] = Field(description="2-3 core macro hypotheses guiding exploration")
    
    # Objective stack supporting dynamic push/pop
    objectives: List[InvestigationObjective] = Field(description="Objectives to verify")
    current_objective_id: str = Field(description="ID of the objective under investigation")
    
    is_completed: bool = Field(default=False, description="Whether all high-priority objectives are resolved")

# ==========================================
# II. Initial plan data structures
# ==========================================

# Output shape for new objectives (no id; ids are generated deterministically)
class NewObjectiveOutput(BaseModel):
    goal: str = Field(description="Goal description, e.g. 'trace upstream controllers that call FileUtils.readFile'")
    expected_output: str = Field(description="Expected output once this objective completes")

# Minimal contract for initial LLM planning (no IDs or statuses)
class InitialPlanOutput(BaseModel):
    project_profile: str = Field(description="Project profile; decide whether this is a web application or a library")
    core_hypotheses: List[str] = Field(description="2-3 core macro hypotheses")
    initial_goals: List[NewObjectiveOutput] = Field(description="Initial investigation objectives, e.g. ['scan project structure...', 'locate core APIs...']")


# ==========================================
# III. Data structures for the Plan Update node
# ==========================================

class DiscardedObjective(BaseModel):
    """A pending objective to discard."""
    obj_id: str = Field(
        description="ID of the objective to discard (must currently be pending)"
    )
    reason: str = Field(
        description="Why it is discarded. Stored in the objective's resolution_summary field."
    )

class AddedObjectives(BaseModel):
    """A group of objectives to add, with an insertion position."""
    insert_after_obj_id: Optional[str] = Field(
        default=None,
        description=(
            "Insert new objectives after the objective with this obj_id. "
            "If null, append to the end of the objectives list."
        )
    )
    new_objectives: List[NewObjectiveOutput] = Field(
        description="New objectives; each must contain goal and expected_output."
    )

class PlanUpdateResult(BaseModel):
    """Structured output of the Plan Update Agent."""

    # --- Global knowledge updates ---
    project_profile_update: Optional[str] = Field(
        default=None,
        description=(
            "Updated project profile. Fill only when this execution revealed new "
            "project characteristics (e.g. the project is a hybrid architecture, "
            "not a pure SDK). Set to null if no update is needed."
        )
    )
    core_hypotheses_update: Optional[List[str]] = Field(
        default=None,
        description=(
            "Updated core macro hypotheses (2-3). Fill only when this execution "
            "refuted, revised, or produced new hypotheses. Set to null if no "
            "update is needed."
        )
    )

    # --- Global conclusion for the current objective ---
    resolution_summary: str = Field(
        description=(
            "Concise global summary of this objective's result (<= 200 characters). "
            "Must include: 1) the core finding or conclusion; 2) how it guides or "
            "constrains later pending objectives. Stored in the current objective's "
            "resolution_summary and used as context for later objectives."
        )
    )

    # --- Plan adjustments ---
    discarded_objectives: List[DiscardedObjective] = Field(
        default_factory=list,
        description=(
            "Pending objectives to discard. Include one only when the current "
            "result fully covers it, refutes it, or removes its investigation value. "
            "Use [] if none."
        )
    )
    added_objectives: Optional[AddedObjectives] = Field(
        default=None,
        description=(
            "Objectives to add. Strict constraint: fill only when this execution "
            "reveals a high-value investigation direction that is entirely new and "
            "not covered by existing pending objectives. If the pending objectives "
            "already cover the core hypotheses, set to null. Never add low-value "
            "objectives just to do more."
        )
    )