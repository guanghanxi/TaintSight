from pydantic import BaseModel, Field
from typing import List


class DirectionDraft(BaseModel):
    """One exploration-direction draft produced by a single LLM divergence call.

    Fields are intentionally minimal (name/goal/strategy); no over-structured
    split into dimension / target_modules / expected_spec_roles, because such
    fields would themselves become a source of randomness.
    """

    name: str = Field(
        description="Short direction name (<= 20 characters) reflecting the target project's business characteristics rather than a generic CWE description."
    )
    goal: str = Field(
        description="The core question this direction explores/answers (one sentence)."
    )
    strategy: str = Field(
        description=(
            "Describe in 2-3 sentences how to explore: which architecture-level "
            "data-flow boundaries, module areas, and code shapes to focus on. "
            "Do not name specific classes or methods."
        )
    )


class DirectionDraftList(BaseModel):
    """Structured-output wrapper for the direction-draft LLM call."""

    directions: List[DirectionDraft] = Field(
        default_factory=list,
        description=(
            "At most 3 complementary directions specialized for the target project. "
            "The user message states how many slots are available this round; "
            "excess directions are truncated. If the project does not suggest any "
            "valuable specialized direction, provide only 1."
        ),
    )
