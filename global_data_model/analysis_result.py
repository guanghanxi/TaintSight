from pydantic import BaseModel, Field
from typing import Optional, List, Literal, Union, Annotated


# ================= 1. Base components =================

class GroundTruthExample(BaseModel):
    """
    A target example used for few-shot prompts and validation.
    """
    is_from_project: bool = Field(
        description=(
            "[Origin] Whether the example comes from the target project's real source "
            "(origin only; validation role is controlled by purpose). "
            "If True, file_path is required for physical authenticity checks; "
            "if False (synthetic code), purpose must be illustration."
        )
    )
    file_path: Optional[str] = Field(
        None,
        description="Relative path of the example in the project (required when is_from_project=True)."
    )
    # Provenance field, used only for Analyzer-stage validation
    source_code_result_id: Optional[str] = Field(
        None,
        description=(
            "[Origin anchor] The `id` of the upstream evidence entry (Code Results) "
            "this example was taken from (e.g. 'prev_cr_001'). Required when "
            "is_from_project=True; use null for synthetic examples. The example is "
            "checked for consistency against that evidence entry rather than the "
            "source file, because examples are intentionally focused subsets."
        )
    )
    # Validation role (orthogonal to is_from_project)
    purpose: Literal["validation", "illustration"] = Field(
        "validation",   # default keeps older specs / upstream_result_path compatible
        description=(
            "[Validation role] Enum, limited to ['validation', 'illustration']. "
            "validation = real ground truth: the example's semantic position "
            "(declaration/definition side vs call/access side) matches the side the "
            "specification matches, and its file_path participates in downstream "
            "ground-truth hit checking. "
            "illustration = supporting material: helps explain the target semantics "
            "(e.g. a method declaration when the specification matches a call site, "
            "third-party source, synthetic example) and is not checked against ground truth. "
            "Rule: when the specification matches the declaration side "
            "(parameter/return_value/field), mark declaration-side project code as "
            "validation; when it matches the call side (argument/receiver/summary/"
            "flow_step), mark method declarations/definitions as illustration."
        )
    )
    explanation: str = Field(
        description="Natural-language explanation: which variable or call in this code corresponds to the specification?"
    )
    code_snippet: List[str] = Field(
        description=(
            "Key code lines or blocks in source order. Extract only the most "
            "recognizable core statements (method signatures, key assignments, "
            "dangerous operations); ignore large unrelated sections, logging and "
            "boilerplate."
        )
    )


# ================= 2. Node matching patterns (flat design) =================

class ParameterPattern(BaseModel):
    """Matches a formal parameter on the declaration side."""
    pattern_type: Literal["parameter"] = "parameter"
    matching_description: str = Field(
        description=(
            "Describe the target parameter's full match characteristics in natural "
            "language, covering class, method and parameter. Recommended form: "
            "'In [class description], the [parameter description] of [method description]'. "
            "Example: 'In com.example.controller.FileController (annotated with "
            "@RestController), the first parameter (type String, annotated with "
            "@PathVariable) of the @GetMapping-annotated method getFile'."
        )
    )


class ArgumentPattern(BaseModel):
    """Matches an actual argument on the call side."""
    pattern_type: Literal["argument"] = "argument"
    matching_description: str = Field(
        description=(
            "Describe the target argument's full match characteristics in natural "
            "language, covering class, method and argument. Recommended form: "
            "'In [class description], the [argument description] of [method description]'. "
            "Example: 'the first argument of every call to a method named evaluate, "
            "regardless of class'."
        )
    )


class FieldPattern(BaseModel):
    """Matches a class field."""
    pattern_type: Literal["field"] = "field"
    matching_description: str = Field(
        description=(
            "Describe the target field's full match characteristics in natural "
            "language, covering class and field. Recommended form: "
            "'In [class description], [field description]'. "
            "Example: 'the String field named userInput in "
            "com.example.model.UserContext'."
        )
    )


class ReturnValuePattern(BaseModel):
    """Matches a method return value."""
    pattern_type: Literal["return_value"] = "return_value"
    matching_description: str = Field(
        description=(
            "Describe the target return value's full match characteristics in "
            "natural language, covering class and method. Recommended form: "
            "'In [class description], the return value of [method description]'. "
            "Example: 'the return value of the public method encode in "
            "com.example.util.MarkupEncoder'."
        )
    )


class ReceiverPattern(BaseModel):
    """Matches the receiver (this/object state) on the call side."""
    pattern_type: Literal["receiver"] = "receiver"
    matching_description: str = Field(
        description=(
            "Describe the target receiver's full match characteristics in natural "
            "language, covering class and method. Recommended form: "
            "'In [class description], the receiver object of [method description]'. "
            "Example: 'the receiver object of calls to append in "
            "com.example.util.StringBuilder'."
        )
    )


class CustomLogicPattern(BaseModel):
    """
    Fallback pattern for logic that cannot be structured, or for reusing a
    built-in CodeQL rule directly.
    """
    pattern_type: Literal["custom_logic"] = "custom_logic"
    matching_intent: str = Field(description="Plain natural-language description of the matching logic.")
    codeql_generation_hint: str = Field(
        description="AST/DFG traversal hint for the CodeQL Agent."
    )
    builtin_codeql_rule: Optional[str] = Field(
        None,
        description=(
            "[Shortcut] To reuse a built-in CodeQL rule (e.g. 'path-injection', "
            "'sql-injection'), put its name here. The CodeQL Agent then imports the "
            "rule directly and ignores generation_hint."
        )
    )


NodePatternUnion = Annotated[
    Union[
        ParameterPattern, ArgumentPattern, FieldPattern,
        ReturnValuePattern, ReceiverPattern, CustomLogicPattern
    ],
    Field(discriminator="pattern_type")
]


# ================= 3. Top-level specifications by role =================

class BaseSpecification(BaseModel):
    spec_id: Optional[str] = Field(
        default=None,
        description="System-generated unique identifier; the LLM does not fill this in."
    )
    description: str = Field(description="Business/security meaning of the specification.")
    security_reason: str = Field(description="Security justification.")
    ground_truth_examples: List[GroundTruthExample] = Field(
        default_factory=list,
        min_length=1,
        max_length=5,
        description="Code examples supporting the specification. Provide 1-5 representative real or synthetic examples."
    )
    # Provenance: which exploration direction produced this specification
    origin_direction: Optional[str] = Field(
        default=None,
        description="Which exploration direction produced the specification (e.g. 'D01:validation and sanitization coverage'); tagged by the orchestrator."
    )


class SourceSpecification(BaseSpecification):
    role: Literal["source"] = "source"
    node_pattern: NodePatternUnion


class SinkSpecification(BaseSpecification):
    role: Literal["sink"] = "sink"
    node_pattern: NodePatternUnion


class SummarySpecification(BaseSpecification):
    role: Literal["summary"] = "summary"
    matching_description: str = Field(
        description=(
            "Describe the target method's full match characteristics in natural "
            "language, covering class and method. Recommended form: "
            "'[method description] in [class description]'. "
            "Example: 'the method named process in classes that inherit "
            "(directly or indirectly) from com.example.base.AbstractProcessor'."
        )
    )
    mapping_type: Literal[
        "arg_to_return",    # Argument[i] -> Return
        "this_to_return",   # Argument[this] -> Return
        "arg_to_this",      # Argument[i] -> Argument[this] (Field)
        "this_to_arg"       # Argument[this] -> Argument[i]
    ] = Field(description="Core taint mapping through the method.")
    source_arg_index: Optional[int] = Field(
        None,
        description="Required when mapping_type is arg_to_return or arg_to_this; index (0-based) of the incoming tainted argument."
    )
    target_arg_index: Optional[int] = Field(
        None,
        description="Required when mapping_type is this_to_arg; index (0-based) of the outgoing tainted argument."
    )


class FlowStepSpecification(BaseSpecification):
    role: Literal["flow_step"] = "flow_step"
    pattern: CustomLogicPattern


# ================= 4. Polymorphic aggregation and wrappers =================

SpecificationUnion = Annotated[
    Union[
        SourceSpecification,
        SinkSpecification,
        SummarySpecification,
        FlowStepSpecification
    ],
    Field(discriminator="role")
]


class TaintSpecificationList(BaseModel):
    """
    Wrapper class that works around LangChain's weak List support and serves
    as the entry point for polymorphic parsing.
    """
    specifications: List[SpecificationUnion] = Field(
        default_factory=list,
        description=(
            "All extracted taint-analysis specifications. Return an empty list [] "
            "if the current results contain no useful Source/Sink/Summary entries."
        )
    )

class ResultDeduplication(BaseModel):
    """
    Deduplication decision for new specifications extracted in each round.
    """
    reserve_new_results: bool = Field(
        description=(
            "[Global override] Keep every newly extracted specification?\n"
            "Set True when the new specifications have no clear overlap with the "
            "existing library, or differ in a subtle but security-relevant way.\n"
            "When True, all new specifications are appended and "
            "discarded_new_result_ids is ignored."
        )
    )
    discarded_new_result_ids: List[str] = Field(
        default_factory=list,
        description=(
            "New specification spec_ids to discard.\n"
            "Only applies when reserve_new_results is False.\n"
            "Criterion: the new specification's matching intent strongly overlaps "
            "an existing one, or its match scope is fully contained in (a subset "
            "of) an existing one, and it adds no new security value."
        )
    )


class FusionDedupResult(BaseModel):
    """
    Fusion deduplication decision: lists only the duplicate spec_ids to discard.
    An empty list means keep everything (deliberately conservative).

    This is the structured-output schema of the first decision round. Do not
    add fields: it is the with_structured_output contract, and changing the
    schema changes the LLM output shape and therefore behavior.
    """
    discarded_spec_ids: List[str] = Field(
        default_factory=list,
        description=(
            "Duplicate specification spec_ids to discard.\n"
            "Be extremely careful: list a spec only when two specifications have "
            "the same role and equivalent (or subset) AST matching intent.\n"
            "When in doubt, keep it (do not list it). Empty list when there are no duplicates."
        )
    )


# ================= 3.5 Fusion dedup / provenance round =================
# Separate second-round output schema: it only maps discarded specifications to
# the kept specification they resemble and takes no keep/discard decision.

class FusionGroup(BaseModel):
    """A group of near-duplicate specs: the discarded ones, the kept spec they resemble, and the shared intent."""
    discarded_spec_id_list: List[str] = Field(
        default_factory=list,
        description="spec_ids of the discarded duplicates in this group, excluding kept_spec_id"
    )
    kept_spec_id: str = Field(
        default="",
        description="spec_id of the kept specification the discarded ones closely resemble"
    )
    spec_desc: str = Field(
        default="",
        description="One sentence describing the matching intent shared by this group"
    )


class FusionGroupsResult(BaseModel):
    """Second-round output: grouped pairs plus discarded specs with no matching peer."""
    groups: List[FusionGroup] = Field(
        default_factory=list,
        description="Groups of duplicate specifications to discard; empty when there are none"
    )
    unmapped: List[str] = Field(
        default_factory=list,
        description=(
            "Discarded spec_ids for which no similar kept peer with the same role "
            "was found.\nPrefer listing them here over inventing a kept_spec_id."
        )
    )