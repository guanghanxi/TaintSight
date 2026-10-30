"""Fallback strategies for every Analysis Agent node when retries are exhausted (centrally managed).

`raise RuntimeError(...)` calls scattered across the nodes are collected here so each node
keeps a single call site; this makes fallback behavior easy to review and fallback rates
easy to observe.

[Design principles]
1. The goal is to [preserve the direction and keep exploration running], not to "pretend
   success" -- a fallback product must honestly be marked as such.
2. Every fallback must be [observable]: a stdout warning plus `<log_dir>/fallback.json`
   on disk, so recall is never silently lost.
3. Fallback functions return products [isomorphic] to the normal path, so downstream
   nodes need not know a fallback occurred.
4. Fallbacks perform only [deterministic] actions and never issue extra LLM calls (no point
   spending more budget on a path that is already unreliable).

[Fallback sites]
    #1 initial_planning_node  -> initial_plan()              deterministic default plan
    #2 plan_update_node       -> plan_update()               keep the plan unchanged (no-op)
    #3 review_agent_node      -> review_verdict()            force FAILED and backfill cur_result
    #4 result_extract_agent_node -> extract_specs()          degraded accept / drop this objective's specs
    #5 result_deduplication_node -> dedup_keep_all()          keep everything
    #6 fusion_dedup_specs      -> fusion_keep_all()           keep everything
    #7 analyze_agent_node      -> analyzer_forced_done()      synthesize a signal_exploration_done call
    #8 updater_agent_node      -> updater_forced_finalize()   deterministic finalize
    #9 executor result missing -> executor_missing_result()   synthesize an ExecutionResult
"""
import json
import os
import uuid
from typing import List, Optional

from langchain_core.messages import AIMessage

# global module
from logger import StdoutLogger
from global_data_model.analysis_result import TaintSpecificationList, SpecificationUnion

# analysis agent local module
from analysis_agent.data_model.plan_data_model import AnalysisPlan, InvestigationObjective
from analysis_agent.data_model.review_node_data import ActiveObjectiveContext, ExecutionResult
from analysis_agent.executor_agent.executor_data_model import CodeResult

from analysis_agent.utils import result_check

# Stdout Log Phase
STDOUT_LOG_PHASE = "analysis_agent"

# Fallback record file name (written under each node's own log directory)
FALLBACK_LOG_FILENAME = "fallback.json"


class FallbackKind:
    """Fallback kind identifiers: written to the log for per-kind fallback rates and quality analysis"""
    INITIAL_PLAN_DEFAULT = "initial_plan_default"           # #1
    PLAN_UPDATE_NOOP = "plan_update_noop"                   # #2
    REVIEW_FORCED_FAILED = "review_forced_failed"           # #3
    EXTRACT_DEGRADED = "extract_degraded_by_file_check"     # #4-①
    EXTRACT_DROPPED = "extract_dropped_specs"               # #4-②
    DEDUP_KEEP_ALL = "dedup_keep_all"                       # #5
    FUSION_KEEP_ALL = "fusion_keep_all"                     # #6
    ANALYZER_FORCED_DONE = "analyzer_forced_done"           # #7
    UPDATER_FORCED_FINALIZE = "updater_forced_finalize"     # #8
    EXECUTOR_MISSING_RESULT = "executor_missing_result"     # #9


def record(
    log_dir: Optional[str],
    node: str,
    kind: str,
    detail: str,
    objective_id: Optional[str] = None,
    **extra,
) -> None:
    """Single exit point for fallbacks: stdout warning plus fallback.json on disk.

    A failure to persist the record must never affect the main flow (the fallback is already
    a degraded path; raising here would defeat the purpose).
    """
    tag = f"{objective_id}: " if objective_id else ""
    StdoutLogger.warning(f"{tag}[fallback] {node} -> {kind}: {detail}", STDOUT_LOG_PHASE)

    if not log_dir:
        return
    try:
        os.makedirs(log_dir, exist_ok=True)
        payload = {"node": node, "kind": kind, "detail": detail, "objective_id": objective_id}
        payload.update(extra)
        with open(os.path.join(log_dir, FALLBACK_LOG_FILENAME), "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception as log_err:
        StdoutLogger.warning(f"Failed to write fallback.json: {log_err}", STDOUT_LOG_PHASE)


# LLM-call degradation record file name (kept separate from fallback.json above: the latter
# records "fallback product after retries are exhausted", the former records the "call failed
# outright" event itself; both can occur in the same node directory, so sharing a name would
# make them overwrite each other).
LLM_DEGRADATION_LOG_FILENAME = "llm_degradation.json"


def invoke_llm_with_fallback(
    llm,
    messages,
    *,
    node: str,
    log_dir: Optional[str] = None,
    spec_id: str = "",
    max_attempts: Optional[int] = None,
    base_delay: Optional[float] = None,
):
    """Unified LLM invocation entry point for analysis_agent: bounded backoff retries;
    **returns None if every attempt fails and never raises**.

    Some providers report queue timeouts as HTTP 200 with an error body. Parsing such a body
    can raise `TypeError: 'NoneType' object is not iterable` / `ValueError`, and the nodes call
    `llm.invoke()` directly, so the exception escapes the node and aborts the whole project run.
    The "generation failed validation MAX_RETRIES times" path already has a fallback -- only the
    "call raised" path was unguarded.

    Reuses `codeql_agent.retry_policy.invoke_with_backoff` (same primitive, byte-identical on the
    happy path) and only writes degradation records to `llm_degradation.json` for aggregation.

    **`honor_non_retryable=True` is enabled only here**: on a provider queue timeout it gives up
    early because the analyzer side retries densely and `3 x MAX_RETRIES=5` would otherwise mean
    up to 45 minutes per direction. `codeql_agent/agent.py` uses the same primitive but does
    **not** pass this flag, preserving its earlier behavior (3x7=21 attempts per specification).

    **`max_attempts` / `base_delay` default to None**: meaning "decided by the provider profile".
    The default profile resolves to `3 / 2.0` (behavior identical to earlier releases), while
    relay profiles get a larger budget. Hard-coding 3/2.0 here would override and neutralize
    those profiles. Explicit arguments still take precedence.
    """
    # Lazy import: avoid import-time ordering coupling between analysis_agent and codeql_agent
    from codeql_agent.retry_policy import invoke_with_backoff

    kwargs = {}
    if max_attempts is not None:
        kwargs["max_attempts"] = max_attempts
    if base_delay is not None:
        kwargs["base_delay"] = base_delay

    return invoke_with_backoff(
        llm,
        messages,
        spec_id=spec_id,
        log_dir=log_dir,
        node=node,
        filename=LLM_DEGRADATION_LOG_FILENAME,
        honor_non_retryable=True,
        **kwargs,
    )


# ==========================================
# #1 initial_planning_node: initial planning retries exhausted
# ==========================================
def initial_plan(state: dict, log_dir: Optional[str] = None, detail: str = "") -> dict:
    """Produce a deterministic default plan so the exploration direction keeps moving.

    The default plan deliberately stays at "generic reconnaissance" level: it never invents
    concrete class or method names (which would pollute the downstream specification library)
    and only gives one directionally clear generic objective, leaving specificity to the
    Executor once it has tool results.
    """
    cwe_id = state.get("cwe_id", "target weakness")
    direction = state.get("exploration_direction", "") or "(no direction specified)"

    objective = InvestigationObjective(
        id="obj_0001",
        goal=(
            f"Perform generic reconnaissance on the target project: map the project structure and core modules, "
            f"locate taint entry points (places receiving external input) and dangerous operations (Sinks) related "
            f"to {cwe_id}, and use the semantics of the exploration direction \"{direction}\" to locate candidate chains."
        ),
        expected_output=(
            "Provide at least 1 candidate taint chain (Source location, Sink location, intermediate propagation steps), "
            "or a clear disproof; include key code slices and file paths."
        ),
        status="investigating",
        execution_narrative="",
        resolution_summary=None,
    )

    final_plan = AnalysisPlan(
        project_profile="Undetermined (initial planning failed validation; the system generated a default plan)",
        core_hypotheses=[f"The project contains a path where insufficiently filtered external input reaches a {cwe_id}-related dangerous operation."],
        objectives=[objective],
        current_objective_id=objective.id,
        is_completed=False,
    )

    active_objective = ActiveObjectiveContext(
        objective=objective,
        status="INITIATING",
        reason="",
        initial_result=None,
        cur_result=None,
        refinements=[],
    )

    record(
        log_dir, "initial_planning_node", FallbackKind.INITIAL_PLAN_DEFAULT,
        detail or "initial planning failed validation repeatedly; continuing with the system default plan",
        direction=direction, objectives=[objective.id],
    )

    return {
        "plan": final_plan,
        "taint_specifications": [],   # initialized analysis-result field
        "active_objective": active_objective,
        "status": "executing",
        "step_count": 0,
        "compressed_summary": "",
    }


# ==========================================
# #2 plan_update_node: plan update retries exhausted
# ==========================================
def plan_update(
    plan: AnalysisPlan,
    log_dir: Optional[str] = None,
    objective_id: Optional[str] = None,
    detail: str = "",
) -> AnalysisPlan:
    """Keep the plan unchanged (no-op): no objectives removed, added or hypotheses updated.

    Better no optimization than mutating the plan structure based on untrusted LLM output.
    Status advancement and resolution_summary backfill for the current objective are performed
    deterministically by plan_promotion_node.
    """
    record(
        log_dir, "plan_update_node", FallbackKind.PLAN_UPDATE_NOOP,
        detail or "plan update failed validation repeatedly; keeping the plan unchanged and continuing",
        objective_id=objective_id, objective_count=len(plan.objectives),
    )
    return plan


# ==========================================
# #3 review_agent_node: review retries exhausted
# ==========================================
def review_verdict(
    active_objective: ActiveObjectiveContext,
    is_refinement: bool,
    log_dir: Optional[str] = None,
    detail: str = "",
) -> ActiveObjectiveContext:
    """Force a conservative FAILED verdict and backfill cur_result (downstream extract / plan_update need it).

    cur_result backfill rules (aligned with the merge semantics of result_check.check_review_agent_result):
    - Refinement with a self-contained result -> use this round's result;
    - Refinement with an incremental result only -> keep the previously integrated cur_result
      (so earlier evidence is not lost);
    - First execution -> use initial_result (forced to self-contained);
    - Everything missing -> synthesize an empty conclusion; never pass None downstream.

    No refinement record is appended: the review produced no verdict, and appending one would
    only inflate refinement_count.
    """
    new_active_objective = active_objective.model_copy(deep=True)
    pending = active_objective.refinements[-1] if active_objective.refinements else None

    new_active_objective.status = "FAILED"
    new_active_objective.reason = (active_objective.reason or "") + (
        "\n[System fallback] The review node failed validation repeatedly; the system forced a FAILED "
        "verdict and kept the collected execution results."
    )

    if is_refinement and pending and pending.execution_result and pending.execution_result.is_self_contained:
        new_active_objective.cur_result = pending.execution_result.model_copy(deep=True)
    elif is_refinement and active_objective.cur_result is not None:
        new_active_objective.cur_result = active_objective.cur_result.model_copy(deep=True)
    elif active_objective.initial_result is not None:
        fallback_result = active_objective.initial_result.model_copy(deep=True)
        fallback_result.is_self_contained = True
        new_active_objective.cur_result = fallback_result
    else:
        new_active_objective.cur_result = ExecutionResult(
            execution_summary="Execution result missing; the system produced an empty conclusion.",
            execution_report="Neither the review nor the execution result was available; the system finalized the objective.",
            code_results=[],
            is_self_contained=True,
        )

    record(
        log_dir, "review_agent_node", FallbackKind.REVIEW_FORCED_FAILED,
        detail or "review failed validation repeatedly; forced FAILED and kept existing execution results",
        objective_id=active_objective.objective.id,
        is_refinement=is_refinement,
        code_result_count=len(new_active_objective.cur_result.code_results or []),
    )
    return new_active_objective


# ==========================================
# #4 result_extract_agent_node: specification extraction retries exhausted
# ==========================================
def extract_specs(
    parsed_output: Optional[TaintSpecificationList],
    project_root: str,
    code_results_pool: List[CodeResult],
    objective_id: Optional[str] = None,
    log_dir: Optional[str] = None,
) -> TaintSpecificationList:
    """Two-stage fallback:

    1. Degraded accept: re-judge the last round's output with the legacy rule (physical
       comparison against source files); accept it when it passes;
    2. Drop this objective's specifications: return an empty list if both stages fail, and
       let the flow continue (the direction is not interrupted).
    """
    valid_ids = [cr.id for cr in code_results_pool if cr.id]

    # Fallback 1: degrade to physical source comparison
    if parsed_output is not None:
        legacy_valid, _, legacy_specs = result_check.check_extract_result(
            parsed_output, project_root, None
        )
        if legacy_valid:
            record(
                log_dir, "result_extract_agent_node", FallbackKind.EXTRACT_DEGRADED,
                "provenance-anchored validation failed but physical source comparison passed; accepted in degraded mode",
                objective_id=objective_id,
                spec_count=len(legacy_specs.specifications),
                valid_code_result_ids=valid_ids,
            )
            return legacy_specs

    # Fallback 2: skip specification extraction for this objective
    dropped = TaintSpecificationList(specifications=[])
    record(
        log_dir, "result_extract_agent_node", FallbackKind.EXTRACT_DROPPED,
        "both provenance-anchored validation and physical source comparison failed; skipping specification extraction for this objective",
        objective_id=objective_id, spec_count=0, valid_code_result_ids=valid_ids,
    )
    return dropped


# ==========================================
# #5 result_deduplication_node: semantic dedup retries exhausted
# ==========================================
def dedup_keep_all(
    specs_to_dedup: List[SpecificationUnion],
    log_dir: Optional[str] = None,
    objective_id: Optional[str] = None,
    detail: str = "",
) -> List[SpecificationUnion]:
    """Keep everything: consistent with the dedup prompt's "prefer redundancy over wrongful deletion" stance."""
    record(
        log_dir, "result_deduplication_node", FallbackKind.DEDUP_KEEP_ALL,
        detail or "dedup failed validation repeatedly; keeping every specification for this objective",
        objective_id=objective_id, kept_count=len(specs_to_dedup),
    )
    return list(specs_to_dedup)


# ==========================================
# #6 fusion_dedup_specs: cross-direction fusion dedup retries exhausted
# ==========================================
def fusion_keep_all(
    specs: List[SpecificationUnion],
    log_dir: Optional[str] = None,
    detail: str = "",
) -> List[SpecificationUnion]:
    """Keep everything: specifications from different directions cover each other's blind spots,
    so wrongful deletion costs more than redundancy."""
    record(
        log_dir, "fusion_dedup_specs", FallbackKind.FUSION_KEEP_ALL,
        detail or "fusion dedup failed; conservatively keeping all specifications",
        kept_count=len(specs),
    )
    return list(specs)


# ==========================================
# #7 analyze_agent_node: explorer retries exhausted (no tool calls in a row)
# ==========================================
def analyzer_forced_done(
    objective_id: Optional[str] = None,
    log_dir: Optional[str] = None,
    attempts: int = 0,
    detail: str = "",
) -> AIMessage:
    """Synthesize a signal_exploration_done tool call to hand control back to the Updater for finalization.

    The synthesized AIMessage carries a valid tool_call that ToolNode executes normally to produce
    a ToolMessage; the Updater then receives a high-priority system hint to produce a final_result,
    turning the collected tool evidence into a report. The content honestly marks this as a system
    fallback so the interaction trace stays auditable.
    """
    reason = (
        f"System fallback: the explorer made no tool call for {attempts} consecutive attempts, so the "
        f"system issued the exploration-termination signal on its behalf. Generate the final report from "
        f"the tool evidence already collected."
    )
    record(
        log_dir, "analyze_agent_node", FallbackKind.ANALYZER_FORCED_DONE,
        detail or f"explorer made no tool call for {attempts} consecutive attempts; system issued signal_exploration_done",
        objective_id=objective_id, attempts=attempts,
    )
    return AIMessage(
        content="[System fallback] The explorer did not follow the tool-calling protocol; the system called `signal_exploration_done` on its behalf to end this exploration round.",
        tool_calls=[{
            "name": "signal_exploration_done",
            "args": {"reason": reason},
            "id": f"fallback_signal_{uuid.uuid4().hex[:8]}",
            "type": "tool_call",
        }],
    )


# ==========================================
# #8 updater_agent_node: updater retries exhausted
# ==========================================
def updater_forced_finalize(
    state: dict,
    log_dir: Optional[str] = None,
    detail: str = "",
) -> dict:
    """Finalize deterministically and return the Updater node's full return dict.

    The shape matches the step-limit fallback report: the execution narrative serves as the report
    body and the current memory pool serves as code_results, so state_transfer always receives a
    non-empty result and the objective is not wasted.

    is_self_contained is False: this fallback contains only the current round's memory pool (the
    Executor subgraph starts each round with an empty pool), not the full evidence set, so the
    downstream Refinement merge logic must not treat it as a complete replacement for history.
    """
    cur_objective = state["cur_objective"]
    cur_code_results: List[CodeResult] = state.get("cur_code_results", []) or []

    exec_res = ExecutionResult(
        execution_summary=(
            f"The task was finalized by the system because the Updater failed validation repeatedly; "
            f"{len(cur_code_results)} code slices were kept."
        ),
        execution_report=f"Current execution narrative:\n{cur_objective.execution_narrative or '(no narrative recorded)'}",
        code_results=cur_code_results,
        is_self_contained=False,
    )

    record(
        log_dir, "updater_agent_node", FallbackKind.UPDATER_FORCED_FINALIZE,
        detail or "the Updater failed validation repeatedly; the system finalized using the existing narrative and code pool",
        objective_id=cur_objective.id, code_result_count=len(cur_code_results),
    )

    return {
        "cur_code_results": cur_code_results,
        "cur_objective": cur_objective,
        "result": exec_res,
        "status": "finished",
    }


# ==========================================
# #9 executor subgraph finished without producing an ExecutionResult
# ==========================================
def executor_missing_result(
    cur_objective: Optional[InvestigationObjective],
    cur_code_results: Optional[List[CodeResult]],
    log_dir: Optional[str] = None,
    detail: str = "",
) -> ExecutionResult:
    """Synthesize a minimal result instead of raising a RuntimeError.

    A reachable path: analyze_agent_node returns `{"status": "finished"}` directly when
    `plan.is_completed or step_count >= max_steps`, leaving the subgraph finished with an empty
    result. Without this fallback state_transfer would raise and the whole exploration direction,
    along with the collected evidence, would be discarded.
    """
    code_results = cur_code_results or []
    narrative = getattr(cur_objective, "execution_narrative", "") or ""
    objective_id = getattr(cur_objective, "id", None)

    exec_res = ExecutionResult(
        execution_summary="The Executor subgraph produced no execution result (terminated early); the system synthesized one.",
        execution_report=f"Current execution narrative:\n{narrative or '(no narrative recorded)'}",
        code_results=code_results,
        is_self_contained=False,
    )

    record(
        log_dir, "state_transfer", FallbackKind.EXECUTOR_MISSING_RESULT,
        detail or "the Executor subgraph finished with an empty result; the system synthesized one from the existing narrative and code pool",
        objective_id=objective_id, code_result_count=len(code_results),
    )
    return exec_res
