"""
Cross-explorer fusion dedup.

Merges specifications produced independently by K exploration perspectives and
deduplicates them extremely conservatively:
- delete only clear duplicates (same role + equivalent or subset matching intent);
- keep everything by default; redundancy is preferable to wrongful deletion;
- reuse the result-deduplication approach (LLM verdict + hallucinated-ID validation +
  keep-all fallback), but treat all perspectives as equals rather than "history vs new".

Called by the orchestration layer after collecting the specifications of all K explorers.

Output layers:
  L0  fusion_discarded_specs.json   full objects of discarded specifications (role / origin_direction)
  L1  fusion_groups.json            group pairs {discarded_spec_id_list, kept_spec_id, spec_desc}

Behavior invariant:
  Round 1 determines the verdict and freezes the surviving set as soon as it finishes.
  Round 2 is a read-only descriptive annotation: it does not change round 1's prompts or
  the kept list, and any error or validation failure only affects the contents of
  fusion_groups.json, never the specification list returned by this function.
  Setting FUSION_GROUP_MAPPING=0 disables round 2 entirely (no extra artifacts).

Why the mapping is a separate round: adding a grouping field to the verdict call
systematically changes the verdict itself (more discards), so the annotation is split
into a second, purely descriptive call.
"""
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langchain_core.language_models import BaseChatModel

from logger import StdoutLogger, log_json, log_message
from global_data_model.analysis_result import (
    SpecificationUnion,
    FusionDedupResult,
    FusionGroupsResult,
)
from analysis_agent.prompts.global_prompt import GLOBAL_SYSTEM_PROMPT
from analysis_agent.prompts.result_extract_prompt import (
    FUSION_DEDUP_SYSTEM_PROMPT,
    FUSION_DEDUP_USER_PROMPT_TEMPLATE,
)
from analysis_agent.prompts.fusion_mapping_prompt import FUSION_MAPPING_USER_PROMPT_TEMPLATE
from analysis_agent.utils.text_process import extract_spec_summary
from analysis_agent.utils.result_check import get_parse_error_message
from analysis_agent.utils import fallback

# Stdout Log Phase
STDOUT_LOG_PHASE = "Vul_Detect_Agent"

# Maximum retries for the round-1 verdict
MAX_RETRIES = 5

# ---- Round 2 (mapping/provenance) ----
# Note: logger.log_json / log_message append ".json" themselves, so the names below omit it.
FUSION_GROUPS_NAME = "fusion_groups"
FUSION_DISCARDED_NAME = "fusion_discarded_specs"
FUSION_MAPPING_PROMPT_NAME = "fusion_mapping_prompt"
FUSION_GROUPS_FILENAME = f"{FUSION_GROUPS_NAME}.json"
MAX_MAPPING_RETRIES = 3
DIGEST_TEXT_LIMIT = 200          # truncation length for description / matching_intent in the digest


def fusion_mapping_enabled() -> bool:
    """Runtime switch. FUSION_GROUP_MAPPING=0 disables round 2 and all L0/L1 artifacts."""
    return os.environ.get("FUSION_GROUP_MAPPING", "1").strip().lower() not in ("0", "false", "no", "off")


# ==========================================
# Round 1: prompt rendering (separate entry point for replay tests)
# ==========================================
def build_fusion_summaries(specs: List[SpecificationUnion]) -> List[Dict[str, Any]]:
    """Build compact summaries carrying origin_direction."""
    summaries = []
    for s in specs:
        s_summary = extract_spec_summary(s)
        s_summary["origin_direction"] = s.origin_direction
        summaries.append(s_summary)
    return summaries


def _render_fusion_prompts(summaries: List[Dict[str, Any]]) -> Tuple[str, str]:
    """Render the round-1 prompts (also used by replay tests)."""
    system_prompt = FUSION_DEDUP_SYSTEM_PROMPT.format(global_system_prompt=GLOBAL_SYSTEM_PROMPT)
    user_prompt = FUSION_DEDUP_USER_PROMPT_TEMPLATE.format(
        all_specs_json=json.dumps(summaries, indent=2, ensure_ascii=False)
    )
    return system_prompt, user_prompt


# ==========================================
# Round 2: mapping / provenance (L1)
# ==========================================
def _digest(s_summary: Dict[str, Any]) -> Dict[str, Any]:
    """Compress a specification summary into a round-2 annotation entry."""
    out: Dict[str, Any] = {"spec_id": s_summary.get("spec_id"), "role": s_summary.get("role")}
    for key in ("description", "matching_intent"):
        value = s_summary.get(key)
        if isinstance(value, str) and value:
            out[key] = value[:DIGEST_TEXT_LIMIT] + "…" if len(value) > DIGEST_TEXT_LIMIT else value
    if s_summary.get("mapping_type"):
        out["mapping_type"] = s_summary["mapping_type"]
    return out


def _check_mapping(
    parsed: FusionGroupsResult,
    discard_ids: set,
    kept_ids: set,
    role_of: Dict[str, str],
) -> Tuple[Optional[List[Dict[str, Any]]], Optional[List[str]], Optional[str]]:
    """
    Validate the round-2 output. Returns (groups, unmapped, error):
    a non-None error means the output is invalid and should be retried; both other values are then None.
    """
    groups: List[Dict[str, Any]] = []
    seen: set = set()
    for g in parsed.groups:
        dlist = list(g.discarded_spec_id_list or [])
        kept = (g.kept_spec_id or "").strip()
        if not dlist:
            return None, None, "a group has an empty discarded_spec_id_list (each group needs at least one discarded specification)"
        if not kept:
            return None, None, "a group has an empty kept_spec_id"
        if kept in discard_ids:
            return None, None, (
                f"kept_spec_id `{kept}` is itself in the round-1 discard set; kept_spec_id must be a **retained** specification"
            )
        if kept not in kept_ids:
            return None, None, f"kept_spec_id `{kept}` is not a real spec_id from the input (hallucinated ID)"
        for sid in dlist:
            if sid not in discard_ids:
                return None, None, (
                    f"`{sid}` in discarded_spec_id_list is not in this round's discard set "
                    f"(do not add or revoke any discard decision)"
                )
            if sid in seen:
                return None, None, f"`{sid}` appears in multiple groups (each item belongs to at most one)"
            seen.add(sid)
        kept_role = role_of.get(kept)
        for sid in dlist:
            if role_of.get(sid) != kept_role:
                return None, None, (
                    f"role mismatch inside a group: `{sid}`({role_of.get(sid)}) vs `{kept}`({kept_role}); "
                    f"different roles are never paired"
                )
        groups.append({
            "discarded_spec_id_list": dlist,
            "kept_spec_id": kept,
            "spec_desc": g.spec_desc or "",
        })

    unmapped = list(parsed.unmapped or [])
    unknown = sorted({x for x in unmapped if x not in discard_ids})
    if unknown:
        return None, None, f"unmapped contains IDs outside the discard set: {unknown}"
    both = sorted({x for x in unmapped if x in seen})
    if both:
        return None, None, f"`{both}` appears in both groups and unmapped (each item belongs to exactly one place)"
    return groups, unmapped, None


def _map_discarded_to_kept(
    llm: BaseChatModel,
    session_prefix: List[BaseMessage],
    summaries_by_id: Dict[str, Dict[str, Any]],
    specs: List[SpecificationUnion],
    discard_ids: set,
    log_dir: Optional[str],
) -> Dict[str, Any]:
    """
    Round 2: annotate the **frozen** discard set with the retained specification each item approximates.

    Read-only: the return value is only written to fusion_groups.json and never changes the
    caller's kept list. session_prefix = [System, Human(round-1 user message), Assistant(round-1 answer)],
    sharing round 1's session prefix (reuses the prefix cache and keeps round 1 attributable).
    """
    valid_ids = {s.spec_id for s in specs}
    kept_ids = valid_ids - discard_ids
    role_of = {s.spec_id: s.role for s in specs}

    digest = [_digest(summaries_by_id[sid]) for sid in sorted(discard_ids) if sid in summaries_by_id]
    user_prompt = FUSION_MAPPING_USER_PROMPT_TEMPLATE.format(
        discarded_digest_json=json.dumps(digest, indent=2, ensure_ascii=False)
    )
    if log_dir:
        log_json(log_dir, FUSION_MAPPING_PROMPT_NAME, {
            "discarded_spec_ids": sorted(discard_ids),
            "kept_spec_ids": sorted(kept_ids),
            "user_prompt": user_prompt,
        })

    mapping_llm = llm.with_structured_output(FusionGroupsResult, method="json_mode", include_raw=True)

    result: Dict[str, Any] = {
        "version": 1,
        "status": "failed",
        "groups": [],
        "unmapped": sorted(discard_ids),
        "kept_spec_ids": sorted(kept_ids),
        "discarded_count": len(discard_ids),
        "retries": 0,
    }

    messages_list: List[BaseMessage] = []
    for i in range(MAX_MAPPING_RETRIES):
        msgs = [*session_prefix, HumanMessage(content=user_prompt), *messages_list]
        try:
            whole_response = mapping_llm.invoke(msgs)
        except Exception as e:
            StdoutLogger.warning(
                f"    Fusion mapping LLM call failed (attempt {i + 1}): {type(e).__name__}: {e}",
                STDOUT_LOG_PHASE,
            )
            result["retries"] = i + 1
            result["error"] = f"{type(e).__name__}: {e}"
            continue

        raw_msg = whole_response["raw"]
        parsed = whole_response["parsed"]
        if log_dir:
            log_message(log_dir, f"mapping_tries_{i + 1}_response.json", raw_msg)
        messages_list = [raw_msg]
        result["retries"] = i + 1

        if parsed is None:
            messages_list.append(get_parse_error_message(whole_response.get("parsing_error")))
            continue

        groups, unmapped, error = _check_mapping(parsed, discard_ids, kept_ids, role_of)
        if error:
            result["error"] = error
            messages_list.append(HumanMessage(content=(
                f"Validation failed: {error}.\n"
                f"This round's discard set is: {sorted(discard_ids)};\n"
                f"the available **retained** spec_ids are: {sorted(kept_ids)}.\n"
                f"Annotate only; do not change any discard decision; re-output the complete JSON.\n"
            )))
            continue

        covered = {sid for g in groups for sid in g["discarded_spec_id_list"]} | set(unmapped)
        missing = sorted(discard_ids - covered)
        if missing:
            # Incomplete coverage: do not retry; record missing items as unmapped (never invent a pair)
            unmapped = unmapped + missing
            status = "partial"
        elif not groups:
            status = "no_pairs"
        else:
            status = "ok"
        result.update(status=status, groups=groups, unmapped=sorted(set(unmapped)))
        break

    # Hard invariant: groups union unmapped must equal the frozen discard set exactly;
    # otherwise discard the whole mapping rather than keeping a partial one
    got = {sid for g in result["groups"] for sid in g["discarded_spec_id_list"]} | set(result["unmapped"])
    if got != discard_ids:
        result.update(
            status="failed",
            groups=[],
            unmapped=sorted(discard_ids),
            error=f"coverage_invariant_violated: got={sorted(got)} want={sorted(discard_ids)}",
        )
    return result


def _write_discarded_specs(
    log_dir: str,
    specs: List[SpecificationUnion],
    discard_set: set,
) -> None:
    """L0: persist the full objects of discarded specifications.

    The final state only stores specifications surviving fusion, so discarded items would
    otherwise appear in no artifact (they could only be reconstructed by differencing
    direction_*/raw_specifications.json against the verdict responses). L0 makes them a
    first-class artifact; substituting a summary also needs the original mapping_type.
    Source membership is not duplicated here: it is joined from the spec_id prefix /
    origin_direction and directions_manifest.json.
    """
    items = []
    for s in specs:
        if s.spec_id in discard_set:
            items.append({
                "spec_id": s.spec_id,
                "role": s.role,
                "origin_direction": s.origin_direction,
                "spec": s.model_dump(mode="json"),
            })
    log_json(log_dir, FUSION_DISCARDED_NAME, {
        "version": 1,
        "count": len(discard_set),
        "items": items,
    })


def load_fusion_groups(log_dir: str) -> Optional[Dict[str, Any]]:
    """Load the L1 artifact. Returns None when the file is missing (old archive / switch off)."""
    path = os.path.join(log_dir, FUSION_GROUPS_FILENAME)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


# ==========================================
# Main entry point
# ==========================================
def fusion_dedup_specs(
    specs: List[SpecificationUnion],
    llm: BaseChatModel,
    log_dir: Optional[str] = None,
) -> List[SpecificationUnion]:
    """
    Conservatively deduplicate the merged cross-perspective specification list; returns the
    deduplicated list in the original order.

    Args:
        specs: global specification list tagged with origin_direction.
        llm: an instantiated LLM (BaseChatModel).
        log_dir: log directory; logging is skipped when None.

    The round-2 mapping/provenance result is only persisted and never affects the return value.
    """
    if not specs or len(specs) <= 1:
        return list(specs)

    # Build compact summaries carrying origin_direction
    summaries = build_fusion_summaries(specs)

    system_prompt, user_prompt = _render_fusion_prompts(summaries)

    dedup_llm = llm.with_structured_output(FusionDedupResult, method="json_mode", include_raw=True)

    if log_dir:
        log_json(log_dir, "fusion_dedup_prompt", {"system_prompt": system_prompt, "user_prompt": user_prompt})

    StdoutLogger.info(f"Cross-perspective fusion dedup: {len(specs)} specs", STDOUT_LOG_PHASE)

    valid_ids = {s.spec_id for s in specs}
    messages_list = []
    parsed_output: Optional[FusionDedupResult] = None
    if_response_success = False
    first_round_raw_msg: Optional[BaseMessage] = None   # reused as the assistant turn in round 2
    for i in range(MAX_RETRIES):
        StdoutLogger.info(f"    Generation Tries: {i + 1}", STDOUT_LOG_PHASE)
        msgs = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
            *messages_list,
        ]
        # Do not let exceptions from the LLM call itself (timeout, content filter, length limit, etc.)
        # escape: fusion_dedup_specs runs after all directions finish, so an exception would discard
        # every collected specification. Treat it as a failed round; the keep-all fallback applies
        # once retries are exhausted.
        try:
            whole_response = dedup_llm.invoke(msgs)
        except Exception as e:
            StdoutLogger.warning(
                f"    Fusion dedup LLM call failed (attempt {i + 1}): {type(e).__name__}: {e}",
                STDOUT_LOG_PHASE,
            )
            continue
        raw_msg = whole_response["raw"]
        parsed_output = whole_response["parsed"]
        parsing_error = whole_response.get("parsing_error")

        if log_dir:
            log_message(log_dir, f"tries_{i + 1}_response.json", raw_msg)

        messages_list = [raw_msg]

        if parsed_output is None:
            messages_list.append(get_parse_error_message(parsing_error))
            continue

        # Anti-hallucination: retry when the discard list contains an ID absent from the input
        invalid_ids = [sid for sid in parsed_output.discarded_spec_ids if sid not in valid_ids]
        if invalid_ids:
            messages_list.append(HumanMessage(
                f"Validation failed: `discarded_spec_ids` contains IDs absent from the input: {invalid_ids}.\n"
                f"The legal specification IDs are: {sorted(list(valid_ids))}.\n"
                f"Fix it and discard only IDs that really exist.\n"
            ))
            continue

        if_response_success = True
        first_round_raw_msg = raw_msg
        break

    # Fallback: keep all specifications when retries fail (details in utils/fallback.py)
    if not if_response_success or parsed_output is None:
        return fallback.fusion_keep_all(
            specs,
            log_dir=log_dir,
            detail=f"Fusion dedup failed validation {MAX_RETRIES} times; keeping all specifications conservatively",
        )

    discard_set = set(parsed_output.discarded_spec_ids)
    # The surviving set is frozen here. Round 2 below is read-only; any failure leaves kept unchanged.
    kept = [s for s in specs if s.spec_id not in discard_set]
    StdoutLogger.info(
        f"    Fusion dedup: {len(specs)} -> {len(kept)} (discarded {len(discard_set)} clear duplicates)",
        STDOUT_LOG_PHASE,
    )

    if log_dir and fusion_mapping_enabled():
        try:
            _write_discarded_specs(log_dir, specs, discard_set)
        except Exception as e:
            StdoutLogger.warning(
                f"    Failed to persist the discard set (does not affect the dedup result): {type(e).__name__}: {e}",
                STDOUT_LOG_PHASE,
            )
        if discard_set:
            try:
                summaries_by_id = {s_summary["spec_id"]: s_summary for s_summary in summaries}
                assert first_round_raw_msg is not None
                session_prefix = [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=user_prompt),
                    first_round_raw_msg,
                ]
                mapping = _map_discarded_to_kept(
                    llm, session_prefix, summaries_by_id, specs, discard_set, log_dir,
                )
            except Exception as e:
                # Round-2 failure only affects fusion_groups.json, never kept
                StdoutLogger.warning(
                    f"    Fusion mapping failed entirely (does not affect the dedup result): {type(e).__name__}: {e}",
                    STDOUT_LOG_PHASE,
                )
                mapping = {
                    "version": 1, "status": "failed", "groups": [],
                    "unmapped": sorted(discard_set), "kept_spec_ids": sorted(valid_ids - discard_set),
                    "discarded_count": len(discard_set), "retries": 0,
                    "error": f"{type(e).__name__}: {e}",
                }
        else:
            mapping = {
                "version": 1, "status": "not_attempted", "groups": [],
                "unmapped": [], "kept_spec_ids": sorted(valid_ids), "discarded_count": 0, "retries": 0,
            }
        try:
            log_json(log_dir, FUSION_GROUPS_NAME, mapping)
        except Exception as e:
            StdoutLogger.warning(
                f"    Failed to persist the fusion mapping (does not affect the dedup result): {type(e).__name__}: {e}",
                STDOUT_LOG_PHASE,
            )
        StdoutLogger.info(
            f"    Fusion mapping: status={mapping['status']}, "
            f"groups={len(mapping['groups'])}, unmapped={len(mapping['unmapped'])}",
            STDOUT_LOG_PHASE,
        )

    return kept
