import json
import os
import re
from pydantic import BaseModel, Field
from typing import List, Optional, Tuple
from langchain_core.messages import AIMessage, ToolMessage, SystemMessage, HumanMessage, BaseMessage

from logger import StdoutLogger

# Stdout Log Phase
STDOUT_LOG_PHASE = "analysis_agent"

# ==========================================
# Message-list helpers
# 
# 1. Safely split the messages list
# ==========================================
def get_safe_split_index(messages: List[BaseMessage], max_turns: int = 3, msg_count_th: int = 8) -> int:
    """
    Compute the index of a safe truncation point so that an AIMessage with tool_calls is
    never separated from its corresponding ToolMessages.

    Args:
        messages: Full message list
        max_turns: Maximum number of interaction turns to keep
                    (1 turn = 1 AIMessage with tool_calls + N matching ToolMessages)
        msg_count_th: Stop scanning once a complete turn has been crossed and the total
                      message count reaches this threshold

    Returns:
        int: Truncation index.
             Old messages (to compress/drop) are messages[:index]
             Kept messages are messages[index:]
             Returns 0 when no truncation is needed.
    """
    if not messages:
        return 0

    split_index = 0
    turns_count = 0

    # Scan from the end
    for i in range(len(messages) - 1, -1, -1):
        msg = messages[i]
        # An AIMessage with tool_calls marks the absolute start of a turn
        is_tool_call_ai = isinstance(msg, AIMessage) and getattr(msg, "tool_calls", [])
        
        if is_tool_call_ai:
            # Reaching a start marker means one full turn after it has just been crossed
            turns_count += 1
            
            # Stop when the turn count or the message-count threshold is reached
            if turns_count == max_turns or (len(messages) - i) >= msg_count_th:
                # Everything from this AIMessage onward is kept
                split_index = i
                break
        
    return split_index # no tool-call message at all: the list is malformed, so return 0


# ==========================================
# 2. Flatten the Message list into plain text (for the compression LLM)
# ==========================================
def format_messages_for_compression(messages: List[BaseMessage]) -> str:
    """
    Convert a list of LangChain Message objects into dense conversational text,
    optimized for models with reasoning and tool-calling capabilities.
    """
    lines = []
    for msg in messages:
        if isinstance(msg, HumanMessage):
            lines.append(f"[User]: {msg.content}")
            
        elif isinstance(msg, AIMessage):
            # 1. Extract the reasoning trace (reasoning_content)
            reasoning = msg.additional_kwargs.get("reasoning_content", "")
            if reasoning:
                # Reasoning traces can be very long; truncate to save tokens during compression
                reasoning_summary = reasoning[:2000] + "..." if len(reasoning) > 2000 else reasoning
                lines.append(f"[Assistant Thought]: {reasoning_summary}")
            
            # 2. Extract the plain-text reply (when present)
            if msg.content:
                lines.append(f"[Assistant]: {msg.content}")
                
            # 3. Extract tool-call decisions (tool_calls)
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                for tc in msg.tool_calls:
                    tool_name = tc.get("name", "unknown_tool")
                    args = tc.get("args", {})
                    # Arguments may contain large code blocks or long strings; truncate them
                    args_str = str(args)
                    if len(args_str) > 1000:
                        args_str = args_str[:1000] + "..."
                    lines.append(f"[Assistant Action]: Called `{tool_name}` with args {args_str}")
                    
        elif isinstance(msg, ToolMessage):
            # 4. Extract the tool name and its result
            tool_name = getattr(msg, "name", "unknown_tool")
            content = str(msg.content)
            if len(content) > 4000:
                content = content[:4000] + "...[Truncated]"
            lines.append(f"[Tool Result ({tool_name})]: {content}")
            
        # SystemMessage usually carries the global prompt or injected state; skip it in the narrative
            
    return "\n".join(lines)


# ==========================================
# 3. Tool-call pairing invariant (an AIMessage with tool_calls must be answered by its ToolMessages)
#
# Provider hard constraint: `An assistant message with 'tool_calls' must be followed by tool messages
# responding to each 'tool_call_id'`. Truncation points (the Updater window and the after_update
# cut in executor_nodes.py) count AIMessages only and do not enforce pairing, so they can produce
# orphans. This section provides three primitives: check / dump / repair. Attach the check at a
# truncation point first to locate problems before switching the cut to the repaired version.
# ==========================================
def check_tool_call_pairing(messages: List[BaseMessage]) -> List[dict]:
    """Check the tool_calls pairing invariant and return violations (empty list = compliant).

    The criterion matches `get_safe_split_index` in executor_nodes: an AIMessage with tool_calls
    is the absolute start of a turn, and every tool_call_id it declares must be answered by a
    ToolMessage after that AIMessage and before the next AIMessage with tool_calls.

    :return: [{"at_index": int, "orphan_ids": [...], "reason": str}, ...]
    """
    violations: List[dict] = []
    pending: List[str] = []
    declared: set = set()      # ids declared by the most recent AIMessage with tool_calls

    for idx, m in enumerate(messages):
        if isinstance(m, AIMessage) and getattr(m, "tool_calls", None):
            if pending:
                violations.append({
                    "at_index": idx,
                    "orphan_ids": list(pending),
                    "reason": "a previous AIMessage with tool_calls was not fully answered by ToolMessages",
                })
            declared = {tc.get("id") for tc in m.tool_calls}
            pending = list(declared)
        elif isinstance(m, ToolMessage):
            tcid = getattr(m, "tool_call_id", None)
            if tcid not in declared:
                # Orphan: the cut removed its AIMessage (an Updater window starting with a ToolMessage looks like this)
                violations.append({
                    "at_index": idx,
                    "orphan_ids": [tcid],
                    "reason": "this ToolMessage tool_call_id was never declared by any AIMessage",
                })
            elif tcid in pending:
                pending.remove(tcid)

    if pending:
        violations.append({
            "at_index": len(messages),
            "orphan_ids": list(pending),
            "reason": "unanswered tool_call_ids remain at the end of the message list",
        })

    return violations


def dump_pairing_violation(
    messages: List[BaseMessage],
    log_dir: Optional[str],
    tag: str = "",
) -> List[dict]:
    """Check pairing and dump PAIRING_VIOLATION.json (only when violations exist).

    Deliberately does **not** mutate messages: this function only collects evidence;
    `repair_tool_call_pairing` performs the repair.
    """
    violations = check_tool_call_pairing(messages)
    if not violations:
        return []

    StdoutLogger.warning(
        f"[pairing check] {tag} tool_calls pairing violated: {violations}", STDOUT_LOG_PHASE
    )
    if log_dir:
        try:
            os.makedirs(log_dir, exist_ok=True)
            with open(os.path.join(log_dir, "PAIRING_VIOLATION.json"), "w", encoding="utf-8") as f:
                json.dump({"tag": tag, "message_count": len(messages), "violations": violations},
                          f, ensure_ascii=False, indent=2)
        except Exception as e:  # noqa: BLE001 -- evidence collection must not break the main flow
            StdoutLogger.warning(f"Failed to write PAIRING_VIOLATION.json: {e}", STDOUT_LOG_PHASE)
    return violations


def repair_tool_call_pairing(messages: List[BaseMessage]) -> Tuple[List[BaseMessage], List[dict]]:
    """Drop unpaired parts instead of letting them fail the whole run.

    - For each AIMessage with tool_calls: keep only the tool_calls answered by following ToolMessages;
    - Drop orphan ToolMessages whose id was not declared by the preceding AIMessage with tool_calls.

    Only takes effect on the **violation path**; compliant input is returned unchanged
    (byte-identical on the happy path).
    """
    violations = check_tool_call_pairing(messages)
    if not violations:
        return list(messages), []

    actions: List[dict] = []
    out: List[BaseMessage] = []

    for idx, m in enumerate(messages):
        if isinstance(m, AIMessage) and getattr(m, "tool_calls", None):
            # Remove tool_calls not answered by a following ToolMessage
            answered = _answered_after(messages, idx)
            kept = [tc for tc in m.tool_calls if tc.get("id") in answered]
            if len(kept) != len(m.tool_calls):
                actions.append({
                    "action": "drop_unanswered_tool_calls",
                    "dropped": [tc.get("id") for tc in m.tool_calls if tc.get("id") not in answered],
                })
                m = m.model_copy(update={"tool_calls": kept})
            out.append(m)

        elif isinstance(m, ToolMessage):
            # Drop orphan ToolMessages not declared by the preceding AIMessage
            declared = _declared_before(messages, idx)
            tcid = getattr(m, "tool_call_id", None)
            if tcid not in declared:
                actions.append({"action": "drop_orphan_tool_message",
                                "tool_call_id": tcid, "name": getattr(m, "name", None)})
                continue
            out.append(m)

        else:
            out.append(m)

    return out, actions


def _answered_after(messages: List[BaseMessage], ai_index: int) -> set:
    """Collect all tool_call_ids after ai_index and before the next AIMessage with tool_calls."""
    answered = set()
    for m in messages[ai_index + 1:]:
        if isinstance(m, AIMessage) and getattr(m, "tool_calls", None):
            break
        if isinstance(m, ToolMessage):
            answered.add(getattr(m, "tool_call_id", None))
    return answered


def _declared_before(messages: List[BaseMessage], tool_index: int) -> set:
    """Collect the tool_call_ids declared by the closest preceding AIMessage (empty set if none)."""
    for j in range(tool_index - 1, -1, -1):
        if isinstance(messages[j], AIMessage):
            return {tc.get("id") for tc in getattr(messages[j], "tool_calls", None) or []}
    return set()


# ==========================================
# 4. Token budget guard (executor context-length overflow)
#
# Existing truncation counts messages only (AIMessages in executor_nodes.py and the
# UPDATER_INTERVAL check) and never measures tokens. Tool results can be enormous
# (search_class / get_method_definition return whole source files), so a **single ToolMessage**
# can overflow the context -- at which point "keep K turns" provides no protection.
# This guard trims **before** invoke based on estimated tokens, in two stages:
#   1. Single message over the cap => truncate that message's content in place; otherwise no
#      amount of history trimming suffices;
#   2. Cumulative over budget    => keep only the most recent complete turns from a
#      pairing-safe boundary.
# Every trigger writes budget_trim.json and emits a stdout warning (no implicit degradation).
# ==========================================
MODEL_TOKEN_LIMIT = int(os.environ.get("MODEL_TOKEN_LIMIT", "1048576"))          # default model input limit
MODEL_TOKEN_BUDGET_RATIO = float(os.environ.get("MODEL_TOKEN_BUDGET_RATIO", "0.85"))
MODEL_SINGLE_MSG_RATIO = float(os.environ.get("MODEL_SINGLE_MSG_RATIO", "0.5"))

# Conservative **worst-case** token cost per character (0.3 underestimated the real ratio
# by 1.21-1.31x on measured workloads).
# Calibration: 2,653,814 characters of tool output were billed as 1,040,440 input tokens,
# i.e. about 0.392 tokens per character in the worst observed case.
# WARNING: this constant is **shared** by estimate_tokens and _truncate_message and must stay
#   consistent -- otherwise the guard can compute an overflow yet fail to truncate: a smaller
#   cost would make char_cap larger than the message, returning the original object unchanged
#   (after == before) without even recording truncated_messages.
TOKENS_PER_CHAR_WORST = 0.42          # non-CJK: ~7% headroom over the measured 0.392
TOKENS_PER_CJK_CHAR_WORST = 1.0       # CJK: 1 token per character

_CJK_RE = re.compile(r"[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]")


def estimate_tokens(text: str) -> int:
    """Conservative token estimate: CJK ~1.0 token/char, everything else ~0.42 token/char
    (worst-case measured values; trimming early is preferable)."""
    if not text:
        return 0
    cjk = len(_CJK_RE.findall(text))
    return int(cjk * TOKENS_PER_CJK_CHAR_WORST
               + (len(text) - cjk) * TOKENS_PER_CHAR_WORST)


def estimate_message_tokens(message: BaseMessage) -> int:
    total = 4  # role / separator overhead
    content = message.content
    if isinstance(content, str):
        total += estimate_tokens(content)
    elif isinstance(content, list):
        total += sum(estimate_tokens(str(part)) for part in content)
    tool_calls = getattr(message, "tool_calls", None)
    if tool_calls:
        total += estimate_tokens(json.dumps(tool_calls, ensure_ascii=False))
    return total


def estimate_messages_tokens(messages: List[BaseMessage]) -> int:
    return sum(estimate_message_tokens(m) for m in messages)


def _truncate_message(message: BaseMessage, token_cap: int) -> BaseMessage:
    """Truncate one message's content to a token cap (keep 60% head + 40% tail, with a marker)."""
    if not isinstance(message.content, str):
        return message
    char_cap = max(int(token_cap / TOKENS_PER_CHAR_WORST), 200)   # derived char cap (worst-case cost per char)
    if len(message.content) <= char_cap:
        return message
    head = int(char_cap * 0.6)
    tail = char_cap - head
    marker = f"\n...[budget guard: content too long, truncated from {len(message.content)} characters]...\n"
    return message.model_copy(update={
        "content": message.content[:head] + marker + message.content[-tail:]
    })


def _pairing_safe_start(messages: List[BaseMessage], allowance: int) -> Tuple[Optional[int], bool]:
    """Scan backwards for a pairing-safe start whose cumulative tokens fit within allowance.

    :return: (start index or None, whether even the last message does not fit)
    """
    best: Optional[int] = None
    last_safe: Optional[int] = None
    acc = 0
    for i in range(len(messages) - 1, -1, -1):
        acc += estimate_message_tokens(messages[i])
        # The start must not be a ToolMessage -- that would orphan its tool_call_id
        if not isinstance(messages[i], ToolMessage):
            last_safe = i
            if acc <= allowance:
                best = i
        elif acc > allowance:
            break
    if best is None:
        return last_safe, last_safe is not None
    return best, False


def budget_guard(
    head: List[BaseMessage],
    middle: List[BaseMessage],
    tail: List[BaseMessage],
    *,
    log_dir: Optional[str] = None,
    tag: str = "",
    limit: Optional[int] = None,
    budget_ratio: Optional[float] = None,
    single_ratio: Optional[float] = None,
) -> List[BaseMessage]:
    """Token guard: trim by estimated token count and return `[*head, *middle', *tail]`.

    `head` / `tail` are structural parts (system prompt, global prompt, action guide, retry
    corrections) and are never trimmed; only `middle` (conversation history) is adjusted --
    the same semantics as the existing N/K truncation, with tokens as the criterion.

    Returns the original list byte-for-byte when under budget (no behavior change on the happy path).
    """
    limit = limit or MODEL_TOKEN_LIMIT
    budget = int(limit * (budget_ratio or MODEL_TOKEN_BUDGET_RATIO))
    single_cap = int(budget * (single_ratio or MODEL_SINGLE_MSG_RATIO))
    report: dict = {}
    original_total = (estimate_messages_tokens(head)
                      + estimate_messages_tokens(middle)
                      + estimate_messages_tokens(tail))

    # 1. Single message over cap: truncate in place (except SystemMessage, which is structural and
    #    handled by the cumulative stage)
    truncated = []
    trimmed_middle = []
    for m in middle:
        before = estimate_message_tokens(m)
        if before > single_cap and not isinstance(m, SystemMessage):
            nm = _truncate_message(m, single_cap)
            after = estimate_message_tokens(nm)
            if after < before:
                truncated.append({"kind": type(m).__name__, "name": getattr(m, "name", None),
                                  "tokens_before": before, "tokens_after": after})
                m = nm
        trimmed_middle.append(m)
    if truncated:
        report["truncated_messages"] = truncated

    # 2. Cumulative over budget: keep the most recent complete paired turns
    fixed = estimate_messages_tokens(head) + estimate_messages_tokens(tail)
    total = fixed + estimate_messages_tokens(trimmed_middle)
    if total > budget:
        start, oversize = _pairing_safe_start(trimmed_middle, max(budget - fixed, 0))
        if start:
            report["dropped_history_messages"] = start
            trimmed_middle = trimmed_middle[start:]
        if oversize:
            report["oversize"] = True

    if report:
        report.update({"tag": tag, "budget": budget, "limit": limit,
                       "estimated_before": original_total, "estimated_after":
                       fixed + estimate_messages_tokens(trimmed_middle)})
        StdoutLogger.warning(
            f"[budget guard] {tag} trimming triggered: {json.dumps(report, ensure_ascii=False)}",
            STDOUT_LOG_PHASE,
        )
        if log_dir:
            try:
                os.makedirs(log_dir, exist_ok=True)
                with open(os.path.join(log_dir, "budget_trim.json"), "w", encoding="utf-8") as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
            except Exception as e:  # noqa: BLE001
                StdoutLogger.warning(f"Failed to write budget_trim.json: {e}", STDOUT_LOG_PHASE)

    return [*head, *trimmed_middle, *tail]