"""
retry_policy.py
Retry strategy and exhaustion handling for the CodeQL Agent.

All handling of "retries exhausted / abnormal interruption" lives in this module;
agent.py only orchestrates. Every exhaustion path funnels through finalize_spec(),
which never silently drops a usable candidate.

Main responsibilities:
  - classify runtime failures as environmental or code-caused;
  - keep a separate budget for runtime retries and fail fast on environmental errors;
  - retry LLM calls with bounded backoff and never raise to the caller;
  - turn raw compiler stderr into structured, actionable feedback;
  - check the assembled script for missing critical roles.

Logging: every fallback writes a fallback.json record under the spec's log
directory so degraded and failed outcomes can be audited afterwards.
"""
import json
import os
import random
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from logger import StdoutLogger, log_json

from codeql_agent.codeql_agent_data import SpecResult

# Stdout Log Phase
STDOUT_LOG_PHASE = "codeql_agent/retry_policy"

# Fallback record filename (shared shape with analysis_agent/utils/fallback.py)
FALLBACK_LOG_FILENAME = "fallback.json"
# Record of consecutive environmental failures that tripped the circuit breaker
CIRCUIT_BREAK_FILENAME = "circuit_break.json"
# Record of missing roles found by the post-assembly self-check
ASSEMBLY_GUARD_FILENAME = "assembly_guard.json"

# Runtime failure causes
ENVIRONMENTAL = "environmental"   # unrelated to the predicate; retrying is pointless
CODE_CAUSED = "code"              # attributable to the generated predicate; retrying helps


# ============================================================
#  Failure kinds (stored in SpecResult.failure_kind for the breaker and stats)
# ============================================================

class FailureKind:
    PASSED = "passed"
    DEGRADED_GT = "degraded_gt_not_hit"          # degraded release: compiles + non-empty, but GT not hit
    NO_CODE = "no_code"                          # no code block extracted
    LLM_ERROR = "llm_error"                      # consecutive LLM call failures
    COMPILE_EXHAUSTED = "compile_exhausted"
    EMPTY_EXHAUSTED = "empty_exhausted"
    RUNTIME_ENV = "runtime_env"                  # environmental execution failure (fail fast)
    RUNTIME_CODE_EXHAUSTED = "runtime_code_exhausted"
    TOTAL_EXHAUSTED = "total_exhausted"
    # Match-scope anomaly (see validator.py): far more results than expected, or
    # a predicate with unconstrained nodes.
    SCOPE_EXHAUSTED = "scope_exhausted"          # scope-rewrite budget exhausted, not released
    SCOPE_DEGRADED = "scope_degraded"            # scope-rewrite budget exhausted, released with oversized marker


# ============================================================
#  1. Runtime failure classification
# ============================================================

# Environmental failure signatures unrelated to the generated predicate.
# On a match, retrying cannot succeed, and the stderr must never be sent back
# to the model as "fix your code" feedback.
_ENVIRONMENTAL_PATTERNS = [
    # CodeQL DB / IMB cache lock contention
    r"IMB disk cache",
    r"already locked by another running process",
    r"OverlappingFileLockException",
    r"Could not acquire lock",
    r"Resource temporarily unavailable",
    # Disk
    r"No space left on device",
    r"Disk quota exceeded",
    r"Read-only file system",
    # Memory
    r"OutOfMemoryError",
    r"Cannot allocate memory",
    r"insufficient memory",
    r"java heap space",
    # CLI unavailable
    r"codeql: (command )?not found",
    r"command not found",
    r"codeql.*No such file or directory",
    r"CodeQL CLI invocation failed",
    r"FileNotFoundError",
    # Database corrupt / missing / incompatible
    r"not a valid database",
    r"database (is )?corrupt",
    r"database .* does not exist",
    r"database .* incompatible",
    # Permissions / network
    r"Permission denied",
    r"Could not resolve host",
    r"Connection (refused|reset|timed out)",
    r"Failed to download",
    # LLM provider queue timeout. Some providers return HTTP 200 with an error
    # body once the queue is saturated; clients parse it as a normal
    # ChatCompletion and surface it as a ValueError or as
    # TypeError: 'NoneType' object is not iterable. Register the literal text so
    # a queue timeout is not mistaken for a code error and fed back to the model.
    r"unable to start processing your request",
    r"within the \d+-second timeout limit",
]
_ENVIRONMENTAL_RE = re.compile("|".join(_ENVIRONMENTAL_PATTERNS), re.IGNORECASE)


# ------------------------------------------------------------
#  LLM exceptions for which retrying is pointless
#  (separate from the CodeQL runtime table above; do not mix)
# ------------------------------------------------------------
# Why a separate table: _ENVIRONMENTAL_RE judges CodeQL execution stderr, where
# "Connection refused / FileNotFoundError / Permission denied" are genuine
# configuration problems. Reusing it for LLM exceptions would also kill
# transient network errors that a retry would fix.
#
# This table only lists cases where the provider has explicitly stated a cause
# and a retry necessarily pays the same cost again. The known case is a provider
# queue timeout: the server queues for up to 900 s and then returns an error
# body, which the client parses as a normal ChatCompletion and surfaces as one
# of the exceptions below. Retrying means queueing for another full window.
_NON_RETRYABLE_LLM_PATTERNS = [
    # Disguise A: langchain_openai/base.py raises ValueError(response_dict["error"]).
    # The original text is preserved in the exception message and can be matched.
    r"unable to start processing your request",
    r"within the \d+-second timeout limit",
    # Disguise B: openai/lib/_parsing/_completions.py iterates over
    # `chat_completion.choices`, which is None, raising TypeError. The queue
    # timeout text is absent, so match the signature. This helper is only
    # applied to `llm.invoke(messages)`, so within that scope the signature
    # almost certainly comes from the choices-is-None path. The worst case of a
    # misclassification is one skipped retry: the caller receives None, injects
    # a "no output last round, please regenerate" message and keeps looping at
    # a higher level, so no direction is lost.
    r"'NoneType' object is not iterable",
]
_NON_RETRYABLE_LLM_RE = re.compile("|".join(_NON_RETRYABLE_LLM_PATTERNS), re.IGNORECASE)


def is_non_retryable_llm_error(exc: BaseException) -> bool:
    """Whether this LLM exception is an environmental failure (e.g. queue timeout) that retrying cannot fix."""
    if exc is None:
        return False
    return bool(_NON_RETRYABLE_LLM_RE.search(f"{type(exc).__name__}: {exc}"))


# ------------------------------------------------------------
#  Provider profiles and LLM error classification
# ------------------------------------------------------------
# An OpenAI-compatible gateway is less stable than the official API and needs a
# larger retry budget. All behavior introduced here is gated by the profile, so
# the legacy DeepSeek path keeps identical parameters and branches.
#
# Detection uses `_llm_type`, not class names: ChatDeepSeek and ChatOpenAI are
# sibling classes (common parent BaseChatOpenAI) and are not isinstance of each
# other. `_llm_type` is proxied by wrappers, but RunnableSequence /
# RunnableParallel return None for it, so the graph must be unwrapped. The
# structured-output wrapper shape is:
#     RunnableSequence -- first --> RunnableParallel -- steps__ --> _ChatModelBinding
# RunnableParallel children live under `steps__` (a dict). Accept both `steps`
# and `steps__`; otherwise a langchain upgrade would silently fall back to the
# legacy profile (old behavior that looks fine but loses the hardening).

LEGACY_PROFILE_NAME = "legacy_deepseek"
RELAY_PROFILE_NAME = "openai_gateway"

_LLM_TYPE_TO_PROFILE = {
    "chat-deepseek": LEGACY_PROFILE_NAME,
    "deepseek-chat": LEGACY_PROFILE_NAME,
    "openai-chat": RELAY_PROFILE_NAME,
    "azure-openai-chat": RELAY_PROFILE_NAME,
    # Dead entry kept for documentation: langchain-openai's ChatOpenAI._llm_type
    # is always 'openai-chat' regardless of the model name, and stays the same
    # with use_responses_api=True. This line therefore never matches; it only
    # records the intent that the responses endpoint belongs to the gateway
    # profile. To distinguish the endpoint, read the instance attribute
    # `use_responses_api`; see `_uses_responses_api()`.
    "openai-responses": RELAY_PROFILE_NAME,
}

_MAX_UNWRAP_DEPTH = 6
_ATOMIC_TYPES = (str, bytes, int, float, bool)


def _iter_child_runnables(obj):
    """List the direct children of a Runnable graph (field names per langchain-core 1.4)."""
    for attr in ("bound", "runnable", "first", "last"):
        child = getattr(obj, attr, None)
        if child is not None:
            yield child
    middle = getattr(obj, "middle", None)
    if isinstance(middle, (list, tuple)):
        yield from middle
    for attr in ("steps", "steps__"):   # support both field names: 1.4 uses steps__ for RunnableParallel
        steps = getattr(obj, attr, None)
        if isinstance(steps, dict):
            yield from steps.values()
        elif isinstance(steps, (list, tuple)):
            yield from steps
    fallbacks = getattr(obj, "fallbacks", None)
    if isinstance(fallbacks, (list, tuple)):
        yield from fallbacks


def _find_llm_type(obj, depth: int = 0, seen=None) -> Optional[str]:
    """Depth-first search for the inner chat model's `_llm_type`; None if not found."""
    if obj is None or depth > _MAX_UNWRAP_DEPTH or isinstance(obj, _ATOMIC_TYPES):
        return None
    seen = set() if seen is None else seen
    if id(obj) in seen:
        return None
    seen.add(id(obj))
    llm_type = getattr(obj, "_llm_type", None)
    if isinstance(llm_type, str) and llm_type:
        return llm_type
    for child in _iter_child_runnables(obj):
        found = _find_llm_type(child, depth + 1, seen)
        if found:
            return found
    return None


def _find_chat_model(obj, depth: int = 0, seen=None):
    """Depth-first search for the inner chat model instance (not its `_llm_type`); None if not found.

    Uses the same traversal, depth limit and give-up behavior as `_find_llm_type`;
    the only difference is that it returns the instance, because the endpoint flag
    `use_responses_api` lives on the instance and `_llm_type` cannot distinguish
    endpoints (see the note above `_LLM_TYPE_TO_PROFILE`).
    """
    if obj is None or depth > _MAX_UNWRAP_DEPTH or isinstance(obj, _ATOMIC_TYPES):
        return None
    seen = set() if seen is None else seen
    if id(obj) in seen:
        return None
    seen.add(id(obj))
    llm_type = getattr(obj, "_llm_type", None)
    if isinstance(llm_type, str) and llm_type:
        return obj
    for child in _iter_child_runnables(obj):
        found = _find_chat_model(child, depth + 1, seen)
        if found is not None:
            return found
    return None


def _uses_responses_api(llm) -> bool:
    """
    Whether the inner chat model uses the `/v1/responses` endpoint.

    `ChatOpenAI.use_responses_api` defaults to None when not passed explicitly
    and becomes True when enabled, so compare with `is True` instead of truthiness
    (to avoid treating None as True). If the inner model cannot be identified,
    return False, and `bind_tools_compat` falls back to the chat/completions
    workaround.
    """
    model = _find_chat_model(llm)
    return model is not None and getattr(model, "use_responses_api", None) is True


@dataclass(frozen=True)
class RetryProfile:
    """One retry budget. LEGACY_PROFILE values must remain equal to the previous hard-coded defaults."""
    name: str
    max_attempts: int
    base_delay: float
    max_delay: float            # 0 means no cap (the legacy 2/4 sequence caps itself)
    jitter: str                 # "none" | "equal"
    legacy_table: bool          # whether the provider queue-timeout table participates
    detect_anomaly: bool        # whether to detect "call succeeded but output unusable"
    budgets: Dict[str, Tuple[int, float, float]] = field(default_factory=dict)

    def budget_for(self, error_class: str) -> Tuple[int, float, float]:
        """Return (max_attempts, base_delay, max_delay) for an error class; profile defaults if unregistered."""
        return self.budgets.get(
            error_class, (self.max_attempts, self.base_delay, self.max_delay)
        )


LEGACY_PROFILE = RetryProfile(
    name=LEGACY_PROFILE_NAME,
    max_attempts=3, base_delay=2.0, max_delay=0.0,
    jitter="none", legacy_table=True, detect_anomaly=False,
)

# Gateway profile: flakiness is mostly load-balancer switches or transient 5xx,
# which recover much faster than a saturated provider queue, so use a lower
# initial delay and more attempts. Equal jitter guarantees at least half the
# delay, preventing workers from hot-retrying in lockstep. Per-class budgets
# avoid waiting 5 x 30 s when the whole gateway is down.
RELAY_PROFILE = RetryProfile(
    name=RELAY_PROFILE_NAME,
    max_attempts=5, base_delay=1.5, max_delay=30.0,
    jitter="equal", legacy_table=False, detect_anomaly=True,
    budgets={
        # Proxy/DNS disconnects are self-healing; waiting longer has high expected value.
        # The budget must not be shorter than the legacy one (3 attempts, base 2.0,
        # no cap => about 6 s).
        "connection": (5, 2.0, 30.0),      # attempts >= legacy, legacy initial delay, 30 s cap (plus equal jitter)
        "rate_limited": (4, 2.0, 60.0),    # 429: honor Retry-After, capped at 60 s
        "server_5xx": (5, 1.5, 30.0),      # gateway 5xx: most likely to recover immediately
        "empty_choices": (4, 1.0, 10.0),   # choices==[]: gateway glitch, retry quickly
        "unknown": (5, 1.5, 30.0),
    },
)

_PROFILES = {p.name: p for p in (LEGACY_PROFILE, RELAY_PROFILE)}


def resolve_provider_profile(llm, override: Optional[str] = None) -> str:
    """
    Decide which retry profile the llm belongs to.

    Order: explicit override > `_llm_type` > legacy fallback.
    **Falling back to legacy for unknown shapes is deliberate**: new wrapper
    shapes and stub objects keep the old behavior instead of silently changing
    strategy just because they were not recognized.
    """
    if override:
        key = str(override).strip().lower()
        if key in (LEGACY_PROFILE_NAME, "deepseek", "legacy"):
            return LEGACY_PROFILE_NAME
        if key in (RELAY_PROFILE_NAME, "openai", "relay"):
            return RELAY_PROFILE_NAME
    return _LLM_TYPE_TO_PROFILE.get(_find_llm_type(llm) or "", LEGACY_PROFILE_NAME)


def get_retry_profile(llm, override: Optional[str] = None) -> RetryProfile:
    """Return the profile object for the llm."""
    return _PROFILES[resolve_provider_profile(llm, override)]


def bind_tools_compat(llm, tools):
    """
    Bind tools, handling one provider constraint that exists only in the gateway profile.

    Some gateways reject function tools combined with reasoning_effort on
    `/v1/chat/completions`:
      400 "Function tools with reasoning_effort are not supported for [model]
           in /v1/chat/completions. To use function tools, use /v1/responses
           or set reasoning_effort to 'none'."
    Only 'none' works there; minimal/low/medium/high are rejected with 400.
    Disabling reasoning hurts multi-step synthesis, so prefer the
    `/v1/responses` endpoint (enabled by `llm_model.py` through
    `default_kwargs["use_responses_api"]`), where tools and reasoning coexist.

    Keep the old workaround as a fallback: if `use_responses_api` did not take
    effect (or a caller constructs the model without `llm_manager`), returning a
    usable model with reasoning disabled is better than sending a request that
    must fail with 400.

    The legacy profile (DeepSeek) adds no arguments: `bind_tools(tools)` is
    called unchanged. Provider differences are described only in this module,
    the same discipline as the profile split in `invoke_with_backoff`.
    """
    if resolve_provider_profile(llm) == RELAY_PROFILE_NAME:
        if _uses_responses_api(llm):
            # /v1/responses: tools and reasoning can coexist, so add no reasoning_effort.
            return llm.bind_tools(tools)
        # /v1/chat/completions: mutually exclusive; only 'none' is accepted (otherwise 400).
        return llm.bind_tools(tools, reasoning_effort="none")
    return llm.bind_tools(tools)


# --- Error classification: classify only, no handling (handling is in invoke_with_backoff) ---

PERMANENT_AUTH = "permanent_auth"
PERMANENT_MODEL = "permanent_model"
PERMANENT_REQUEST = "permanent_request"
PERMANENT_CLASSES = frozenset({PERMANENT_AUTH, PERMANENT_MODEL, PERMANENT_REQUEST})

_RE_EMPTY_CHOICES = re.compile(r"\bIndexError\b.*list index out of range", re.IGNORECASE)
# Text fallback for input-size limits (in case the exception has no status_code):
# `413 - {'error': {'message': 'Input token count (1040440) exceeds system limit (1000000)'}}`.
_RE_INPUT_TOO_LARGE = re.compile(
    r"exceeds system limit|maximum context length|context_length_exceeded|"
    r"Input token count \(\d+\) exceeds",
    re.IGNORECASE,
)
_RE_CONNECTION = re.compile(
    r"NameResolutionError|Temporary failure in name resolution|getaddrinfo|"
    r"APIConnectionError|ConnectError|Connection (refused|reset|timed out)|"
    r"ProxyError|ReadTimeout|ConnectTimeout|RemoteProtocolError",
    re.IGNORECASE,
)


def _status_of(exc) -> Optional[int]:
    """Extract the HTTP status code (duck typing: openai.APIStatusError has .status_code and .response)."""
    status = getattr(exc, "status_code", None)
    if isinstance(status, int):
        return status
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def classify_llm_error(exc: BaseException) -> str:
    """Classify an LLM exception into a category with its own budget. Status code wins over text regex."""
    if exc is None:
        return "unknown"
    status = _status_of(exc)
    if status in (401, 403):
        return PERMANENT_AUTH
    if status == 404:
        return PERMANENT_MODEL
    if status in (400, 413, 422):
        # 413 = input too large. The payload size is fixed, so every attempt fails
        # the same way; retrying only resends the same oversized request.
        return PERMANENT_REQUEST
    if status == 429:
        return "rate_limited"
    if status is not None and status >= 500:
        return "server_5xx"
    text = f"{type(exc).__name__}: {exc}"
    if _RE_EMPTY_CHOICES.search(text):
        return "empty_choices"
    if _RE_INPUT_TOO_LARGE.search(text):
        return PERMANENT_REQUEST
    if _RE_CONNECTION.search(text):
        return "connection"
    if _NON_RETRYABLE_LLM_RE.search(text):
        return "provider_queue_timeout"
    return "unknown"


def is_permanent_llm_error(exc: BaseException) -> bool:
    """
    Provider-side permanent error: wrong key, model or request; retry and fallback are pointless.

    This is a **disjoint table** from `is_non_retryable_llm_error`:
    - the latter describes a provider queue timeout: retryable but expensive,
      and the caller explicitly opts out with `honor_non_retryable`;
    - this table describes configuration errors where every attempt fails the
      same way, so they must never be retried under any provider.
    The pattern sets deliberately do not overlap.
    """
    return classify_llm_error(exc) in PERMANENT_CLASSES


# --- Server-suggested wait time ---
# Aligned with the OpenAI SDK's MAX_RETRY_AFTER_DELAY (120 s). With our own
# retry layer the SDK no longer honors this header, so read it ourselves.
RETRY_AFTER_CAP = 120.0


def retry_after_seconds(exc) -> Optional[float]:
    """Return the `Retry-After` header in seconds; None if absent or unparseable."""
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    try:
        raw = headers.get("retry-after") or headers.get("Retry-After")
    except Exception:  # noqa: BLE001 -- header objects vary; treat failure as absent
        return None
    if raw is None:
        return None
    try:
        return max(0.0, float(raw))          # seconds form
    except (TypeError, ValueError):
        pass
    try:                                      # HTTP-date form
        import email.utils
        from datetime import datetime, timezone
        when = email.utils.parsedate_to_datetime(str(raw))
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    except Exception:  # noqa: BLE001
        return None


def classify_anomalous_response(response) -> Optional[str]:
    """
    Detect a "successful" call whose output is unusable; return None when normal.

    This is a subtle gateway failure mode: if the gateway ignores
    `response_format=json_object`, `with_structured_output(..., include_raw=True)`
    does not raise; it returns `{"raw": ..., "parsed": None, "parsing_error": ...}`.
    Without this check no retry fires and the pipeline silently degrades to an
    empty result that looks completed. Both dict and AIMessage shapes are checked.

    Only called when `profile.detect_anomaly` is true, so the legacy path is unaffected.
    """
    if response is None:
        return "empty_response"
    # Shape 1: structured wrapper (include_raw=True) -> dict
    if isinstance(response, dict) and ("parsed" in response or "raw" in response):
        if response.get("parsing_error") is not None:
            return "parsing_error"
        if response.get("parsed") is None:
            inner = response.get("raw")
            meta = getattr(inner, "response_metadata", None) or {}
            return "truncated_length" if meta.get("finish_reason") == "length" else "parsed_none"
        return None
    # Shape 2: bare model / bind_tools -> AIMessage
    content = getattr(response, "content", None)
    if isinstance(content, str) and content.strip():
        return None
    if isinstance(content, list) and any(content):
        return None
    if getattr(response, "tool_calls", None):
        return None
    meta = getattr(response, "response_metadata", None) or {}
    return "truncated_length" if meta.get("finish_reason") == "length" else "empty_content"


def backoff_seconds(
    profile: RetryProfile,
    base: float,
    attempt_index: int,
    max_delay: float,
    retry_after: Optional[float],
    pick,
) -> float:
    """
    Delay in seconds for one backoff step.

    The legacy profile is equivalent to the previous fixed formula:
    `base * 2**(i-1)` with no cap, no jitter and Retry-After ignored. The gateway
    profile adds an exponential cap, equal jitter (wait at least half the delay
    to avoid synchronized hot retries across workers) and prefers the server's
    Retry-After.
    """
    nominal = base * (2 ** (attempt_index - 1))
    if max_delay:
        nominal = min(nominal, max_delay)
    if profile.name == LEGACY_PROFILE_NAME:
        return nominal
    if retry_after is not None:
        capped = min(retry_after, RETRY_AFTER_CAP)
        return min(capped, max_delay) if max_delay else capped
    if profile.jitter == "equal":
        return nominal / 2 + pick(0.0, nominal / 2)
    return nominal


def classify_runtime_error(stderr: str) -> str:
    """
    Decide whether an execution failure is ENVIRONMENTAL or CODE_CAUSED.

    Defaults to CODE_CAUSED; only an explicit environmental signature in stderr
    changes that. A query timeout is code-caused: it usually means the match
    scope is too broad, so narrowing the predicate and retrying is meaningful.
    """
    if stderr and _ENVIRONMENTAL_RE.search(stderr):
        return ENVIRONMENTAL
    return CODE_CAUSED


def summarize_error(text: str, max_len: int = 160) -> str:
    """Collapse multi-line stderr into one line summary and strip absolute paths."""
    if not text:
        return ""
    flat = re.sub(r"/[\w./\-]+/", ".../", text)
    flat = re.sub(r"\s+", " ", flat).strip()
    return flat[:max_len]


# ============================================================
#  2. Structured error diagnosis
# ============================================================

# --- CodeQL compile error grammar ---
#   ERROR: <name>() cannot be resolved for type <Type> (<path>:<line>,<col>)
#   ERROR: could not resolve type <Name> (<path>:<line>,<col>)
#   ERROR: <other syntax/type error> (<path>:<line>,<col>)
_RE_ERROR_LINE = re.compile(r"^\s*ERROR:\s*(?P<body>.+?)\s*$")
# The location suffix must be the last parenthesized group at end of line, and
# the parentheses must not contain another parenthesis; otherwise
# `getMethodName() cannot be resolved ... (path:9,27-40)` would match the empty
# parentheses after the method name.
_RE_LOCATION = re.compile(r"\((?P<path>[^()]*?):(?P<line>\d+),(?P<col>[\d\-]+)\)\s*$")
_RE_API_UNRESOLVED = re.compile(
    r"^(?P<name>[^\s]+?)\s+cannot be resolved for type\s+(?P<type>\S+)$"
)
_RE_TYPE_UNRESOLVED = re.compile(r"^could not resolve type\s+(?P<name>\S+)$")

# --- Type names verified to be absent in the current CodeQL version (java-all 9.0.2 / CLI 2.25.1) ---
# A match gives a definite alternative instead of letting the model guess among made-up names.
_TYPE_CORRECTIONS: Dict[str, str] = {
    "ArrayType": "Current CodeQL (java-all 9.x) renamed `ArrayType` to `Array`; "
                 "write `.(Array)` instead of `.(ArrayType)`. `getComponentType()` is still available.",
    # This table takes precedence over the generic guidance in _JS_LIBRARY_TYPES:
    # give the exact replacement instead of letting the model search for one.
    "PropAccess": "`PropAccess` is a CodeQL JavaScript/TypeScript library type and does not exist in Java analysis. "
                  "The Java equivalent is `VarAccess` (variable access, including local variables and fields); "
                  "use its subclass `FieldAccess` when only fields matter. Do not apply type names across languages.",
}

# Type names from the CodeQL JavaScript/TypeScript library that do not exist in
# the Java library. Models influenced by pretraining often use them across
# languages; a match gets uniform guidance instead of a per-name guess.
_JS_LIBRARY_TYPES = {
    "PropAccess", "PropertyAccess", "VariableAccess", "DotExpr", "ObjectLit",
    "ArrayLit", "StringLit", "ObjectLiteral", "ObjectExpr", "CallExpr",
    "InvokeExpr", "MethodCallExpr", "ClassInstanceCreation", "ArrayLiteral",
    "Function", "IndexExpr", "NullLiteral",
}
# Node class names that do not exist in the DataFlow::Xxx namespace but are often invented
_FAKE_DATAPLOW_NODES = {
    "DataFlow::CallNode", "DataFlow::MethodCallNode", "DataFlow::PropWrite",
    "DataFlow::PropRead", "DataFlow::VariableNode",
}

# --- Verified wrong API -> correct form ---
# (called-name regex, owning-type regex, correction hint)
_API_CORRECTIONS: List[tuple] = [
    (
        r"getMethodName|getCalleeName",
        r"MethodCall|Call|MethodAccess",
        "Java CodeQL's `Call`/`MethodCall` has no `getMethodName()` / `getCalleeName()`. "
        "To get the method name, write `c.getCallee().getName()` (`getCallee()` returns `Callable`); "
        "to also constrain the declaring class, write "
        "`c.getCallee().getDeclaringType().getSourceDeclaration().hasQualifiedName(pkg, cls)`.",
    ),
    (
        r"getReceiver",
        r"MethodCall|Call|MethodAccess",
        "To get the receiver (qualifier), use `c.getQualifier()`. "
        "`getReceiver()` is not a Java CodeQL library API (that naming belongs to other languages).",
    ),
    (
        r"getNumberOfArguments",
        r"Call|MethodCall",
        "`Call` has no `getNumberOfArguments()`. Argument count is `c.getNumArgument()`; "
        "parameter count is `c.getCallee().getNumberOfParameters()`.",
    ),
    (
        r"getSourceDeclaration",
        r"^(?:Type|Type::Type)$",
        "`getSourceDeclaration()` is defined on `RefType`, not on `Type`. "
        "Cast first: `xxx.getType().(RefType).getSourceDeclaration()`, "
        "or use `getType()` and drop the source-declaration semantics.",
    ),
    (
        r"getValue|getInit",
        r"Member|Property",
        "Java CodeQL has no `Member::Property` type. Use `Field` for class fields and "
        "`Field.getInitializer()` for field initializers.",
    ),
    (
        r"getContents|getContent|getName",
        r"File|FileSystem::File",
        "`File` has no `getContents()` / `getName()`. Use `getRelativePath()` for the relative path, "
        "`getAbsolutePath()` for the absolute path; split the path string yourself for a file name.",
    ),
    (
        r"getAChild|getChild\b",
        r"Expr|BinaryExpr|AddExpr|Call",
        "Use `getAChildExpr()` for child expressions and "
        "`getLeftOperand()` / `getRightOperand()` for binary operands. `getAChild()` is not a Java CodeQL API.",
    ),
    (
        r"getEnclosingFunction",
        r".*",
        "`getEnclosingFunction()` is not a Java CodeQL API; "
        "use `getEnclosingCallable()` (returns `Callable`) for the enclosing method.",
    ),
    (
        r"getStringValue",
        r"Expr|Expr::Expr",
        "`Expr` has no `getStringValue()`. Cast a string literal first: `.(StringLiteral).getValue()`.",
    ),
    (
        r"regexpFind",
        r"string",
        "Strings have no `regexpFind()`. Use `regexpMatch()` for regular expressions; "
        "note that `matches()` uses wildcard semantics (`*` / `?`), not regex, and the two must not be mixed.",
    ),
    (
        r"substring",
        r"string",
        "CodeQL strings have no `substring()`. Combine `indexOf()` / `prefix()` / `suffix()`, "
        "or use `regexpMatch()` to constrain the pattern.",
    ),
]
_API_CORRECTIONS_COMPILED = [
    (re.compile(name_re), re.compile(type_re), hint)
    for name_re, type_re, hint in _API_CORRECTIONS
]


def _correct_api(name: str, type_name: str) -> Optional[str]:
    """Return a definite correction hint for an API that does not exist on a type; None if unknown."""
    for name_re, type_re, hint in _API_CORRECTIONS_COMPILED:
        if name_re.search(name) and type_re.search(type_name):
            return hint
    return None


def _correct_type(name: str) -> Optional[str]:
    """Return a definite correction hint for a type name that cannot be resolved; None if unknown."""
    if name in _TYPE_CORRECTIONS:
        return _TYPE_CORRECTIONS[name]
    if name in _FAKE_DATAPLOW_NODES:
        return (
            f"`{name}` does not exist. The DataFlow library only provides `DataFlow::Node` "
            "(plus a few subclasses such as `DataFlow::ExprNode` and `DataFlow::ParameterNode`); "
            "to narrow by expression kind, cast on `DataFlow::Node` with `node.asExpr().(...)`."
        )
    if name in _JS_LIBRARY_TYPES:
        return (
            f"`{name}` belongs to the CodeQL JavaScript/TypeScript library and does not exist in Java analysis. "
            "Use the Java library equivalent instead and do not apply type names across languages."
        )
    return None


# Cause hints for runtime (non-compile) errors
_RUNTIME_HINTS = [
    (
        r"query timed out|timeout",
        "A query timeout means the predicate's match scope is too broad (or it produces a "
        "cartesian-product style explosion). Narrow the conditions: use more specific class or "
        "method names, or add stronger constraints to `exists`; do not use `any()` or "
        "unconditional wildcards just to make the query run.",
    ),
]


@dataclass
class ErrorDiagnosis:
    """
    Structured diagnosis of one compile/run failure.

    raw_excerpt is kept for human inspection, but the model-facing text uses the
    structured fields: line numbers are mapped from the wrapped script back to the
    model's own code, and absolute paths or noise such as `Failed [1/1]` are stripped.
    """
    stage: str                                    # "compile" | "run"
    raw_excerpt: str = ""
    api_errors: List[dict] = field(default_factory=list)    # {name, type, line, hint}
    type_errors: List[dict] = field(default_factory=list)   # {name, line, hint}
    syntax_errors: List[dict] = field(default_factory=list)  # {text, line}
    other_errors: List[dict] = field(default_factory=list)   # {text, line}
    hints: List[str] = field(default_factory=list)

    @property
    def total_errors(self) -> int:
        return (len(self.api_errors) + len(self.type_errors)
                + len(self.syntax_errors) + len(self.other_errors))

    def one_line_summary(self) -> str:
        """One-line summary for compressed history (more precise than generic regex compression)."""
        if self.api_errors:
            e = self.api_errors[0]
            pos = f"line {e['line']}: " if e["line"] else ""
            return f"{pos}{e['name']} does not exist on {e['type']}"
        if self.type_errors:
            e = self.type_errors[0]
            pos = f"line {e['line']}: " if e["line"] else ""
            return f"{pos}cannot resolve type {e['name']}"
        if self.syntax_errors:
            return f"syntax error: {self.syntax_errors[0]['text']}"
        if self.hints:
            return summarize_error(self.hints[0], 150)
        return summarize_error(self.raw_excerpt, 150)

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "raw_excerpt": self.raw_excerpt,
            "api_errors": self.api_errors,
            "type_errors": self.type_errors,
            "syntax_errors": self.syntax_errors,
            "other_errors": self.other_errors,
            "hints": self.hints,
            "total_errors": self.total_errors,
        }


def _parse_error_lines(stderr: str, line_offset: int) -> ErrorDiagnosis:
    """
    Parse stderr from `codeql compile` / `codeql run`.

    Args:
        line_offset: number of lines in the wrapper script before the predicate
                     starts (predicate line 1 = offset + 1). Used to map CodeQL's
                     line numbers back to the lines the model wrote.
    """
    diag = ErrorDiagnosis(stage="compile", raw_excerpt=summarize_error(stderr, 300))

    for raw_line in (stderr or "").split("\n"):
        m = _RE_ERROR_LINE.match(raw_line)
        if not m:
            continue
        body = m.group("body")

        # Strip the location suffix and map the line number back
        line_no: Optional[int] = None
        loc = _RE_LOCATION.search(body)
        if loc:
            body = body[: loc.start()].strip()
            try:
                line_no = int(loc.group("line")) - line_offset
                if line_no < 1:
                    line_no = None
            except ValueError:
                line_no = None

        api = _RE_API_UNRESOLVED.match(body)
        if api:
            name, type_name = api.group("name"), api.group("type")
            hint = _correct_api(name, type_name)
            if hint and hint not in diag.hints:
                diag.hints.append(hint)
            diag.api_errors.append(
                {"name": name, "type": type_name, "line": line_no, "hint": hint or ""}
            )
            continue

        typ = _RE_TYPE_UNRESOLVED.match(body)
        if typ:
            name = typ.group("name")
            hint = _correct_type(name)
            if hint and hint not in diag.hints:
                diag.hints.append(hint)
            diag.type_errors.append({"name": name, "line": line_no, "hint": hint or ""})
            continue

        # Syntax / other compile errors
        entry = {"text": body[:200], "line": line_no}
        if body.startswith(("unexpected input", "no viable parse", "predicate requires",
                            "could not resolve variable", "'")):
            diag.syntax_errors.append(entry)
        else:
            diag.other_errors.append(entry)

    # If nothing could be parsed line by line (e.g. only a one-line summary remains),
    # fall back to the raw summary so the feedback is never empty.
    if diag.total_errors == 0 and diag.raw_excerpt:
        diag.other_errors.append({"text": diag.raw_excerpt, "line": None})

    return diag


def diagnose_compile_error(stderr: str, line_offset: int = 0) -> ErrorDiagnosis:
    """Parse compile errors into a structured diagnosis."""
    return _parse_error_lines(stderr, line_offset)


def diagnose_runtime_error(stderr: str) -> ErrorDiagnosis:
    """Parse execution errors into a structured diagnosis; add hints for known causes."""
    diag = ErrorDiagnosis(stage="run", raw_excerpt=summarize_error(stderr, 300))
    if stderr and _ENVIRONMENTAL_RE.search(stderr):
        diag.hints.append(
            "This failure is environmental (unrelated to your predicate, e.g. database lock "
            "contention, disk or memory). The system has stopped retrying this specification; "
            "no code change is needed based on this message."
        )
    for pattern, hint in _RUNTIME_HINTS:
        if stderr and re.search(pattern, stderr, re.IGNORECASE):
            diag.hints.append(hint)
    if not diag.hints:
        diag.other_errors.append({"text": diag.raw_excerpt, "line": None})
    return diag


# ============================================================
#  3. Consecutive environmental failure circuit breaker
# ============================================================

class EnvironmentCircuitBreaker:
    """
    N consecutive specifications ending in environmental failure means the CodeQL
    environment is unusable, so terminate the whole stage early.

    Division of labor with the per-spec fail-fast: fail-fast saves the remaining
    retries of one specification; the breaker saves all invalid attempts of the
    remaining specifications. Any non-environmental outcome (success or code-caused
    failure) resets the counter so a transient glitch does not trip the breaker.
    """

    def __init__(self, threshold: int = 5, log_dir: Optional[str] = None):
        self.threshold = threshold
        self.log_dir = log_dir
        self.consecutive_env_failures = 0
        self.env_failures: List[dict] = []
        self.tripped = False
        self.tripped_by: Optional[str] = None
        self.tripped_detail: str = ""

    def observe(self, failure_kind: str, spec_id: str, detail: str = "") -> bool:
        """Record one specification outcome; return True if this observation trips the breaker."""
        if failure_kind != FailureKind.RUNTIME_ENV:
            self.consecutive_env_failures = 0
            return False

        self.consecutive_env_failures += 1
        self.env_failures.append({"spec_id": spec_id, "detail": summarize_error(detail)})

        if not self.tripped and self.consecutive_env_failures >= self.threshold:
            self.tripped = True
            self.tripped_by = spec_id
            self.tripped_detail = summarize_error(detail)
            return True
        return False

    def to_record(self, skipped_spec_ids: Optional[List[str]] = None) -> dict:
        return {
            "kind": "environment_circuit_break",
            "reason": (
                f"{self.consecutive_env_failures} consecutive specifications ended with "
                f"environmental execution failures; the CodeQL environment is considered "
                f"unavailable, so this stage is terminated early"
            ),
            "threshold": self.threshold,
            "consecutive_env_failures": self.consecutive_env_failures,
            "tripped_by": self.tripped_by,
            "detail": self.tripped_detail,
            "env_failures": list(self.env_failures),
            "skipped_spec_ids": list(skipped_spec_ids or []),
        }

    def persist(self, skipped_spec_ids: Optional[List[str]] = None) -> Optional[str]:
        """Write circuit_break.json and return its path (a write failure does not affect the main flow)."""
        return record(
            self.log_dir,
            node="CodeQLAgent.circuit_breaker",
            kind="environment_circuit_break",
            detail=self.to_record(skipped_spec_ids)["reason"],
            level=StdoutLogger.error,
            record_payload=self.to_record(skipped_spec_ids),
            filename=CIRCUIT_BREAK_FILENAME,
        )


# ============================================================
#  4. Single exit point for exhaustion paths
# ============================================================

def finalize_spec(
    spec,
    *,
    attempts: int,
    reason: str,
    failure_kind: str,
    last_valid_code: Optional[str] = None,
    last_valid_attempt: int = 0,
    last_valid_oversized: bool = False,
    last_valid_defective: bool = False,
    degraded_kind: Optional[str] = None,
    log_dir: Optional[str] = None,
    detail: str = "",
) -> SpecResult:
    """
    Single exit point for every retry-exhaustion path.

    If a historical candidate exists (compiled successfully with non-empty
    results, `last_valid_code`), release it as success=True + gt_verified=False
    no matter which path exhausted (compile failure / empty result / runtime
    failure / total attempts). A usable candidate is never silently discarded.

    Two exceptions from the match-scope guard (`last_valid_*` flags are
    maintained by agent.py):

    - `last_valid_defective=True`: the candidate is provably unsound (a disjunct
      leaves node variables unconstrained, so it matches any node in the
      program). Such a candidate must not be revived; take the failure branch.
    - `last_valid_oversized=True`: the candidate only matches more results than
      expected (not a soundness defect). Release it with a marker and record
      `degraded_kind` (defaults to SCOPE_DEGRADED), and set SpecResult.oversized
      for runtime health statistics.

    When `degraded_kind=None`, choose from the candidate: oversized ->
    SCOPE_DEGRADED, otherwise DEGRADED_GT.
    """
    if degraded_kind is None:
        degraded_kind = (
            FailureKind.SCOPE_DEGRADED if last_valid_oversized else FailureKind.DEGRADED_GT
        )

    if last_valid_code is not None and not last_valid_defective:
        StdoutLogger.warning(
            f"[{spec.spec_id}] {reason}, but a degraded candidate exists "
            f"(attempt={last_valid_attempt}); releasing it"
            + (" (match scope too large, marked)" if last_valid_oversized else ""),
            STDOUT_LOG_PHASE,
        )
        record(
            log_dir,
            node="CodeQLAgent.finalize_spec",
            kind=degraded_kind,
            detail=f"{reason}; released historical candidate",
            spec_id=spec.spec_id,
            attempts=last_valid_attempt or attempts,
            candidate_available=True,
            oversized=last_valid_oversized,
        )
        return SpecResult(
            spec_id=spec.spec_id, role=spec.role, success=True,
            predicate_code=last_valid_code, spec=spec,
            attempts=last_valid_attempt or attempts, gt_verified=False,
            failure_kind=degraded_kind, oversized=last_valid_oversized,
        )

    if last_valid_defective:
        # Defective candidates must not be revived; keep the reason in detail for later inspection.
        detail = (detail or reason) + "; historical candidate has unconstrained node variables and must not be released"

    record(
        log_dir,
        node="CodeQLAgent.finalize_spec",
        kind=failure_kind,
        detail=detail or reason,
        spec_id=spec.spec_id,
        attempts=attempts,
        candidate_available=False,
    )
    return SpecResult(
        spec_id=spec.spec_id, role=spec.role, success=False,
        error_summary=reason, spec=spec, attempts=attempts,
        failure_kind=failure_kind,
    )


# ============================================================
#  5. LLM call backoff
# ============================================================

def invoke_with_backoff(
    llm,
    messages,
    *,
    max_attempts: Optional[int] = None,
    base_delay: Optional[float] = None,
    spec_id: str = "",
    log_dir: Optional[str] = None,
    sleep_fn=time.sleep,
    node: str = "CodeQLAgent.invoke_with_backoff",
    filename: str = FALLBACK_LOG_FILENAME,
    honor_non_retryable: bool = False,
    provider_profile: Optional[str] = None,
    jitter_fn=None,
    random_seed: Optional[int] = None,
):
    """
    Call the LLM with bounded backoff; return None when all attempts fail and
    never raise. A transient failure (rate limit, network glitch,
    LengthFinishReasonError, ...) must not abort the whole CodeQL stage. Only
    Exception is caught; KeyboardInterrupt / SystemExit propagate as usual.

    `node` / `filename` let reusers (analysis_agent) label their own node and
    write degradation records to a separate file (`llm_degradation.json`)
    instead of overwriting the identically shaped fallback.json.

    Retry budgets come from the provider profile:
    - legacy profile (DeepSeek or unrecognized): (3, 2.0, no cap, no jitter),
      identical to the previous hard-coded defaults.
    - gateway profile: more attempts, lower initial delay, jitter, exponential
      cap, per-error-class budgets, and detection of "call succeeded but output
      unusable".
    `max_attempts` / `base_delay` default to None, meaning "use the profile";
    passing them explicitly overrides the profile.

    Environmental queue timeouts are not retried (see
    `_NON_RETRYABLE_LLM_PATTERNS`): the error costs a full queue window, so a
    retry only buys another one. This is opt-in via `honor_non_retryable=True`
    and is not the default:
    - codeql_agent/agent.py leaves it False: each outer attempt still backs off
      up to 3 times, and the outer loop in role_registry allows 7 attempts, so
      the per-spec LLM call limit stays 3 x 7 = 21. A specification may need the
      9th call to produce a valid result, so giving up earlier would lose it.
      The cost of retrying during congestion is a separate decision that should
      not be changed from the analysis side.
    - analysis_agent/utils/fallback.py passes True: its analyzer loop is already
      retry-heavy, and 3 x 5 attempts could take 45 minutes per direction, so it
      needs to give up early.

    The legacy table only participates when `profile.legacy_table` is true. In
    the gateway profile it does not apply: a queue timeout is "retryable but
    expensive", while auth/model/request errors are permanent; mixing the two
    would treat a wrong key as another queue window.
    """
    profile = get_retry_profile(llm, provider_profile)
    explicit_attempts = max_attempts is not None
    attempts = max_attempts if explicit_attempts else profile.max_attempts
    base = base_delay if base_delay is not None else profile.base_delay
    rnd = random.Random(random_seed) if random_seed is not None else random
    pick = jitter_fn or (rnd.uniform if profile.jitter == "equal" else (lambda lo, hi: lo))

    last_error: Optional[BaseException] = None
    last_anomaly: Optional[str] = None
    attempts_used = 0
    non_retryable = False
    gave_up_early = False
    permanent = False
    error_class = ""
    max_delay = profile.max_delay

    for i in range(1, attempts + 1):
        attempts_used = i
        try:
            result = llm.invoke(messages)
        except Exception as e:  # noqa: BLE001 -- fallback code must swallow all retryable exceptions
            last_error = e
            error_class = classify_llm_error(e)
            non_retryable = is_non_retryable_llm_error(e)
            # Permanent errors (wrong key / model / request): every attempt fails
            # the same way, so do not try at all. This applies only to the gateway
            # profile; the legacy profile must keep the old behavior exactly.
            # Note that this only refuses to retry; it does not raise. Fallback
            # functions never raise: the failure is recorded with
            # error_class=permanent_* and handled by the existing degradation
            # branch, so it remains auditable.
            permanent = (not profile.legacy_table) and is_permanent_llm_error(e)
            gave_up_early = (permanent
                             or (non_retryable and honor_non_retryable and profile.legacy_table))
            non_retryable = non_retryable or permanent
            if permanent:
                note = (f", classified as permanent ({error_class}) => not retried "
                        "(configuration problem; retry and fallback are both pointless)")
            elif gave_up_early:
                note = ", provider queue timeout => giving up (a retry only buys another queue window)"
            elif non_retryable and profile.legacy_table:
                note = ("; provider queue timeout (early give-up is not enabled at this "
                        "call site => keeping the old backoff behavior)")
            else:
                note = ""
            StdoutLogger.warning(
                f"[{spec_id}] LLM call failed ({i}/{attempts})" + note
                + f": {type(e).__name__}: {summarize_error(str(e), 120)}",
                STDOUT_LOG_PHASE,
            )
            if gave_up_early:
                break
            if explicit_attempts:
                max_delay = profile.max_delay
            else:
                # Tighten this round's budget by error class (especially connection:
                # stop waiting when the host is unreachable).
                class_max, base, max_delay = profile.budget_for(error_class)
                if i >= class_max:
                    break
            if i < attempts:
                retry_after = (None if profile.name == LEGACY_PROFILE_NAME
                               else retry_after_seconds(e))
                sleep_fn(backoff_seconds(profile, base, i, max_delay, retry_after, pick))
            continue

        # --- Call did not raise: the gateway profile also checks the response contract ---
        anomaly = classify_anomalous_response(result) if profile.detect_anomaly else None
        if anomaly is None:
            return result
        last_anomaly = anomaly
        error_class = anomaly
        StdoutLogger.warning(
            f"[{spec_id}] LLM returned unusable output ({anomaly}, {i}/{attempts}); retrying",
            STDOUT_LOG_PHASE,
        )
        if i >= attempts:
            break
        sleep_fn(backoff_seconds(profile, base, i, max_delay, None, pick))

    if last_error is None and last_anomaly is not None:
        record(
            log_dir,
            node=node,
            kind=FailureKind.LLM_ERROR,
            detail=(f"LLM returned unusable output ({last_anomaly}) after "
                    f"{attempts_used}/{attempts} attempts; treated as a call failure and "
                    f"handled by the existing degradation branch (auditable)"),
            spec_id=spec_id,
            filename=filename,
            attempts_used=attempts_used,
            non_retryable=False,
            error_class=last_anomaly,
            profile=profile.name,
        )
        return None

    if permanent:
        outcome = f", permanent error ({error_class}), not retried"
    elif gave_up_early:
        outcome = ", environmental queue timeout, not retried"
    elif non_retryable and profile.legacy_table:
        outcome = ", environmental queue timeout (early give-up not enabled), backoff retries exhausted"
    else:
        outcome = ", backoff retries exhausted"
    record(
        log_dir,
        node=node,
        kind=FailureKind.LLM_ERROR,
        detail=(
            f"LLM call failed ({attempts_used}/{attempts} attempts" + outcome
            + f"): {type(last_error).__name__}: {summarize_error(str(last_error), 200)}"
        ),
        spec_id=spec_id,
        filename=filename,
        attempts_used=attempts_used,
        non_retryable=non_retryable,
        error_class=error_class,
        profile=profile.name,
    )
    return None


# ============================================================
#  6. Post-assembly role self-check
# ============================================================

# Roles without which the stage cannot continue: no source / sink means zero taint flows
CRITICAL_ROLES = ("source", "sink")


def check_assembly(
    validated: List[SpecResult],
    requested_roles,
    log_dir: Optional[str] = None,
) -> Optional[dict]:
    """
    Post-assembly self-check: does every requested critical role have at least
    one usable specification?

    When a role fails entirely, `ConfigAssembler` silently writes
    `false // no matching rules`, producing a script that compiles but always
    yields zero flows. Logs alone cannot distinguish that from "no
    vulnerabilities". This function records the degradation explicitly.

    Returns:
        The degradation record (also persisted as assembly_guard.json); None if
        no degradation.
    """
    available = {r.role for r in validated}
    missing = [role for role in CRITICAL_ROLES if role in requested_roles and role not in available]
    if not missing:
        return None

    record_data = {
        "kind": "assembly_degenerate",
        "reason": (
            f"Critical roles {missing} have no usable specification in this CodeQL stage; "
            f"the assembled script will have zero sources / zero sinks and taint analysis "
            f"will produce no flows"
        ),
        "missing_roles": missing,
        "requested_roles": sorted(requested_roles),
        "available_roles": sorted(available),
        "validated_count": len(validated),
    }
    StdoutLogger.error(
        f"Assembly self-check failed: {record_data['reason']}", STDOUT_LOG_PHASE
    )
    file_path = record(
        log_dir,
        node="CodeQLAgent.check_assembly",
        kind="assembly_degenerate",
        detail=record_data["reason"],
        level=StdoutLogger.error,
        record_payload=record_data,
        filename=ASSEMBLY_GUARD_FILENAME,
    )
    record_data["log_path"] = file_path
    return record_data


# ============================================================
#  Logging outlet (same shape as analysis_agent/utils/fallback.py)
# ============================================================

def record(
    log_dir: Optional[str],
    node: str,
    kind: str,
    detail: str,
    objective_id: Optional[str] = None,
    spec_id: Optional[str] = None,
    level=None,
    record_payload: Optional[dict] = None,
    filename: str = FALLBACK_LOG_FILENAME,
    **extra,
) -> Optional[str]:
    """
    Single fallback outlet: stdout warning + JSON record on disk.

    A write failure (unwritable directory, invalid path, ...) must not affect the
    main flow: fallback handling must never become a new failure point.
    """
    (level or StdoutLogger.warning)(
        f"[fallback] {node} | {kind} | {detail}", STDOUT_LOG_PHASE
    )

    payload = {
        "kind": kind,
        "node": node,
        "detail": detail,
        "objective_id": objective_id,
        "spec_id": spec_id,
    }
    payload.update(extra)
    if record_payload:
        # Flatten rather than nest, so circuit_break.json / assembly_guard.json
        # keep the same flat structure as codeql_agent_skipped.json and batch
        # scripts can read fields directly.
        payload.update(record_payload)

    if not log_dir:
        return None
    try:
        os.makedirs(log_dir, exist_ok=True)
        path = os.path.join(log_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return path
    except Exception as e:  # noqa: BLE001 -- a write failure only warns and never aborts the main flow
        StdoutLogger.warning(
            f"Failed to persist fallback record (main flow unaffected): {type(e).__name__}: {e}",
            STDOUT_LOG_PHASE,
        )
        return None
