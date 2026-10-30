#!/usr/bin/env python
"""
T8 offline regression: provider-aware retry profiles.

Subjects: the profile layer of `codeql_agent/retry_policy.py` and `invoke_with_backoff`.
Same harness as T7 (StubLLM / SleepRecorder / load_module / check() / fails / exit 0|1).
Everything is offline: section 2 builds real langchain client objects but **sends no network request**.

Section 1 pins the compatibility red line: an unrecognized client falls back to the legacy
DeepSeek profile and must remain byte-for-byte identical in behavior; section 7 G6 re-runs T7
as a subtest.

Section 6 covers a failure surface T7 cannot reach: if the gateway does not support
`response_format=json_object`, `with_structured_output(..., include_raw=True)` does **not**
raise; it returns `{"raw": ..., "parsed": None, "parsing_error": ...}`, so no retry fires and
the pipeline silently degrades into a "looks completed" empty result. Such failures do not
travel the exception path and can only be caught by return-contract validation.
"""
import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = HERE.parent.parent          # release root

fails = []


def check(ok, label, extra=""):
    print(f"  {'✓' if ok else '✗'} {label}" + (f"   {extra}" if extra and not ok else ""))
    if not ok:
        fails.append(label)
    return ok


# ---------------------------------------------------------------- Stubs

class StubLLM:
    """Fake LLM that raises or returns according to a script (same as in T7)."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        item = self.script.pop(0) if self.script else RuntimeError("script exhausted")
        if isinstance(item, BaseException):
            raise item
        return item


class ProfileStubLLM(StubLLM):
    """Stub carrying `_llm_type`, used to impersonate the gateway / DeepSeek client offline."""

    def __init__(self, script, llm_type="openai-chat"):
        super().__init__(script)
        self._llm_type = llm_type


class SleepRecorder:
    def __init__(self):
        self.calls = []

    def __call__(self, secs):
        self.calls.append(secs)


class ProviderError(RuntimeError):
    """Fake provider exception carrying status_code / response.headers.

    Duck-typed after `openai.APIStatusError` (which has both `.status_code` and
    `.response.headers`), so the code under test can read the status code and Retry-After
    without importing openai.
    """

    def __init__(self, status, message, retry_after=None):
        super().__init__(message)
        self.status_code = status
        headers = {}
        if retry_after is not None:
            headers["retry-after"] = retry_after
        self.response = SimpleNamespace(status_code=status, headers=headers)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _read(log_dir, fname):
    p = os.path.join(log_dir, fname)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


# The two DeepSeek disguise messages used by T7
MSG_A = ("We were unable to start processing your request within the 900-second "
         "timeout limit, please try again later.")
MSG_B = "'NoneType' object is not iterable"


# ================================================================ Section 1: DeepSeek path zero-regression

def part_regression(rp, tmp):
    print("[1] DeepSeek path zero-regression (unrecognized => legacy profile => byte-identical to prior releases)")

    # B1: ordinary exception, max_attempts not passed => the profile supplies the default
    llm = StubLLM([RuntimeError("boom")] * 5)
    sl = SleepRecorder()
    got = rp.invoke_with_backoff(llm, ["m"], spec_id="t8:b1", log_dir=tmp, sleep_fn=sl)
    check(got is None, "B1 returns None")
    check(llm.calls == 3, "B1 profile default is still 3 attempts", f"actual {llm.calls}")
    check(sl.calls == [2.0, 4.0], "B1 backoff is still exactly 2s/4s (proves jitter is off)", f"actual {sl.calls}")

    rec = _read(tmp, "fallback.json")
    check(rec is not None and rec.get("attempts_used") == 3, "B1 records attempts_used=3")
    check(rec is not None and rec.get("profile") == "legacy_deepseek",
          "B1 records profile=legacy_deepseek", f"actual {rec.get('profile') if rec else None}")
    check(rec is not None and rec.get("non_retryable") is False, "B1 records non_retryable=False")

    # B2: disguise A with the flag on => early give-up (restates T7 A1-A3)
    llm = StubLLM([ValueError(MSG_A), "should not be called"])
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:b2", log_dir=tmp, sleep_fn=sl,
                          honor_non_retryable=True)
    check(llm.calls == 1 and sl.calls == [], "B2 disguise A + flag => called once, no wait",
          f"calls={llm.calls} sleeps={sl.calls}")

    # B3: same for disguise B
    llm = StubLLM([TypeError(MSG_B), "should not be called"])
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:b3", log_dir=tmp, sleep_fn=sl,
                          honor_non_retryable=True)
    check(llm.calls == 1 and sl.calls == [], "B3 disguise B + flag => called once, no wait",
          f"calls={llm.calls} sleeps={sl.calls}")

    # B4: disguise A without the flag => all 3 attempts (legacy CodeQL-side behavior)
    llm = StubLLM([ValueError(MSG_A)] * 5)
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:b4", log_dir=tmp, sleep_fn=sl)
    check(llm.calls == 3 and sl.calls == [2.0, 4.0],
          "B4 disguise A without flag => still attempts all 3 times", f"calls={llm.calls} sleeps={sl.calls}")
    rec = _read(tmp, "fallback.json")
    check(rec is not None and "early give-up" in rec.get("detail", ""),
          "B4 detail text unchanged")

    # B5: explicit arguments override the profile (compatibility path for existing callers)
    llm = StubLLM([RuntimeError("boom")] * 5)
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], max_attempts=3, base_delay=2.0,
                          spec_id="t8:b5", log_dir=tmp, sleep_fn=sl)
    check(llm.calls == 3 and sl.calls == [2.0, 4.0], "B5 explicit 3/2.0 matches the profile default")

    # B6: explicitly force the legacy profile (key escape hatch for offline tests)
    llm = ProfileStubLLM([RuntimeError("boom")] * 5, llm_type="openai-chat")
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:b6", log_dir=tmp, sleep_fn=sl,
                          provider_profile="legacy")
    check(llm.calls == 3 and sl.calls == [2.0, 4.0],
          "B6 provider_profile='legacy' forces the legacy profile",
          f"calls={llm.calls} sleeps={sl.calls}")

    # B7: happy path never writes a degradation record
    happy = os.path.join(tmp, "happy")
    os.makedirs(happy, exist_ok=True)
    llm = StubLLM(["OK"])
    sl = SleepRecorder()
    got = rp.invoke_with_backoff(llm, ["m"], spec_id="t8:b7", log_dir=happy, sleep_fn=sl)
    check(got == "OK" and sl.calls == [], "B7 happy path returns immediately, zero wait")
    check(_read(happy, "fallback.json") is None, "B7 happy path writes no fallback.json")


# ================================================================ Section 2: profile resolution

def part_profile(rp, tmp):
    print("[2] Profile resolution: _llm_type drill-down (including structured and bind_tools wrappers)")
    from langchain_core.messages import AIMessage  # noqa: F401  (only to confirm the dependency is available)
    from langchain_openai import ChatOpenAI
    from langchain_deepseek import ChatDeepSeek
    from pydantic import BaseModel

    class Out(BaseModel):
        name: str

    ds = ChatDeepSeek(model="deepseek-flash", api_key="dummy")
    oa = ChatOpenAI(model="gpt-4o-mini", api_key="dummy", base_url="http://127.0.0.1:1/v1")
    tools = [{"type": "function",
              "function": {"name": "f", "description": "d",
                           "parameters": {"type": "object", "properties": {}}}}]

    cases = [
        ("A1 unrecognized => legacy", StubLLM([]), "legacy_deepseek"),
        ("A2 ChatDeepSeek => legacy", ds, "legacy_deepseek"),
        ("A3 ChatOpenAI => gateway", oa, "openai_gateway"),
        ("A4 ChatDeepSeek.bind_tools => legacy", ds.bind_tools(tools), "legacy_deepseek"),
        ("A5 ChatOpenAI.bind_tools => gateway", oa.bind_tools(tools), "openai_gateway"),
        ("A6 ChatOpenAI.with_structured_output => gateway",
         oa.with_structured_output(Out, method="json_mode", include_raw=True), "openai_gateway"),
        ("A7 ChatDeepSeek.with_structured_output => legacy",
         ds.with_structured_output(Out, method="json_mode", include_raw=True), "legacy_deepseek"),
        ("A9 ChatOpenAI.bind(response_format) => gateway",
         oa.bind(response_format={"type": "json_object"}), "openai_gateway"),
    ]
    for label, obj, expect in cases:
        got = rp.resolve_provider_profile(obj)
        check(got == expect, label, f"actual {got}")

    check(rp.resolve_provider_profile(StubLLM([]), "openai_gateway") == "openai_gateway",
          "A8 explicit override can force a stub into the gateway profile")

    src = (Path(rp.__file__)).read_text(encoding="utf-8")
    check('"steps"' in src and '"steps__"' in src,
          "A10 drill-down accepts both steps and steps__ (RunnableParallel uses steps__ in 1.4)")

    # A11 bind_tools_compat: the gateway returns 400 for "function tools + reasoning" on
    #     /v1/chat/completions; only reasoning_effort='none' was observed to work there.
    #     The client now uses the /v1/responses endpoint (use_responses_api=True in
    #     llm_model.py), where both coexist => no argument is added; the old workaround is
    #     kept as a fallback for when that switch is inactive. A11 therefore has three
    #     branches: responses endpoint / chat endpoint / unknown endpoint.
    class BindRecorder:
        def __init__(self, llm_type, use_responses_api=None):
            self._llm_type = llm_type
            if use_responses_api is not None:
                self.use_responses_api = use_responses_api
            self.calls = []

        def bind_tools(self, tools, **kw):
            self.calls.append((tools, kw))
            return "BOUND"

    TOOLS = [{"type": "function", "function": {"name": "f", "parameters": {}}}]

    rec = BindRecorder("openai-chat", use_responses_api=True)
    got = rp.bind_tools_compat(rec, TOOLS)
    check(got == "BOUND" and rec.calls == [(TOOLS, {})],
          "A11 /v1/responses endpoint: no reasoning_effort added (reasoning stays at its default, on)",
          f"actual {rec.calls}")

    rec = BindRecorder("openai-chat", use_responses_api=False)
    rp.bind_tools_compat(rec, TOOLS)
    check(rec.calls == [(TOOLS, {"reasoning_effort": "none"})],
          "A11 /v1/chat/completions endpoint: still explicitly reasoning_effort='none' (the known-good form)",
          f"actual {rec.calls}")

    rec = BindRecorder("openai-chat")     # attribute missing (legacy stub / unknown wrapper)
    rp.bind_tools_compat(rec, TOOLS)
    check(rec.calls == [(TOOLS, {"reasoning_effort": "none"})],
          "A11 endpoint flag unknown => conservatively use the chat-endpoint workaround instead of sending a guaranteed-400 request",
          f"actual {rec.calls}")

    rec = BindRecorder("chat-deepseek", use_responses_api=True)
    rp.bind_tools_compat(rec, TOOLS)
    check(rec.calls == [(TOOLS, {})],
          "A11 the legacy profile adds no bind_tools argument at all (DeepSeek path byte-identical)", f"actual {rec.calls}")

    rec = BindRecorder("whatever-unknown")
    rp.bind_tools_compat(rec, TOOLS)
    check(rec.calls == [(TOOLS, {})], "A11 unrecognized object also takes the legacy path")

    # A12 the endpoint predicate must **see through wrappers** (production receives a structured runnable, not a bare model).
    inner = ChatOpenAI(model="gpt-4o-mini", api_key="dummy",
                       base_url="http://127.0.0.1:1/v1", use_responses_api=True)
    for label, wrapped in (
        ("bind_tools wrapper", inner.bind_tools(tools)),
        ("with_structured_output wrapper",
         inner.with_structured_output(Out, method="json_mode", include_raw=True)),
    ):
        check(rp._uses_responses_api(wrapped) is True,
              f"A12 endpoint predicate sees through '{label}'")
    plain = ChatOpenAI(model="gpt-4o-mini", api_key="dummy", base_url="http://127.0.0.1:1/v1")
    check(rp._uses_responses_api(plain) is False,
          "A12 predicate is False when the endpoint switch is off (its default is None, not True)")
    check(rp._uses_responses_api(StubLLM([])) is False,
          "A12 predicate is False for unrecognized objects => the old workaround applies")


# ================================================================ Section 3: gateway profile scheduling

def part_relay_schedule(rp, tmp):
    print("[3] Gateway profile: more attempts + equal jitter (wait at least half to avoid synchronized hot retries)")

    llm = ProfileStubLLM([RuntimeError("gateway hiccup")] * 9)
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:c1", log_dir=tmp, sleep_fn=sl)
    check(llm.calls == 5, "C1 unclassified error => profile default of 5 attempts", f"actual {llm.calls}")
    check(len(sl.calls) == 4, "C1 4 backoff sleeps", f"actual {sl.calls}")

    bands = [(0.75, 1.5), (1.5, 3.0), (3.0, 6.0), (6.0, 12.0)]
    okband = all(lo - 1e-9 <= s <= hi + 1e-9 for s, (lo, hi) in zip(sl.calls, bands))
    check(okband, "C2 every backoff lies within the equal-jitter [d/2, d] band", f"actual {sl.calls}")
    check(sl.calls == sorted(sl.calls), "C2 backoff is monotonically increasing", f"actual {sl.calls}")

    # Inject jitter_fn at the upper / lower bound => pins equal jitter rather than full jitter
    for fn, expect, label in [
        (lambda a, b: b, [1.5, 3.0, 6.0, 12.0], "C3 upper bound => d/2+d/2=d"),
        (lambda a, b: a, [0.75, 1.5, 3.0, 6.0], "C3 lower bound => d/2"),
    ]:
        llm = ProfileStubLLM([RuntimeError("x")] * 9)
        sl = SleepRecorder()
        rp.invoke_with_backoff(llm, ["m"], spec_id="t8:c3", log_dir=tmp, sleep_fn=sl,
                              jitter_fn=fn)
        check(sl.calls == expect, label, f"actual {sl.calls}")

    # Real jitter: two runs with different seeds must not produce equal backoff vectors
    vecs = []
    for seed in (1, 2):
        llm = ProfileStubLLM([RuntimeError("x")] * 9)
        sl = SleepRecorder()
        rp.invoke_with_backoff(llm, ["m"], spec_id="t8:c4", log_dir=tmp, sleep_fn=sl,
                              random_seed=seed)
        vecs.append(sl.calls)
    check(vecs[0] != vecs[1], "C4 jitter is effective (different results for two seeds)", f"{vecs}")

    # Success on a later attempt (note: the gateway profile validates the return contract,
    # so the stub must return a real AIMessage -- a bare string is classified as
    # empty_content, see F5)
    from langchain_core.messages import AIMessage
    ok_msg = AIMessage(content="OK")
    llm = ProfileStubLLM([RuntimeError("x"), ok_msg])
    sl = SleepRecorder()
    got = rp.invoke_with_backoff(llm, ["m"], spec_id="t8:c5", log_dir=tmp, sleep_fn=sl)
    check(got is ok_msg and len(sl.calls) == 1, "C5 second attempt succeeds and returns")

    # C5b: counter-case -- a bare string must be rejected in the gateway profile (proves contract validation runs)
    llm = ProfileStubLLM(["OK"] * 9)
    sl = SleepRecorder()
    got = rp.invoke_with_backoff(llm, ["m"], spec_id="t8:c5b", log_dir=tmp, sleep_fn=sl)
    check(got is None and llm.calls == 5,
          "C5b bare string (not an AIMessage) is classified empty_content and retried in the gateway profile",
          f"calls={llm.calls}")

    # Per-class budgets
    llm = ProfileStubLLM([ProviderError(503, "bad gateway")] * 9)
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:c6", log_dir=tmp, sleep_fn=sl)
    check(llm.calls == 5, "C6 server_5xx => budget 5 attempts", f"actual {llm.calls}")

    llm = ProfileStubLLM([ProviderError(None, "APIConnectionError: NameResolutionError")] * 9)
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:c6b", log_dir=tmp, sleep_fn=sl)
    # C6b: disconnects are **self-healing** failures, so the budget is raised from
    # (3, 1.0, 10.0) to (5, 2.0, 30.0). With the old values three attempts gave up after
    # ~3s (t≈0/+1/+2s), **half as long as the legacy ~6s** -- the direction was wrong.
    check(llm.calls == 5, "C6b connection => raised to 5 attempts (>= legacy)", f"actual {llm.calls}")
    _bands = [((2.0 * 2 ** i) / 2, min(2.0 * 2 ** i, 30.0)) for i in range(4)]   # [1,2] [2,4] [4,8] [8,16]
    check(len(sl.calls) == 4 and all(lo <= s <= hi for s, (lo, hi) in zip(sl.calls, _bands)),
          "C6b connection => base 2.0 + equal jitter => 4 backoffs land in [1,2]/[2,4]/[4,8]/[8,16]",
          f"actual {sl.calls}")
    _rec = _read(tmp, "fallback.json")
    check(_rec is not None and _rec.get("error_class") == "connection",
          "C6b records error_class=connection")

    # Explicit arguments override the profile
    llm = ProfileStubLLM([RuntimeError("x")] * 9)
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], max_attempts=2, spec_id="t8:c7",
                          log_dir=tmp, sleep_fn=sl)
    check(llm.calls == 2, "C7 explicit max_attempts=2 overrides the profile's 5", f"actual {llm.calls}")


# ================================================================ Section 4: permanent errors + disjoint tables

def part_permanent(rp, tmp):
    print("[4] Permanent errors: never retried; and disjoint from the DeepSeek queue-timeout table")

    for status, msg, expect, label in [
        (401, "Invalid token", "permanent_auth", "D1 401 Invalid token => permanent_auth"),
        (404, "No available channel for this model on the current token",
         "permanent_model", "D2 404 model_not_found => permanent_model"),
        (400, "field messages is required", "permanent_request", "D3 400 invalid request => permanent_request"),
        (400, "max_tokens is too large", "permanent_request", "D4 400 max_tokens too large"),
        # D3b: 413 used to be unclassified => unknown => 5 inner retries, then the outer
        # MAX_RETRIES=5 reran the whole segment => **5x5 = 25** attempts, each sending the
        # same 1.04M-token payload (deterministic size => guaranteed failure). Observed as
        # 30 log lines matching `exceeds system limit` (5 x (5 + 1)).
        (413, "Input token count (1040440) exceeds system limit (1000000)",
         "permanent_request", "D3b* 413 input too large => permanent_request"),
    ]:
        llm = ProfileStubLLM([ProviderError(status, msg)] * 9)
        sl = SleepRecorder()
        d = os.path.join(tmp, f"perm{status}")
        os.makedirs(d, exist_ok=True)
        got = rp.invoke_with_backoff(llm, ["m"], spec_id="t8:d", log_dir=d, sleep_fn=sl)
        check(llm.calls == 1 and sl.calls == [], label + " => called once, zero wait",
              f"calls={llm.calls} sleeps={sl.calls}")
        rec = _read(d, "fallback.json")
        check(rec is not None and rec.get("error_class") == expect,
              label + " => records the right error_class",
              f"actual {rec.get('error_class') if rec else None}")
        check(got is None, label + " => returns None (nothing raised upward)")
        check(rec is not None and "permanent error" in rec.get("detail", "")
              and rec.get("non_retryable") is True,
              label + " => detail names a permanent error and non_retryable=True")

    # D3c: text-based fallback with **no status code** (in case a proxy swallows status_code and 413 falls back to unknown)
    for msg, label in [
        ("APIStatusError: 413 - Input token count (1040440) exceeds system limit (1000000)",
         "D3c no status code + exceeds system limit => permanent_request"),
        ("BadRequestError: maximum context length is 1048576 tokens. "
         "However, you requested 1084421 tokens", "D3d no status code + maximum context length"),
    ]:
        llm = ProfileStubLLM([ProviderError(None, msg)] * 9)
        sl = SleepRecorder()
        d = os.path.join(tmp, "perm_text_" + str(abs(hash(msg)) % 10000))
        os.makedirs(d, exist_ok=True)
        rp.invoke_with_backoff(llm, ["m"], spec_id="t8:d3c", log_dir=d, sleep_fn=sl)
        check(llm.calls == 1 and sl.calls == [], label + " => called once, zero wait",
              f"calls={llm.calls} sleeps={sl.calls}")
        rec = _read(d, "fallback.json")
        check(rec is not None and rec.get("error_class") == "permanent_request",
              label + " => records permanent_request",
              f"actual {rec.get('error_class') if rec else None}")

    # D3e: counter-case -- 429 must never be classified as permanent (it is retryable)
    llm = ProfileStubLLM([ProviderError(429, "rate limit exceeded")] * 9)
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:d3e", log_dir=tmp, sleep_fn=sl)
    check(llm.calls == 4, "D3e 429 => rate_limited, retryable (budget 4 attempts)", f"actual {llm.calls}")

    # D5: the legacy profile still attempts a 401 three times (old behavior); it records but does not act
    llm = ProfileStubLLM([ProviderError(401, "Invalid token")] * 9, llm_type="chat-deepseek")
    sl = SleepRecorder()
    d = os.path.join(tmp, "legacy401")
    os.makedirs(d, exist_ok=True)
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:d5", log_dir=d, sleep_fn=sl)
    check(llm.calls == 3 and sl.calls == [2.0, 4.0],
          "D5 legacy profile + 401 => still attempts all 3 times (DeepSeek behavior unchanged)",
          f"calls={llm.calls} sleeps={sl.calls}")
    rec = _read(d, "fallback.json")
    check(rec is not None and rec.get("error_class") == "permanent_auth",
          "D5 still records error_class faithfully (record only, no action)")

    # D6/D7: the two tables are disjoint
    check(rp.is_permanent_llm_error(ValueError(MSG_A)) is False
          and rp.is_non_retryable_llm_error(ValueError(MSG_A)) is True,
          "D6 queue timeout is in the old non-retry table, not in the permanent table (different semantics, never mixed)")
    check(rp.is_permanent_llm_error(TypeError(MSG_B)) is False,
          "D7 disguise B is not in the permanent table either")

    # D8: the old table is fully inactive in the gateway profile (even with honor_non_retryable set)
    llm = ProfileStubLLM([ValueError(MSG_A)] * 9)
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:d8", log_dir=tmp, sleep_fn=sl,
                          honor_non_retryable=True)
    check(llm.calls == 5, "D8 the gateway profile does not give up early even with honor_non_retryable (old table disabled)",
          f"actual {llm.calls}")

    # D9: the record carries the profile name
    d = os.path.join(tmp, "d9")
    os.makedirs(d, exist_ok=True)
    llm = ProfileStubLLM([RuntimeError("x")] * 9)
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:d9", log_dir=d, sleep_fn=SleepRecorder())
    rec = _read(d, "fallback.json")
    check(rec is not None and rec.get("profile") == "openai_gateway",
          "D9 records profile=openai_gateway", f"actual {rec.get('profile') if rec else None}")


# ================================================================ Section 5: Retry-After

def part_retry_after(rp, tmp):
    print("[5] Retry-After: honored by the gateway profile (capped at 120s, matching the SDK constant)")

    llm = ProfileStubLLM([ProviderError(429, "rate limited", retry_after="7")] * 9)
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:e1", log_dir=tmp, sleep_fn=sl)
    check(sl.calls and sl.calls[0] == 7.0, "E1 Retry-After: 7 => first backoff is 7s", f"actual {sl.calls}")

    llm = ProfileStubLLM([ProviderError(429, "rate limited", retry_after="600")] * 9)
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:e2", log_dir=tmp, sleep_fn=sl)
    check(sl.calls and sl.calls[0] == 60.0,
          "E2 Retry-After: 600 => clamped by the 60s rate_limited cap (does not sleep 600s)",
          f"actual {sl.calls}")

    llm = ProfileStubLLM(
        [ProviderError(429, "rate limited", retry_after="Wed, 21 Oct 2015 07:28:00 GMT")] * 9)
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:e3", log_dir=tmp, sleep_fn=sl)
    check(sl.calls and sl.calls[0] == 0.0,
          "E3 HTTP-date Retry-After parses (a past instant => 0s)", f"actual {sl.calls}")

    check(rp.retry_after_seconds(RuntimeError("x")) is None, "E4 no response/headers => None")

    llm = ProfileStubLLM([ProviderError(429, "rate limited", retry_after="7")] * 9,
                         llm_type="chat-deepseek")
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:e5", log_dir=tmp, sleep_fn=sl)
    check(sl.calls == [2.0, 4.0], "E5 legacy profile ignores Retry-After (old behavior unchanged)", f"actual {sl.calls}")


# ================================================================ Section 6: return-contract validation (the focus of this test)

def part_contract(rp, tmp):
    print("[6] Return contract: a 'successful' call with unusable output must be retried (otherwise it is silent degradation)")
    from langchain_core.messages import AIMessage

    # F1/F2: choices == [] => IndexError, retryable
    llm = ProfileStubLLM([IndexError("list index out of range")] * 9)
    sl = SleepRecorder()
    d = os.path.join(tmp, "f1")
    os.makedirs(d, exist_ok=True)
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:f1", log_dir=d, sleep_fn=sl)
    check(llm.calls == 4, "F1 gateway profile with choices==[] => retried with the empty_choices budget of 4",
          f"actual {llm.calls}")
    rec = _read(d, "fallback.json")
    check(rec is not None and rec.get("error_class") == "empty_choices",
          "F1 records error_class=empty_choices")

    llm = ProfileStubLLM([IndexError("list index out of range")] * 9, llm_type="chat-deepseek")
    sl = SleepRecorder()
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:f2", log_dir=tmp, sleep_fn=sl)
    check(llm.calls == 3, "F2 legacy profile with the same input still makes 3 attempts (behavior unchanged)", f"actual {llm.calls}")

    # F3: * structured wrapper returns parsed=None -- exactly the "gateway does not support json_object" shape
    bad = {"raw": AIMessage(content="not json at all"), "parsed": None,
           "parsing_error": ValueError("invalid json")}
    llm = ProfileStubLLM([bad] * 9)
    sl = SleepRecorder()
    d = os.path.join(tmp, "f3")
    os.makedirs(d, exist_ok=True)
    got = rp.invoke_with_backoff(llm, ["m"], spec_id="t8:f3", log_dir=d, sleep_fn=sl)
    check(llm.calls > 1, "F3* parsed=None triggers a retry (old code called once)",
          f"actual {llm.calls}")
    check(got is None, "F3* returns None after retries are exhausted (an auditable failure, not a silent empty result)")
    rec = _read(d, "fallback.json")
    check(rec is not None and rec.get("error_class") == "parsing_error",
          "F3* records error_class=parsing_error",
          f"actual {rec.get('error_class') if rec else None}")

    ok_dict = {"raw": AIMessage(content="{}"), "parsed": SimpleNamespace(name="x"),
               "parsing_error": None}
    llm = ProfileStubLLM([ok_dict])
    got = rp.invoke_with_backoff(llm, ["m"], spec_id="t8:f3b", log_dir=tmp,
                                 sleep_fn=SleepRecorder())
    check(got is ok_dict, "F3b a valid parsed result is returned unchanged")

    # F4: empty content / truncated
    cut = AIMessage(content="", response_metadata={"finish_reason": "length"})
    llm = ProfileStubLLM([cut] * 9)
    d = os.path.join(tmp, "f4")
    os.makedirs(d, exist_ok=True)
    rp.invoke_with_backoff(llm, ["m"], spec_id="t8:f4", log_dir=d, sleep_fn=SleepRecorder())
    check(llm.calls == 5, "F4 finish_reason=length with empty content => retried", f"actual {llm.calls}")
    rec = _read(d, "fallback.json")
    check(rec is not None and rec.get("error_class") == "truncated_length",
          "F4 records error_class=truncated_length")

    empty = AIMessage(content="")
    llm = ProfileStubLLM([empty])
    check(rp.classify_anomalous_response(empty) == "empty_content", "F5 empty content => empty_content")
    check(rp.classify_anomalous_response(AIMessage(content="normal")) is None,
          "F5 normal content => None (no false positive)")
    check(rp.classify_anomalous_response(
        AIMessage(content="", tool_calls=[{"name": "t", "args": {}, "id": "1"}])) is None,
        "F5 tool_calls present => not anomalous (the exploration loop relies on this)")

    # F6: the legacy profile skips contract validation => a malformed result is returned as-is (DeepSeek behavior unchanged)
    llm = ProfileStubLLM([empty], llm_type="chat-deepseek")
    sl = SleepRecorder()
    got = rp.invoke_with_backoff(llm, ["m"], spec_id="t8:f6", log_dir=tmp, sleep_fn=sl)
    check(got is empty and llm.calls == 1 and sl.calls == [],
          "F6 legacy profile returns as-is without retry (DeepSeek behavior unchanged)",
          f"calls={llm.calls} sleeps={sl.calls}")


# ================================================================ Section 7: source-structure assertions

def _block(src, key):
    """Roughly extract the text between `"<key>": {` and its matching closing brace."""
    i = src.find(f'"{key}": {{')
    if i < 0:
        return ""
    depth, j = 0, i + len(f'"{key}": ')
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
        j += 1
    return src[i:]


def part_source(root: Path, tmp):
    print("[7] Source structure: changes are confined to the openai profile; the old table and flag semantics are not reverted")

    rp_src = (root / "codeql_agent/retry_policy.py").read_text(encoding="utf-8")
    code_hits = [ln for ln in rp_src.splitlines()
                 if "llm.invoke(messages)" in ln and not ln.strip().startswith("#")]
    check(len(code_hits) == 1,
          "G1 exactly one llm.invoke(messages) in the module (comments excluded)", f"actual {code_hits}")

    lm = (root / "llm_model.py").read_text(encoding="utf-8")
    ds_block = _block(lm, "deepseek")
    check(ds_block and "timeout" not in ds_block and "max_retries" not in ds_block,
          "G3 the deepseek profile gains no timeout/max_retries", f"block: {ds_block[:80]}")
    check(ds_block and "default_kwargs" not in ds_block,
          "G3 the deepseek profile gains no default_kwargs")
    oa_block = _block(lm, "openai")
    check(all(k in oa_block for k in ("default_kwargs", "max_retries", "timeout")),
          "G4 the openai profile carries default_kwargs / max_retries / timeout")
    # G4: temperature/max_tokens must equal the aligned values, not merely be absent.
    # The intent is unchanged -- the two profiles must not diverge in sampling behavior.
    # temperature=1 and max_tokens=65536 **equal the DeepSeek server-side defaults**
    # (the former has no effect in thinking mode; the latter is the thinking-mode output
    # cap), so the **effective** parameters stay identical.
    check('"temperature": 1' in oa_block,
          "G4 the openai profile pins temperature to 1 (= DeepSeek default; not a new sampling behavior)")
    check('"max_tokens": 65536' in oa_block,
          "G4e the openai profile sets max_tokens=65536 (aligned with the DeepSeek thinking-mode 64K output cap)")
    check("temperature" not in ds_block and "max_tokens" not in ds_block,
          "G4 the deepseek profile still adds **no sampling key at all** (DeepSeek path byte-identical)")
    check("use_responses_api" in oa_block,
          "G4b the openai profile enables the /v1/responses endpoint")
    check("use_responses_api" not in ds_block,
          "G4b the deepseek profile **lacks** this key (DeepSeek path byte-identical)")
    check('output_version' in oa_block and '"v0"' in oa_block,
          "G4c the openai profile sets output_version='v0' (keeps responses/v1 from packing encrypted reasoning blocks into content)")
    check('"reasoning_effort": "xhigh"' in oa_block or "'reasoning_effort': 'xhigh'" in oa_block,
          "G4d the openai profile pins reasoning_effort='xhigh' (no reliance on upstream defaults, prevents drift)")
    check("reasoning_effort" not in ds_block,
          "G4d the deepseek profile **lacks** this key (the DeepSeek side relies on the server-side default and keeps existing behavior)")

    # G4c (cont.): with list-valued content, both consumers must handle it -- otherwise "no crash but silent degradation".
    mp = (root / "analysis_agent/utils/message_process.py").read_text(encoding="utf-8")
    check("isinstance(content, list)" in mp,
          "G4c estimate_message_tokens has a list-content branch (token estimation is not bypassed)")
    # G4f: single-character cost constants of the budget guard. **Both sites must share the
    # same constants** -- changing estimate_tokens without changing the divisor in
    # _truncate_message makes the guard "detect an overrun but fail to trim" (the old
    # char_cap = cap/0.3 let 1.3M-character messages escape truncation, returning the same
    # object with after==before).
    check("TOKENS_PER_CHAR_WORST = 0.42" in mp and "TOKENS_PER_CJK_CHAR_WORST = 1.0" in mp,
          "G4f guard per-character costs raised to 0.42 / 1.0 based on measurements")
    check(mp.count("TOKENS_PER_CHAR_WORST") >= 3,
          "G4f estimate_tokens and _truncate_message **share the same constants** (no duplicated literals)",
          f"found {mp.count('TOKENS_PER_CHAR_WORST')} times")
    check("token_cap / 0.3" not in mp and "* 0.3" not in mp,
          "G4f no hardcoded 0.3 factor remains in the source")

    ca = (root / "codeql_agent/agent.py").read_text(encoding="utf-8")
    check("isinstance(content, list)" in ca,
          "G4c _extract_code_block has a list-content branch (CodeQL-side code blocks are still extracted)")

    fb = (root / "analysis_agent/utils/fallback.py").read_text(encoding="utf-8")
    check("honor_non_retryable=True" in fb,
          "G5 analysis_agent/utils/fallback.py still enables the flag explicitly (T7 E7 must not regress)")
    ag = (root / "codeql_agent/agent.py").read_text(encoding="utf-8")
    check("honor_non_retryable" not in ag,
          "G5 codeql_agent/agent.py still does not pass the flag (T7 E8 must not regress)")

    ex = (root / "analysis_agent/executor_agent/executor_nodes.py").read_text(encoding="utf-8")
    check("bind_tools_compat(" in ex and ".bind_tools(TOOLS)" not in ex,
          "G7 executor_nodes binds tools only via bind_tools_compat (no bare .bind_tools(TOOLS))")

    # G6: run T7 as a subtest -- the strongest single assertion of DeepSeek-path zero-regression
    t7 = root / "test/offline/T7_llm_fallback_injection.py"
    proc = subprocess.run([sys.executable, str(t7), "--post-root", str(root)],
                          capture_output=True, text=True, timeout=300)
    check(proc.returncode == 0, "G6 T7 still passes as a subtest (DeepSeek path unchanged)",
          f"exit={proc.returncode} tail={proc.stdout[-200:]}")


def main():
    ap = argparse.ArgumentParser(description="T8 offline regression: provider-aware retry profiles")
    ap.add_argument("--post-root", default=str(DEFAULT_ROOT),
                    help="root of the release under test (default: two levels above this script)")
    args = ap.parse_args()

    post = Path(args.post_root).resolve()
    if str(post) not in sys.path:
        sys.path.insert(0, str(post))

    rp = load_module(post / "codeql_agent/retry_policy.py", "t8_retry_policy")

    print("=" * 68)
    print(f"T8 root under test: {post}")
    print("=" * 68)

    with tempfile.TemporaryDirectory() as tmp:
        for name in ("r", "p", "s", "perm", "ra", "contract"):
            os.makedirs(os.path.join(tmp, name), exist_ok=True)
        part_regression(rp, os.path.join(tmp, "r"))
        part_profile(rp, os.path.join(tmp, "p"))
        part_relay_schedule(rp, os.path.join(tmp, "s"))
        part_permanent(rp, os.path.join(tmp, "perm"))
        part_retry_after(rp, os.path.join(tmp, "ra"))
        part_contract(rp, os.path.join(tmp, "contract"))
        part_source(post, tmp)

    print("=" * 68)
    if fails:
        print(f"✗ T8 FAILED, {len(fails)} item(s):")
        for f in fails:
            print(f"    - {f}")
        return 1
    print("✓ T8 PASSED: DeepSeek path byte-identical; the gateway profile uses per-class backoff, "
          "permanent errors are not retried, Retry-After is honored, and contract validation catches silent degradation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
