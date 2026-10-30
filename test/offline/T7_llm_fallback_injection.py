#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
T7 -- injection regression for provider queue timeouts without a fallback.

Everything here is **offline**: stub objects impersonate `llm`; no network, no CodeQL DB and
no run artifacts are touched.

## Pinned semantics (three points)

1. **Disguise A is recognized**: the provider returns `HTTP 200 + error body`, and
   langchain_openai does `raise ValueError(response_dict.get("error"))`; the exception message
   still contains "unable to start processing your request ... within the 900-second timeout limit".
2. **Disguise B is recognized**: the same responses reach
   `openai/lib/_parsing/_completions.py` with `choices` set to None, producing
   `TypeError: 'NoneType' object is not iterable`. Its message does **not** contain the queue
   timeout text, so it can only be recognized by signature.
3. **Neither is retried**: a 900-second queue delay costs 900 seconds even once, and retrying
   only changes queue position. On a match the loop `break`s and `sleep_fn` is never called.

A fourth point (`plan_llm.invoke` raising TypeError must **not** abort) is covered by the
**structural scan** below: every one of the 7 analysis_agent call sites must (a) go through
`invoke_llm_with_fallback` and (b) be immediately followed by a `None` guard -- without both,
`None` flows into downstream `response.content` and becomes a new crash point.

## Usage

    cd <release root>
    python test/offline/T7_llm_fallback_injection.py

Exit code 0 only when everything passes.
"""
import argparse
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

# 7 call sites: (file relative to post-root, expected occurrences)
CALL_SITES = [
    ("analysis_agent/plan_nodes.py", 2),
    ("analysis_agent/process_nodes.py", 3),
    ("analysis_agent/executor_agent/executor_nodes.py", 2),
]

DEFAULT_ROOT = HERE.parent.parent  # release root

fails = []


def check(ok, label, extra=""):
    print(f"  {'✓' if ok else '✗'} {label}" + (f"   {extra}" if extra and not ok else ""))
    if not ok:
        fails.append(label)
    return ok


# ---------------------------------------------------------------- Stubs

class StubLLM:
    """Fake LLM that raises or returns according to a script."""

    def __init__(self, script):
        self.script = list(script)   # each item: an Exception instance raises; anything else is returned
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        item = self.script.pop(0) if self.script else RuntimeError("script exhausted")
        if isinstance(item, BaseException):
            raise item
        return item


class SleepRecorder:
    def __init__(self):
        self.calls = []

    def __call__(self, secs):
        self.calls.append(secs)


# ---------------------------------------------------------------- Load modules under test

def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# The two disguise messages as observed in production logs
MSG_A = (
    "We were unable to start processing your request within the 900-second "
    "timeout limit, please try again later."
)
# Disguise B's message does **not** contain the queue-timeout text -- that is why it is hard to recognize
MSG_B = "'NoneType' object is not iterable"


# ---------------------------------------------------------------- Section 1: disguise A

def part_a(rp, tmpdir):
    print("[1] Disguise A: HTTP 200 + error body => ValueError(queue-timeout text)")
    print("    (honor_non_retryable enabled: the semantics used by the analysis_agent entry points)")
    llm = StubLLM([ValueError(MSG_A), "should not be called"])
    sleeper = SleepRecorder()
    got = rp.invoke_with_backoff(
        llm, ["m"], max_attempts=3, spec_id="t7:a",
        log_dir=tmpdir, sleep_fn=sleeper, honor_non_retryable=True,
    )
    check(got is None, "A1 returns None (degraded, nothing raised upward)")
    check(llm.calls == 1, "A2 called exactly once (no retry)", f"actual {llm.calls}")
    check(sleeper.calls == [], "A3 no backoff sleep occurred", f"actual {sleeper.calls}")

    rec = _read(tmpdir, "fallback.json")
    check(rec is not None, "A4 degradation record written")
    if rec:
        check(rec.get("non_retryable") is True, "A5 record marks non_retryable=True")
        check(rec.get("attempts_used") == 1, "A6 record has attempts_used=1",
              f"actual {rec.get('attempts_used')}")
        check(rec.get("kind") == "llm_error", "A7 record has kind=llm_error")


# ---------------------------------------------------------------- Section 2: disguise B

def part_b(rp, tmpdir):
    print("[2] Disguise B: choices is None => TypeError('NoneType' object is not iterable)")
    print("    (honor_non_retryable also enabled)")
    llm = StubLLM([TypeError(MSG_B), "should not be called"])
    sleeper = SleepRecorder()
    got = rp.invoke_with_backoff(
        llm, ["m"], max_attempts=3, spec_id="t7:b",
        log_dir=tmpdir, sleep_fn=sleeper, honor_non_retryable=True,
    )
    check(got is None, "B1 returns None")
    check(llm.calls == 1, "B2 called exactly once (no retry)", f"actual {llm.calls}")
    check(sleeper.calls == [], "B3 no backoff sleep occurred")
    check(rp.is_non_retryable_llm_error(TypeError(MSG_B)) is True,
          "B4 is_non_retryable_llm_error recognizes this signature")


# ---------------------------------------------------------------- Section 3: ordinary exceptions still retry

def part_c(rp, tmpdir):
    print("[3] Counter-case: ordinary exceptions still back off and retry up to max_attempts")
    llm = StubLLM([RuntimeError("connection reset by peer")] * 3)
    sleeper = SleepRecorder()
    got = rp.invoke_with_backoff(
        llm, ["m"], max_attempts=3, base_delay=2.0, spec_id="t7:c",
        log_dir=tmpdir, sleep_fn=sleeper,
    )
    check(got is None, "C1 returns None")
    check(llm.calls == 3, "C2 called the full 3 times", f"actual {llm.calls}")
    check(sleeper.calls == [2.0, 4.0], "C3 backoff is 2s / 4s (exponential)",
          f"actual {sleeper.calls}")
    rec = _read(tmpdir, "fallback.json")
    check(rec is not None and rec.get("non_retryable") is False,
          "C4 record marks non_retryable=False")
    check(rp.is_non_retryable_llm_error(RuntimeError("connection reset")) is False,
          "C5 ordinary exceptions are not misclassified")

    # Success on a later attempt: return the real result and stop backing off
    llm2 = StubLLM([RuntimeError("transient"), "OK"])
    s2 = SleepRecorder()
    got2 = rp.invoke_with_backoff(
        llm2, ["m"], max_attempts=3, spec_id="t7:c2", log_dir=tmpdir, sleep_fn=s2,
    )
    check(got2 == "OK", "C6 second attempt succeeds and its result is returned")
    check(s2.calls == [2.0], "C7 success path backs off once then stops", f"actual {s2.calls}")


# ---------------------------------------------------------------- Section 4: all 7 call sites have a None guard

def part_d(root: Path, tmpdir):
    print("[4] Structural scan: all 7 analysis_agent call sites use the fallback and a None guard")
    used = 0
    for rel, expect in CALL_SITES:
        src = (root / rel).read_text(encoding="utf-8")
        n = src.count("invoke_llm_with_fallback(")
        check(n == expect, f"D  {rel} has {expect} call sites", f"actual {n}")
        used += n

        # Each call site must be followed by an `if <name> is None:` guard
        guards = len(re.findall(r"if\s+\w+\s+is\s+None\s*:", src))
        check(guards >= expect, f"D  {rel} has >={expect} None guards",
              f"actual {guards}")

        # No bare .invoke( may remain -- that is the root-cause shape
        bare = [ln for ln in src.split("\n")
                if re.search(r"\b(llm|_llm|plan_llm|execution_llm|extractor_llm|dedup_llm)"
                             r"\.invoke\(", ln)]
        check(bare == [], f"D  {rel} has no bare .invoke(", f"remaining {bare}")
    check(used == 7, "D  7 call sites in total", f"actual {used}")


# ------------------------------------- Section 5: scope -- the CodeQL side still retries by default

def part_e(rp, root: Path, tmpdir):
    """"Do not retry environmental errors" must apply **only to analysis_agent**.

    Real counter-example: a specification needed 9 attempts (outer round 3 x inner attempt 3)
    before a round returned a complete result, while the earlier rounds failed with
    `llm_error` after 3x900s each. If the early break were enabled by default in the shared
    primitive, the CodeQL-side budget would drop from 3x7=21 to 7 and that predicate would be
    lost (it did appear in the final artifact).
    """
    print("[5] Scope: without honor_non_retryable the CodeQL side keeps legacy behavior (3 backoff retries)")

    # E1-E3: the same 900s disguise A must be attempted 3 times in the default profile, with exponential backoff
    llm = StubLLM([ValueError(MSG_A)] * 3)
    sleeper = SleepRecorder()
    got = rp.invoke_with_backoff(
        llm, ["m"], max_attempts=3, base_delay=2.0, spec_id="t7:e",
        log_dir=tmpdir, sleep_fn=sleeper,
    )
    check(got is None, "E1 returns None")
    check(llm.calls == 3, "E2 CodeQL side attempts all 3 times (no early give-up)", f"actual {llm.calls}")
    check(sleeper.calls == [2.0, 4.0], "E3 backoff remains 2s / 4s (legacy behavior)",
          f"actual {sleeper.calls}")

    rec = _read(tmpdir, "fallback.json")
    check(rec is not None and rec.get("non_retryable") is True,
          "E4 still honestly marks non_retryable=True (it just does not force a break)",
          f"actual {rec.get('non_retryable') if rec else None}")
    check(rec is not None and rec.get("attempts_used") == 3,
          "E5 attempts_used=3, and the text no longer claims no retry happened",
          f"actual {rec.get('attempts_used') if rec else None}")
    if rec:
        check("early give-up" in rec.get("detail", ""),
              "E6 detail states that early give-up is not enabled at this call site",
              f"actual {rec.get('detail', '')[:60]}")

    # E7-E8: structural assertion -- the flag is enabled in exactly one place and never on the CodeQL side
    fb = (root / "analysis_agent/utils/fallback.py").read_text(encoding="utf-8")
    check("honor_non_retryable=True" in fb,
          "E7 analysis_agent/utils/fallback.py enables it explicitly")
    ag = (root / "codeql_agent/agent.py").read_text(encoding="utf-8")
    check("honor_non_retryable" not in ag,
          "E8 codeql_agent/agent.py never passes the flag (keeps legacy behavior)")


# ---------------------------------------------------------------- Helpers

def _read(log_dir, fname):
    p = os.path.join(log_dir, fname)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description="T7 offline regression: LLM queue-timeout fallback")
    ap.add_argument("--post-root", default=str(DEFAULT_ROOT),
                    help="root of the release under test (default: two levels above this script)")
    args = ap.parse_args()

    post = Path(args.post_root).resolve()
    if str(post) not in sys.path:
        sys.path.insert(0, str(post))

    rp = load_module(post / "codeql_agent/retry_policy.py", "t7_retry_policy")

    print("=" * 68)
    print(f"T7 root under test: {post}")
    print("=" * 68)

    with tempfile.TemporaryDirectory() as tmp:
        d1 = os.path.join(tmp, "a"); os.makedirs(d1)
        d2 = os.path.join(tmp, "b"); os.makedirs(d2)
        d3 = os.path.join(tmp, "c"); os.makedirs(d3)
        d4 = os.path.join(tmp, "e"); os.makedirs(d4)
        part_a(rp, d1)
        part_b(rp, d2)
        part_c(rp, d3)
        part_e(rp, post, d4)
    part_d(post, tmp)

    print("=" * 68)
    if fails:
        print(f"✗ T7 FAILED, {len(fails)} item(s):")
        for f in fails:
            print(f"    - {f}")
        return 1
    print("✓ T7 PASSED: the analysis side recognizes both disguises and stops retrying; "
          "the CodeQL side keeps 3 backoff retries (the flag is enabled in one place only); "
          "ordinary exceptions still back off exponentially")
    return 0


if __name__ == "__main__":
    sys.exit(main())
