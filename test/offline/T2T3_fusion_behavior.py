#!/usr/bin/env python3
"""
T2 + T3 -- behavior invariants and decision rules for the fusion "mapping module"
(zero LLM; everything is a local stub).

T2 Behavioral equivalence: whether round 2 (mapping/provenance) succeeds, is partial,
fails, or is disabled by the switch, the kept list returned by `fusion_dedup_specs` must be
element-wise identical -- this is the hard invariant. Also asserts that
FUSION_GROUP_MAPPING=0 writes no additional files (legacy behavior).

T3 Decision rules: assert the handling of six illegal/boundary cases in round-2 output
(retry / partial / failed).

A0 Source guard: the two round-1 fusion prompt constants must remain byte-identical to the
baseline release's prompt module.

Usage: python T2T3_fusion_behavior.py [--baseline <baseline_root>]

The baseline root can also be supplied via T2T3_BASELINE_ROOT; A0 is skipped when it is absent.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

VERSION_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(VERSION_ROOT))

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage  # noqa: E402

from analysis_agent import fusion  # noqa: E402
from global_data_model.analysis_result import (  # noqa: E402
    ArgumentPattern,
    FusionDedupResult,
    FusionGroup,
    FusionGroupsResult,
    GroundTruthExample,
    SinkSpecification,
    SourceSpecification,
)

DEFAULT_BASELINE = Path(os.environ.get(
    "T2T3_BASELINE_ROOT", str(VERSION_ROOT.parent / "baseline")))


# ---------------------------------------------------------------- Fixtures
def make_spec(spec_id: str, role: str, desc: str, direction: str):
    gt = [GroundTruthExample(is_from_project=False, explanation="fixture", code_snippet=["x"])]
    if role == "source":
        return SourceSpecification(
            spec_id=spec_id, description=desc, security_reason="r",
            ground_truth_examples=gt, origin_direction=direction,
            node_pattern=ArgumentPattern(matching_description=desc),
        )
    return SinkSpecification(
        spec_id=spec_id, description=desc, security_reason="r",
        ground_truth_examples=gt, origin_direction=direction,
        node_pattern=ArgumentPattern(matching_description=desc),
    )


def make_specs():
    return [
        make_spec("d01_source_01", "source", "source of D01", "D01:validation side"),
        make_spec("d01_sink_01", "sink", "sink A of D01", "D01:validation side"),
        make_spec("d02_sink_01", "sink", "sink A of D02", "D02:trigger side"),
        make_spec("d02_sink_02", "sink", "sink B of D02", "D02:trigger side"),
        make_spec("d03_sink_01", "sink", "sink A of D03", "D03:business side"),
        make_spec("d03_sink_02", "sink", "sink B of D03", "D03:business side"),
    ]


DISCARDED = ["d01_sink_01", "d02_sink_02"]


# ---------------------------------------------------------------- Stub LLM
class _StubRunnable:
    def __init__(self, llm: "_StubLLM", model):
        self.llm = llm
        self.model = model

    def invoke(self, messages):
        return self.llm._next(self.model, messages)


class _StubLLM:
    """Emit scripted structured outputs in call order; each step may be valid, invalid or raise."""

    def __init__(self, script: List[Dict[str, Any]]):
        self.script = list(script)
        self.calls: List[Any] = []

    def with_structured_output(self, model, method=None, include_raw=False):
        return _StubRunnable(self, model)

    def _next(self, model, messages):
        self.calls.append((model, messages))
        if not self.script:
            raise AssertionError("stub script exhausted: more calls than expected")
        step = self.script.pop(0)
        if step["kind"] == "raise":
            raise RuntimeError(step.get("error", "stub error"))
        if step["kind"] == "parse_fail":
            return {"raw": AIMessage(content="not json"), "parsed": None,
                    "parsing_error": "stub parse error"}
        parsed = step["parsed"]
        if parsed is not None and not isinstance(parsed, model):
            if not isinstance(parsed, model):
                raise AssertionError(f"scripted object is not a {model.__name__}: {type(parsed)}")
        return {"raw": AIMessage(content=json.dumps(step.get("raw_json", {}), ensure_ascii=False)),
                "parsed": parsed, "parsing_error": None}


def round1_step(discarded: List[str]) -> Dict[str, Any]:
    parsed = FusionDedupResult(discarded_spec_ids=list(discarded))
    return {"kind": "ok", "parsed": parsed, "raw_json": {"discarded_spec_ids": list(discarded)}}


def round2_step(groups: List[Dict[str, Any]], unmapped: List[str]) -> Dict[str, Any]:
    parsed = FusionGroupsResult(
        groups=[FusionGroup(**g) for g in groups], unmapped=list(unmapped))
    return {"kind": "ok", "parsed": parsed,
            "raw_json": {"groups": groups, "unmapped": unmapped}}


def run_fusion(script: List[Dict[str, Any]], log_dir: Optional[str], mapping_on: bool):
    os.environ["FUSION_GROUP_MAPPING"] = "1" if mapping_on else "0"
    llm = _StubLLM(script)
    specs = make_specs()
    kept = fusion.fusion_dedup_specs(specs, llm, log_dir)
    return kept, llm


# ---------------------------------------------------------------- A0 Source guard
def check_a0(baseline_root: Path) -> Optional[str]:
    """The whole module containing the round-1 prompts must be byte-identical to the
    baseline release (a stronger guarantee than comparing two constants: any change to
    `result_extract_prompt.py`, including added constants, is caught).
    The round-2 prompts deliberately live in a separate module `fusion_mapping_prompt.py`."""
    base_file = baseline_root / "analysis_agent" / "prompts" / "result_extract_prompt.py"
    cur_file = VERSION_ROOT / "analysis_agent" / "prompts" / "result_extract_prompt.py"
    if not base_file.exists():
        return f"{base_file} not found; A0 skipped"
    a = hashlib.sha256(base_file.read_bytes()).hexdigest()
    b = hashlib.sha256(cur_file.read_bytes()).hexdigest()
    if a != b:
        return f"A0 failed: result_extract_prompt.py is no longer byte-identical to the baseline ({a[:12]} vs {b[:12]})"
    return None


# ---------------------------------------------------------------- T2
def test_t2(tmp: Path) -> List[str]:
    fails: List[str] = []
    legal = [round2_step(
        [{"discarded_spec_id_list": ["d01_sink_01"], "kept_spec_id": "d03_sink_01",
          "spec_desc": "both are sink A"},
         {"discarded_spec_id_list": ["d02_sink_02"], "kept_spec_id": "d03_sink_02",
          "spec_desc": "both are sink B"}], [])]

    boom = {"kind": "raise", "error": "stub boom"}
    kept_on, _ = run_fusion([round1_step(DISCARDED), *legal], str(tmp / "on"), True)
    kept_off, _ = run_fusion([round1_step(DISCARDED)], str(tmp / "off"), False)
    kept_fail, _ = run_fusion([round1_step(DISCARDED), boom, boom, boom], str(tmp / "fail"), True)

    ids_on = [s.spec_id for s in kept_on]
    if ids_on != [s.spec_id for s in kept_off]:
        fails.append(f"T2: mapping switch changed kept (on={ids_on})")
    if ids_on != [s.spec_id for s in kept_fail]:
        fails.append(f"T2: round-2 failure changed kept (fail={[s.spec_id for s in kept_fail]})")
    expect_kept = [s.spec_id for s in make_specs() if s.spec_id not in DISCARDED]
    if ids_on != expect_kept:
        fails.append(f"T2: kept differs from the frozen round-1 result (got={ids_on} want={expect_kept})")

    on_files = {p.name for p in (tmp / "on").glob("*.json")}
    off_files = {p.name for p in (tmp / "off").glob("*.json")}
    if "fusion_groups.json" not in on_files:
        fails.append("T2: fusion_groups.json not written when the switch is on")
    if "fusion_discarded_specs.json" not in on_files:
        fails.append("T2: fusion_discarded_specs.json not written when the switch is on")
    new_in_off = off_files - {"fusion_dedup_prompt.json", "tries_1_response.json"}
    if new_in_off:
        fails.append(f"T2: new files written while the switch is off: {sorted(new_in_off)}")

    groups = json.loads((tmp / "on" / "fusion_groups.json").read_text(encoding="utf-8"))
    if groups.get("status") != "ok":
        fails.append(f"T2: expected status=ok, got {groups.get('status')}")
    if sorted(groups.get("unmapped", [])) != []:
        fails.append(f"T2: expected empty unmapped, got {groups.get('unmapped')}")
    disc = json.loads((tmp / "on" / "fusion_discarded_specs.json").read_text(encoding="utf-8"))
    if sorted(i["spec_id"] for i in disc["items"]) != sorted(DISCARDED):
        fails.append("T2: entries in fusion_discarded_specs.json do not match the discarded set")
    return fails


# ---------------------------------------------------------------- T3
def _mapping_result(script_variants: List[List[Dict[str, Any]]], tmp: Path) -> Dict[str, Any]:
    """Run mapping once per script variant and return the last fusion_groups.json content."""
    for i, variant in enumerate(script_variants):
        d = tmp / f"m{i}"
        kept, _ = run_fusion([round1_step(DISCARDED), *variant], str(d), True)
        kept_ids = [s.spec_id for s in kept]
        expect = [s.spec_id for s in make_specs() if s.spec_id not in DISCARDED]
        if kept_ids != expect:
            raise AssertionError(f"variant {i} changed kept: {kept_ids}")
        out = json.loads((d / "fusion_groups.json").read_text(encoding="utf-8"))
        out["_kept"] = kept_ids
    return out


def test_t3(tmp: Path) -> List[str]:
    fails: List[str] = []

    def case(name: str, script: List[Dict[str, Any]], expect_status: str,
             expect_unmapped: Optional[List[str]] = None, expect_groups: int = 0):
        d = tmp / name
        kept, _ = run_fusion([round1_step(DISCARDED), *script], str(d), True)
        expect_kept = [s.spec_id for s in make_specs() if s.spec_id not in DISCARDED]
        if [s.spec_id for s in kept] != expect_kept:
            fails.append(f"T3[{name}]: kept was changed")
        got = json.loads((d / "fusion_groups.json").read_text(encoding="utf-8"))
        if got.get("status") != expect_status:
            fails.append(f"T3[{name}]: expected status {expect_status}, got {got.get('status')} "
                         f"(error={got.get('error')})")
        if expect_unmapped is not None and sorted(got.get("unmapped", [])) != sorted(expect_unmapped):
            fails.append(f"T3[{name}]: expected unmapped {sorted(expect_unmapped)}, "
                         f"got {sorted(got.get('unmapped', []))}")
        if len(got.get("groups", [])) != expect_groups:
            fails.append(f"T3[{name}]: expected {expect_groups} groups, got {len(got.get('groups', []))}")
        # Hard invariant: groups union unmapped equals the frozen discarded set
        covered = {x for g in got.get("groups", []) for x in g["discarded_spec_id_list"]}
        covered |= set(got.get("unmapped", []))
        if covered != set(DISCARDED):
            fails.append(f"T3[{name}]: coverage invariant broken {sorted(covered)} != {sorted(DISCARDED)}")

    ok_script = round2_step(
        [{"discarded_spec_id_list": DISCARDED, "kept_spec_id": "d03_sink_01",
          "spec_desc": "same class of sink"}], [])

    # 1) hallucinated kept id -> retry then valid
    case("hallucinated", [round2_step([{"discarded_spec_id_list": DISCARDED,
                                        "kept_spec_id": "d99_sink_99", "spec_desc": "x"}], []),
                          ok_script],
         expect_status="ok", expect_unmapped=[], expect_groups=1)
    # 2) cross-role pairing -> retry then valid
    case("cross_role", [round2_step([{"discarded_spec_id_list": DISCARDED,
                                      "kept_spec_id": "d01_source_01", "spec_desc": "x"}], []),
                         ok_script],
         expect_status="ok", expect_unmapped=[], expect_groups=1)
    # 3) same id in multiple groups -> retry then valid
    case("dup_membership", [round2_step([{"discarded_spec_id_list": ["d01_sink_01"],
                                          "kept_spec_id": "d03_sink_01", "spec_desc": "x"},
                                         {"discarded_spec_id_list": ["d01_sink_01"],
                                          "kept_spec_id": "d03_sink_02", "spec_desc": "y"}], []),
                            ok_script],
         expect_status="ok", expect_unmapped=[], expect_groups=1)
    # 4) kept_spec_id inside the discarded set -> retry then valid
    case("kept_in_discard", [round2_step([{"discarded_spec_id_list": DISCARDED,
                                           "kept_spec_id": "d02_sink_02", "spec_desc": "x"}], []),
                             ok_script],
         expect_status="ok", expect_unmapped=[], expect_groups=1)
    # 5) incomplete coverage (one item missing and not in unmapped) -> partial; missing items
    #    are filled into unmapped without a retry
    case("partial", [round2_step([{"discarded_spec_id_list": ["d01_sink_01"],
                                   "kept_spec_id": "d03_sink_01", "spec_desc": "x"}], [])],
         expect_status="partial", expect_unmapped=["d02_sink_02"], expect_groups=1)
    # 6) nothing can be paired -> no_pairs (variants run in turn; the last one takes effect)
    case("no_pairs", [round2_step([], DISCARDED)],
         expect_status="no_pairs", expect_unmapped=DISCARDED, expect_groups=0)
    # 7) three invalid attempts -> failed; unmapped = the whole discarded set
    bad = round2_step([{"discarded_spec_id_list": DISCARDED,
                        "kept_spec_id": "d99_sink_99", "spec_desc": "x"}], [])
    case("all_illegal", [bad, bad, bad],
         expect_status="failed", expect_unmapped=DISCARDED, expect_groups=0)
    # 8) three exceptions -> failed; unmapped = the whole discarded set
    boom = {"kind": "raise", "error": "stub boom"}
    case("all_raise", [boom, boom, boom],
         expect_status="failed", expect_unmapped=DISCARDED, expect_groups=0)
    # 9) parse failure -> retry then valid
    case("parse_fail", [{"kind": "parse_fail"}, ok_script],
         expect_status="ok", expect_unmapped=[], expect_groups=1)
    return fails


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default=str(DEFAULT_BASELINE),
                    help="baseline release root used by the A0 prompt guard")
    args = ap.parse_args()

    all_fails: List[str] = []
    print("== A0 Source guard: round-1 fusion prompt constants ==")
    a0 = check_a0(Path(args.baseline))
    if a0 and a0.startswith("A0 failed"):
        all_fails.append(a0)
    print(f"  {a0 or 'A0 ok: byte-identical to the baseline'}")

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        print("== T2 Behavioral equivalence ==")
        t2 = test_t2(tmp)
        for f in t2:
            print(f"  ✗ {f}")
        all_fails += t2
        if not t2:
            print("  ✓ kept is element-wise identical with the switch on, off and after round-2 failure; written files match expectations")

        print("== T3 Decision rules ==")
        t3 = test_t3(tmp)
        for f in t3:
            print(f"  ✗ {f}")
        all_fails += t3
        if not t3:
            print("  ✓ hallucination/cross-role/duplicate membership/kept-in-discarded -> retry; "
                  "incomplete coverage -> partial; no pairs -> no_pairs; three invalid or raising attempts -> failed; "
                  "kept unchanged in every case")

    print(f"\nResult: {'all passed' if not all_fails else f'{len(all_fails)} failed'}")
    return 0 if not all_fails else 1


if __name__ == "__main__":
    raise SystemExit(main())
