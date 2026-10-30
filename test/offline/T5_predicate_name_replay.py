#!/usr/bin/env python3
"""
T5 -- deterministic offline replay of the predicate-name normalization fix
(no LLM / no database needed).

Why it exists: a real run reported
    ERROR: could not resolve predicate is_d01_summary_01 (VulDetectLib.qll:1848)
The root cause was that **predicate-name normalization applied only on the execution path,
not on the persisted path**: the LLM emits `predicate is_summary_01(...)`;
`ScriptBuilder.build()` rewrites it to `is_d01_summary_01` only when wrapping the execution
script, while `SpecResult.predicate_code` and the persisted
`codeql_agent_spec_scripts.json` keep the original name. The assembler writes the definition
block verbatim (`_predicate_block`) but builds references as `f"is_{spec_id}"`, so the
definition name != the reference name.

This bug appeared only once in 161 cases / 9679 predicates, so a re-run cannot verify the
fix reliably. Instead, this script replays **saved real trigger artifacts**: the same input
goes through the pre-fix and post-fix assembler code paths, asserting the failure before and
the success after. The fix is thereby **demonstrated**, not hoped for.

Four assertions:
  A0 Fidelity: the **pre-fix** definition block reconstructed from the persisted JSON is
     byte-identical to the historical `VulDetectLib.qll` (the real artifact), so A1/A2
     exercise the production path rather than an equivalent re-implementation in the test.
  A1 Text invariant: pre-fix definition names do NOT cover the reference names (missing
     `is_d01_summary_01`); post-fix they do; and only 1 line differs (minimal change).
  A2 Real compile (`codeql query compile`; **compile only, no DB, no query evaluation
     cache**): the pre-fix path reproduces `could not resolve predicate
     is_d01_summary_01`; the post-fix path exits 0.
  A3 Defense layer: the post-fix assembler logs a **named** error for a non-conforming
     definition (change 3 takes effect).

Usage:
    python test/offline/T5_predicate_name_replay.py \
        [--run <run_dir>] [--codeql <cli>] [--skip-compile] [--keep-tmp]
"""
from __future__ import annotations

import argparse
import contextlib
import difflib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

VERSION_ROOT = Path(__file__).resolve().parents[2]          # release root
V2_ROOT = VERSION_ROOT.parent                               # parent directory (legacy trees live here)
sys.path.insert(0, str(VERSION_ROOT))                       # import this release's own package
sys.path.insert(0, str(V2_ROOT))                            # same order as production (agent.py is a package import)

from codeql_agent.assembler import ConfigAssembler as AssemblerCurrent   # noqa: E402
from codeql_agent.script_builder import PREDICATE_HEAD_RE             # noqa: E402


# Default input is a **recorded pre-fix archive**, not a live run directory: re-running the case
# with the fixed version emits conforming JSON, so the pre-fix defect would no longer be
# reproducible. The archive must be produced by an older, unfixed version.
DEFAULT_RUN = Path(os.environ.get(
    "T5_RUN_DIR",
    str(VERSION_ROOT / "test/data/predicate_name_run"),
))
# Pre-fix assembler implementation, kept outside this release (path sanitized via env var).
LEGACY_ASSEMBLER = Path(os.environ.get(
    "T5_LEGACY_ASSEMBLER",
    str(V2_ROOT / "legacy/codeql_agent/assembler.py"),
))
DEFAULT_CODEQL = os.environ.get("CODEQL_BIN", "codeql")
BROKEN_REF = "is_d01_summary_01"        # reference name missing in this case (always missing pre-fix)

HEADER = (
    "import java\n"
    "import semmle.code.java.dataflow.DataFlow\n"
    "import semmle.code.java.dataflow.ExternalFlow\n"
    "import semmle.code.java.dataflow.TaintTracking\n"
)
# Same call order as ConfigAssembler.assemble()
ROLE_ORDER = (("Source", "source"), ("Sink", "sink"), ("FlowStep", "flow_step"), ("Summary", "summary"))
# assemble() joins fragments with "\n\n", and each definition block itself ends with
# "\n\n", so the definition and configuration sections are separated by 4 newlines
# (2 blank lines). Reproduce this exactly; do not normalize with rstrip (that would drop
# 2 blank lines and make the A0 byte comparison fail spuriously).
DEFS_CFG_JOIN = "\n\n"


def load_module(name: str, path: Path):
    """Load a module by file path (used to import the legacy assembler read-only).

    Note: the legacy `assembler.py` imports `from codeql_agent.codeql_agent_data import
    SpecResult`, which resolves to the module of the same name on sys.path. That file is
    byte-identical across versions, so the replay semantics are unaffected.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def build_shims(specs_json: dict) -> dict:
    """The persisted JSON only stores role / predicate_code, so feed duck-typed shells to
    _predicate_block.

    _predicate_block only reads `.predicate_code` / `.spec_id` / `.role`; it needs neither a
    real SpecResult nor SummarySpecification.mapping_type (the reference section is produced
    by _config_class, and the fix does not touch it).
    """
    by_role: dict = {}
    for sid, v in specs_json.items():
        by_role.setdefault(v["role"], []).append(
            SimpleNamespace(spec_id=sid, role=v["role"], predicate_code=v["predicate_code"])
        )
    return by_role


def defs_part(predicate_block, by_role: dict) -> str:
    """Build the definition section the way assemble() does (the part before
    `module VulDetectConfig` in the library)."""
    parts = [HEADER]
    for label, role in ROLE_ORDER:
        specs = by_role.get(role, [])
        if not specs:
            continue
        block = predicate_block(specs, label)
        if block:
            parts.append(block)
    return "\n\n".join(parts)


def def_names(text: str) -> set:
    return {m.group(2) for m in PREDICATE_HEAD_RE.finditer(text)}


def ref_names(all_spec_ids) -> set:
    """Upper bound on reference names: every spec may be referenced as is_<spec_id>.

    In practice a summary is referenced only when mapping_type is known (otherwise the
    assembler writes `false // unknown mapping_type`), and the persisted JSON does not store
    mapping_type, so this takes the upper bound. That makes the check **stricter**: the real
    reference set is a subset, so "upper bound is covered by definitions" implies
    "references are covered by definitions". In this case is_d01_summary_01 really is
    referenced (the historical analysis.log error proves it).
    """
    return {f"is_{sid}" for sid in all_spec_ids}


def compile_one(codeql_bin: str, work_dir: Path, lib_text: str, timeout: int = 900):
    """Compile the candidate library in a temporary qlpack -- compile only, no DB and no
    query evaluation cache.

    The directory layout mirrors the production work_dir:
    <tmp>/qlpack.yml + <tmp>/taint_analysis/{Lib,Query}.
    """
    tmp = Path(tempfile.mkdtemp(prefix="t5_replay_"))
    d = tmp / "taint_analysis"
    d.mkdir(parents=True)
    shutil.copy2(work_dir / "qlpack.yml", tmp / "qlpack.yml")
    shutil.copy2(work_dir / "taint_analysis/TaintAnalysis.ql", d / "TaintAnalysis.ql")
    (d / "VulDetectLib.qll").write_text(lib_text, encoding="utf-8")
    try:
        p = subprocess.run(
            [codeql_bin, "query", "compile", str(d / "TaintAnalysis.ql")],
            capture_output=True, text=True, timeout=timeout,
        )
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip(), tmp
    except subprocess.TimeoutExpired:
        return 124, f"compile timed out ({timeout}s)", tmp


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default=str(DEFAULT_RUN), help="run/archive directory that triggered the bug")
    ap.add_argument("--codeql", default=DEFAULT_CODEQL)
    ap.add_argument("--skip-compile", action="store_true", help="skip A2 (when no CodeQL environment is available)")
    ap.add_argument("--keep-tmp", action="store_true", help="keep the temporary qlpack directories for inspection")
    args = ap.parse_args()

    run = Path(args.run)
    specs_path = run / "outputs/codeql_agent_spec_scripts.json"
    lib_path = run / "work_dir/taint_analysis/VulDetectLib.qll"
    work_dir = run / "work_dir"
    for p in (specs_path, lib_path, work_dir / "qlpack.yml",
              work_dir / "taint_analysis/TaintAnalysis.ql"):
        if not p.exists():
            print(f"✗ missing input file: {p}")
            return 2

    fails, notes = [], []

    # ---------- Input ----------
    specs_json = json.loads(specs_path.read_text(encoding="utf-8"))
    by_role = build_shims(specs_json)
    lib = lib_path.read_text(encoding="utf-8")
    cut = lib.index("module VulDetectConfig")
    hist_defs, hist_cfg = lib[:cut], lib[cut:]
    n_specs = len(specs_json)
    print(f"Input: {run}")
    print(f"  {n_specs} specs ("
          + " / ".join(f"{role} {len(by_role.get(role, []))}" for _, role in ROLE_ORDER) + ")")
    print(f"  historical library {lib.count(chr(10)) + 1} lines; definition section {hist_defs.count(chr(10)) + 1} lines\n")

    # ---------- Pre-fix / post-fix definition sections ----------
    asm_legacy = load_module("assembler_legacy_readonly", LEGACY_ASSEMBLER)
    pre = defs_part(asm_legacy.ConfigAssembler._predicate_block, by_role)

    # The post-fix path emits the defense-layer log; capture it and echo it verbatim so the
    # log is neither lost nor hard to assert on
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        post = defs_part(AssemblerCurrent._predicate_block, by_role)
    captured = buf.getvalue()
    if captured.strip():
        print(captured.rstrip())
        print()

    pre_full = pre + DEFS_CFG_JOIN + hist_cfg
    post_full = post + DEFS_CFG_JOIN + hist_cfg

    # ---------- A0 Fidelity ----------
    print("A0 Fidelity (reconstructed pre-fix section vs historical artifact)")
    if pre_full != lib:
        notes.append("reconstructed full library differs from the historical library")
        dif = [l.rstrip() for l in difflib.unified_diff(
            lib.splitlines(True), pre_full.splitlines(True), n=0) if l[:1] in "+-" and l[:3] not in ("---", "+++")]
        print(f"  ✗ {len(dif)} differing lines; first 6:")
        for l in dif[:6]:
            print(f"      {l}")
        fails.append("A0")
    else:
        print(f"  ✓ reconstructed definitions + historical references == historical library "
              f"(byte-identical, {len(lib)} chars / {lib_path.stat().st_size} bytes)"
              f" => A1/A2 really exercise the production path")

    # ---------- A1 Text invariant ----------
    print("\nA1 Text invariant: definition names cover reference names")
    refs = ref_names(specs_json.keys())
    d_pre, d_post = def_names(pre), def_names(post)
    miss_pre, stray_pre = sorted(refs - d_pre), sorted(d_pre - refs)
    miss_post, stray_post = sorted(refs - d_post), sorted(d_post - refs)

    diff_lines = [l for l in difflib.unified_diff(pre.splitlines(True), post.splitlines(True), n=0)
                  if l[:1] in "+-" and l[:3] not in ("---", "+++")]
    print(f"  reference names: {len(refs)}")
    print(f"  pre-fix:  {len(d_pre)} definitions; missing {miss_pre}; stray (not a reference name) {stray_pre}")
    print(f"  post-fix: {len(d_post)} definitions; missing {miss_post}; stray {stray_post}")
    print(f"  differing lines before/after = {len(diff_lines)} (expected 2 = one add and one removal, i.e. minimal change)")

    if not miss_pre:
        notes.append("pre-fix path did not reproduce the missing name (the artifact may not be the trigger for this bug)")
        fails.append("A1-pre")
    if miss_post or stray_post:
        fails.append("A1-post")
    if len(diff_lines) != 2:
        fails.append("A1-minimal")
    if "A1-pre" not in fails and "A1-post" not in fails and "A1-minimal" not in fails:
        print(f"  ✓ pre-fix definitions do not cover references (missing {miss_pre}); post-fix they do; only 1 line differs")

    # ---------- A3 Defense layer ----------
    print("\nA3 Defense layer: named error logged for a non-conforming definition")
    if "Assembly fallback rename" in captured and "d01_summary_01" in captured:
        print("  ✓ captured the named error log (including spec_id); the defense layer works on production data")
    else:
        # Require the log only when the pre-fix path is actually non-conforming
        if not miss_pre:
            print("  - no non-conforming definition, so the defense log should not appear (skipped)")
        else:
            print("  ✗ expected named error log was not captured")
            fails.append("A3")

    # ---------- A2 Real compile ----------
    if args.skip_compile:
        print("\nA2 Real compile: skipped (--skip-compile)")
    else:
        print(f"\nA2 Real compile ({args.codeql} query compile; no DB)")
        rc_pre, out_pre, tmp_pre = compile_one(args.codeql, work_dir, lib)
        ok_pre = rc_pre != 0 and "could not resolve predicate" in out_pre and BROKEN_REF in out_pre
        tail = [l for l in out_pre.splitlines() if "ERROR" in l or "could not" in l][:2]
        print(f"  pre-fix:  exit={rc_pre} (expected != 0 with 'could not resolve predicate')")
        for l in tail:
            print(f"      {l}")
        print("      ✓ reproduced" if ok_pre else "      ✗ not reproduced")
        if not ok_pre:
            fails.append("A2-pre")

        rc_post, out_post, tmp_post = compile_one(args.codeql, work_dir, post_full)
        ok_post = rc_post == 0
        print(f"  post-fix: exit={rc_post} (expected 0)" + ("  ✓" if ok_post else "  ✗"))
        if not ok_post:
            for l in out_post.splitlines()[:6]:
                print(f"      {l}")
            fails.append("A2-post")

        if not args.keep_tmp:
            shutil.rmtree(tmp_pre, ignore_errors=True)
            shutil.rmtree(tmp_post, ignore_errors=True)
        else:
            print(f"  temporary directories kept: {tmp_pre} / {tmp_post}")

    # ---------- Conclusion ----------
    print("\n" + "=" * 76)
    if fails:
        print(f"✗ T5 FAILED: {sorted(set(fails))}")
        for n in notes:
            print(f"  note: {n}")
        return 1
    print("✓ T5 PASSED: reproduced pre-fix, gone post-fix, and the change is 1 line"
          + (" (A2 skipped)" if args.skip_compile else " (including real compilation)"))
    for n in notes:
        print(f"  note: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
