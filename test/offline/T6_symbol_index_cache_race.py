#!/usr/bin/env python3
"""T6: offline regression for concurrency defects -- cross-project symbol index
contamination plus the unlocked code_verify singleton.

Same harness pattern as T5: argparse + per-check ✓/✗ + a fails list +
`return 0 if not fails else 1`.

    python test/offline/T6_symbol_index_cache_race.py --pre-root ../legacy --post-root .

**Exit code semantics: 0 only when every defect in pre-root is reproduced as expected
AND every post-root check passes.** Both halves are required: showing the new code passes
does not prove this bug was fixed, and showing the old code fails does not prove it is fixed.

[Why old and new code can coexist in one process]
`importlib.util.spec_from_file_location` loads modules by **file path**, so the two copies of
`symbol_ops` / `code_verify` are independent module objects whose module-level globals do not
interfere. The other offline tests use the same approach.

[Determinism]
All interleavings are ordered with `threading.Event`, never with `sleep`: the race window is
created precisely by blocking in a specific function or line, so the old code always
reproduces the defect and the new code never does. No flakiness.
"""
import argparse
import dis
import importlib.util
import os
import shutil
import sys
import tempfile
import threading
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
DEFAULT_POST = HERE.parent.parent                       # this release
DEFAULT_PRE = Path(os.environ.get(
    "T6_PRE_ROOT", str(DEFAULT_POST.parent / "legacy")))  # unfixed version

SYM_REL = "analysis_agent/tools/symbol_ops.py"
VER_REL = "analysis_agent/utils/code_verify.py"

# Mutually exclusive sentinel names: they only appear if the other project's index leaked in
A_CLS, A_METHOD, A_FIELD, A_CALLEE = "AlphaOnly", "alphaMethod", "AlphaField", "alphaCallee"
B_CLS, B_METHOD, B_FIELD, B_CALLEE = "BetaOnly", "betaMethod", "BetaField", "betaCallee"


# ============================================================
#  Load: by file path, so old and new code coexist in one process
# ============================================================
def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def build_project(root: Path, pkg: str, cls: str, method: str, field: str, callee: str) -> Path:
    """Build a minimal synthetic project (4 symbol_index CSVs plus one real .java file on disk)"""
    si = root / "symbol_index"
    si.mkdir(parents=True, exist_ok=True)
    src_rel = f"src/main/java/{pkg}/{cls}.java"
    src = root / src_rel
    src.parent.mkdir(parents=True, exist_ok=True)
    # Line numbers must line up with the index: L3 class declaration (first '{'), L4 field, L6-L8 method
    src.write_text(
        f"package {pkg};\n"
        f"\n"
        f"public class {cls} {{\n"
        f"    private String {field};\n"
        f"\n"
        f"    public void {method}() {{\n"
        f'        System.out.println("{pkg}");\n'
        f"    }}\n"
        f"}}\n",
        encoding="utf-8",
    )
    qn = f"{pkg}.{cls}"

    pd.DataFrame([{
        "name": cls, "qualified_name": qn, "type_kind": "Class", "modifiers": "public",
        "annotations": "", "super_types": "", "file": src_rel,
        "start_line": 3, "annotations_start_line": 3, "end_line": 9, "body_end_line": 9,
    }]).to_csv(si / "fetch_class_details.csv", index=False)

    pd.DataFrame([
        {"name": cls, "class_qualified_name": qn, "type_kind": "Constructor",
         "return_type": "", "string_signature": f"{cls}()", "modifiers": "public",
         "annotations": "", "file": src_rel,
         "start_line": 3, "annotations_start_line": 3, "body_end_line": 3},
        {"name": method, "class_qualified_name": qn, "type_kind": "Method",
         "return_type": "void", "string_signature": f"void {method}()", "modifiers": "public",
         "annotations": "", "file": src_rel,
         "start_line": 6, "annotations_start_line": 6, "body_end_line": 8},
    ]).to_csv(si / "fetch_func_details.csv", index=False)

    pd.DataFrame([{
        "name": field, "class_qualified_name": qn, "type": "String", "detailed_type": "String",
        "modifiers": "private", "annotations": "", "file": src_rel,
        "start_line": 4, "annotations_start_line": 4, "end_line": 4,
    }]).to_csv(si / "fetch_field_details.csv", index=False)

    pd.DataFrame([{
        # Uppercase only the first letter: str.capitalize() would turn betaCallee into Betacallee
        "callee_name": callee, "callee_class": f"{pkg}.{callee[:1].upper()}{callee[1:]}Helper",
        "callee_type": "Method", "callee_return_type": "void",
        "callee_signature": f"void {callee}()", "caller_context": f"{qn}.{method}",
        "caller_file": src_rel, "caller_start_line": 7, "caller_end_line": 7,
    }]).to_csv(si / "fetch_call.csv", index=False)
    return root


def cfg(project: Path) -> dict:
    return {"configurable": {"project_data_path": str(project), "project_root": str(project)}}


# ============================================================
#  Part A -- cross-project symbol index contamination
# ============================================================
class ReadCsvGate:
    """Replace `pandas.read_csv` with a controllable gate: block when the predicate matches,
    then let the other thread finish before releasing.

    Both versions' `_safe_read_csv` call the **same** `pandas.read_csv` (the module object is
    shared), so one patch affects both old and new code.
    """

    def __init__(self, block_when):
        self.block_when = block_when        # (path:str, seen:list[int]) -> bool
        self.seen = []
        self.entered = threading.Event()    # blocked
        self.release = threading.Event()    # released
        self._real = pd.read_csv

    def __enter__(self):
        def fake(path, *a, **kw):
            p = str(path)
            self.seen.append(p)
            if self.block_when(p, self.seen):
                self.entered.set()
                self.release.wait(15)
            return self._real(path, *a, **kw)
        pd.read_csv = fake
        return self

    def __exit__(self, *exc):
        pd.read_csv = self._real
        return False


def storm_pair(mod, proj_a: Path, proj_b: Path) -> None:
    """Create the final-state mismatch "A writes `_loaded_path` first, B loads all four tables,
    then A overwrites the four tables".

    Old code: after the interleaving `_loaded_path == B` while the tables belong to A, so B
    stays permanently mismatched by the fast-path check.
    New code: keyed cache; A and B each get their own entries and never overwrite each other.
    """
    out = {}

    def run_a():
        out["a"] = mod.search_class.invoke({"name_pattern": A_CLS}, config=cfg(proj_a))

    with ReadCsvGate(lambda p, seen: "proj_A" in p and seen.count(p) == 1) as gate:
        t = threading.Thread(target=run_a)
        t.start()
        assert gate.entered.wait(15), "A did not block on index loading as expected"
        # Let B complete (the old code's _class_details_df is still None, so the guard allows it)
        out["b"] = mod.search_class.invoke({"name_pattern": B_CLS}, config=cfg(proj_b))
        gate.release.set()
        t.join(15)
    return out


def part_a_checks(mod, proj_a: Path, proj_b: Path, label: str) -> dict:
    res = {}
    storm_pair(mod, proj_a, proj_b)

    # A2: after the interleaving, a **serial** call for B must still see B's own class.
    # Anchor the assertion on the **qualified name**: the tool's "no match" branch does not echo
    # the pattern, so checking only the simple name would pass spuriously when the old error
    # text happens to contain 'BetaOnly'.
    got = mod.search_class.invoke({"name_pattern": B_CLS}, config=cfg(proj_b))
    res["A2"] = ("beta.BetaOnly" in got) and ("alpha.AlphaOnly" not in got)

    # A3: same for search_method
    got = mod.search_method.invoke({"name_pattern": B_METHOD}, config=cfg(proj_b))
    res["A3"] = ("beta.BetaOnly" in got) and ("alpha." not in got)

    # A4: same for search_usage
    got = mod.search_usage.invoke({"callee_name_pattern": B_CALLEE}, config=cfg(proj_b))
    res["A4"] = ("beta.BetaCalleeHelper" in got) and ("alpha." not in got)

    return res


def part_a5(mod, proj_a: Path, proj_b: Path) -> bool:
    """A5: **intra-call tearing** in `get_class_outline`.

    The old code has no consistency guarantee between `_find_declaration_end` (class
    declaration) and `idx.field_details` (field table). Blocking between those two points while
    B fully reloads makes a single A call return "declaration from A, fields/methods from B".
    The new code binds the four tables into one immutable bundle, so a call cannot tear.
    """
    out = {}
    real_find = mod._find_declaration_end
    hook_entered, hook_release = threading.Event(), threading.Event()

    def hooked(*a, **kw):
        hook_entered.set()
        hook_release.wait(15)
        return real_find(*a, **kw)

    mod._find_declaration_end = hooked
    try:
        t = threading.Thread(target=lambda: out.update(
            a=mod.get_class_outline.invoke({"class_name": A_CLS}, config=cfg(proj_a))))
        t.start()
        assert hook_entered.wait(15), "A did not block during class declaration parsing as expected"
        mod.search_class.invoke({"name_pattern": B_CLS}, config=cfg(proj_b))   # full B reload
        hook_release.set()
        t.join(15)
    finally:
        mod._find_declaration_end = real_find

    return A_FIELD in out.get("a", "")


def part_a67(mod, tmp: Path) -> dict:
    """A6 LRU bound / A7 structural assertion (post only; the old code has no such structure)"""
    res = {}
    res["A7"] = (hasattr(mod, "get_symbol_indices") and hasattr(mod, "_index_cache")
                 and not hasattr(mod, "_class_details_df") and not hasattr(mod, "load_symbol_indices"))
    if not res["A7"]:
        return {**res, "A6": False}

    for i in range(mod._MAX_CACHED_PROJECTS + 4):
        p = build_project(tmp / f"lru_{i}", f"lru{i}", f"Cls{i}", f"m{i}", f"f{i}", f"c{i}")
        mod.get_symbol_indices(p)
    res["A6"] = len(mod._index_cache) <= mod._MAX_CACHED_PROJECTS
    return res


# ============================================================
#  Part B -- unlocked global singleton in code_verify
# ============================================================
def last_return_line(func) -> int:
    """Locate the source line of the last return in a function using dis (without reading the
    source text).

    Note: do **not** use `Instruction.starts_line` -- since Python 3.13 it is a `bool` (it only
    says whether an instruction starts a line), so using it as a line number yields `True`.
    `code.co_lines()` is a stable interface since 3.10 and works across versions.
    """
    code = func.__code__
    starts = [(s, l) for s, _e, l in code.co_lines() if l is not None]
    starts.sort()

    def line_of(offset: int) -> int:
        best = -1
        for s, l in starts:
            if s <= offset:
                best = l
            else:
                break
        return best

    lines = [line_of(ins.offset) for ins in dis.get_instructions(code)
             if ins.opname in ("RETURN_VALUE", "RETURN_CONST")]
    return max(lines) if lines else -1


def part_b1(mod, root_a: Path, root_b: Path) -> bool:
    """B1: after obtaining B's verifier, requesting A again must still return the **same
    instance** (keyed reuse is what makes the cache meaningful)"""
    v1 = mod.get_verifier(str(root_a))
    mod.get_verifier(str(root_b))
    v2 = mod.get_verifier(str(root_a))
    return v1 is v2


def part_b2(mod, ver_path: Path, root_a: Path, root_b: Path) -> bool:
    """B2: `get_verifier(A)` must return an instance whose project_root == A (the old code can
    return B's).

    The old code's defect line is `return _current_verifier` -- it **re-reads the module
    global** after writing it. `threading.settrace` pauses A exactly **before** that line
    executes, B replaces the global, and A then reads B's instance. The new code has no such
    line (it returns a local from inside the `with` lock), so the line number never matches.
    """
    got = {}
    entered, release = threading.Event(), threading.Event()

    # Install the tracer only for the old code: the new code's `return` is **inside**
    # `with _verifier_cache_lock:`, so pausing there would hold the lock and deadlock B. The old
    # code's `return` is outside any lock (it has none), so pausing there is safe.
    use_tracer = hasattr(mod, "_current_verifier")
    line = last_return_line(mod.get_verifier) if use_tracer else -1

    def tracer(frame, event, arg):
        if (event == "line" and frame.f_lineno == line
                and Path(frame.f_code.co_filename).resolve() == ver_path):
            entered.set()
            release.wait(15)
        return tracer

    if use_tracer:
        threading.settrace(tracer)
    try:
        t = threading.Thread(target=lambda: got.update(a=mod.get_verifier(str(root_a))))
        t.start()
        hit = entered.wait(3)
        # Run B either way; when the defect line is hit, this is exactly the "rewrite the global" step
        v_b = mod.get_verifier(str(root_b))
        release.set()
        t.join(15)
    finally:
        if use_tracer:
            threading.settrace(None)

    v_a = got.get("a")
    if v_a is None:
        return False
    if hit:      # old code: paused at the return line -> after resuming it must still get its own
        return Path(str(v_a.project_root)).resolve() == root_a.resolve()
    # new code (line never hit): A and B must each get their own, distinct instances
    return (Path(str(v_a.project_root)).resolve() == root_a.resolve()
            and Path(str(v_b.project_root)).resolve() == root_b.resolve()
            and v_a is not v_b)


def part_b2_stress(mod, root_a: Path, root_b: Path, rounds: int = 200) -> bool:
    """B2 supplement: 8 threads alternate between A and B; every returned verifier must belong
    to the requester"""
    bad = []
    lock = threading.Lock()

    def worker(k):
        root = root_a if k % 2 == 0 else root_b
        for _ in range(rounds):
            v = mod.get_verifier(str(root))
            if Path(str(v.project_root)).resolve() != root.resolve():
                with lock:
                    bad.append((k, str(root), str(v.project_root)))
                return

    ts = [threading.Thread(target=worker, args=(k,)) for k in range(8)]
    [t.start() for t in ts]
    [t.join(60) for t in ts]
    return not bad


def part_b4(mod) -> bool:
    return (hasattr(mod, "_verifier_cache") and hasattr(mod, "clear_verifier_cache")
            and not hasattr(mod, "_current_verifier"))


# ============================================================
#  Driver
# ============================================================
POST_ONLY = {"A6", "A7", "B4"}
PRE_EXPECTED_FAIL = {"A2", "A3", "A4", "A5", "B1", "B2"}


def run_side(root: Path, tag: str, results: dict, verbose: bool) -> None:
    tmp = Path(tempfile.mkdtemp(prefix=f"t6_{tag}_"))
    try:
        mod = load_module(root / SYM_REL, f"t6_{tag}_symbol_ops")
        ver = load_module(root / VER_REL, f"t6_{tag}_code_verify")
        proj_a = build_project(tmp / "proj_A", "alpha", A_CLS, A_METHOD, A_FIELD, A_CALLEE)
        proj_b = build_project(tmp / "proj_B", "beta", B_CLS, B_METHOD, B_FIELD, B_CALLEE)

        results.update(part_a_checks(mod, proj_a, proj_b, tag))
        results["A5"] = part_a5(mod, proj_a, proj_b)
        if tag == "post":
            results.update(part_a67(mod, tmp))

        results["B1"] = part_b1(ver, proj_a, proj_b)
        results["B2"] = (part_b2(ver, (root / VER_REL).resolve(), proj_a, proj_b)
                         and part_b2_stress(ver, proj_a, proj_b))
        if tag == "post":
            results["B4"] = part_b4(ver)

        if verbose:
            for k in sorted(results):
                print(f"    {k}: {'✓' if results[k] else '✗'}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="T6 offline regression for concurrency defects (index contamination + unlocked singleton)")
    ap.add_argument("--pre-root", default=str(DEFAULT_PRE), help="root of the unfixed version (default ./legacy sibling)")
    ap.add_argument("--post-root", default=str(DEFAULT_POST), help="root of the fixed version (default: this release)")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    pre, post = Path(args.pre_root).resolve(), Path(args.post_root).resolve()
    # Both module copies resolve shared dependencies through post-root (codeql_ops /
    # analysis_agent.* are identical across the two versions). The script directory is sys.path[0],
    # so without this insert `from codeql_ops...` would raise ImportError.
    sys.path.insert(0, str(post))
    for root, tag in ((pre, "pre"), (post, "post")):
        for rel in (SYM_REL, VER_REL):
            if not (root / rel).exists():
                print(f"✗ missing input file: {root / rel}")
                return 2

    print(f"pre -root : {pre}")
    print(f"post-root : {post}")
    pre_res, post_res = {}, {}
    print("\n[pre] expected: defects reproduced")
    run_side(pre, "pre", pre_res, not args.quiet)
    print("\n[post] expected: all checks pass")
    run_side(post, "post", post_res, not args.quiet)

    fails = []
    print("\n-- verdict --")
    for k in sorted(PRE_EXPECTED_FAIL):
        got = pre_res.get(k)
        ok = got is False
        print(f"  {k}: pre {'defect reproduced ✓' if ok else 'not reproduced ✗'} / post {'passed ✓' if post_res.get(k) else 'failed ✗'}")
        if not ok:
            fails.append(f"{k}-pre-not-reproduced")
        if not post_res.get(k):
            fails.append(f"{k}-post-failed")
    for k in sorted(POST_ONLY):
        ok = bool(post_res.get(k))
        print(f"  {k}: post-only {'passed ✓' if ok else 'failed ✗'}")
        if not ok:
            fails.append(f"{k}-post-failed")

    print()
    if fails:
        print(f"✗ T6 FAILED: {sorted(set(fails))}")
        return 1
    print("✓ T6 PASSED: all defects reproduced on old code and gone on new code (index contamination + unlocked singleton)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
