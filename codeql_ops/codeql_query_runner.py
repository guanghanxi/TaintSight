"""
CodeQL preprocessing queries.

Before the Analysis Agent starts, run the six symbol/location index scripts in
batch and write their results to <project_slug>/symbol_index/{script_name}.csv
for the symbol_ops tools and downstream validation.

Directory layout:
{repo_root}/codeql_scripts/              <- six .ql files + qlpack.yml (resolved relative to this module)
<project_slug>/
├── symbol_index/{script_name}.csv       <- index results (flat storage, consumed by pandas)
└── codeql_logs/{script_name}.log        <- execution logs (kept separate from data)
"""
import os
import csv
import shutil
import argparse
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib, json
from datetime import datetime
from logger import StdoutLogger
from codeql_ops.proc_utils import run_codeql

# Stdout Log Phase
STDOUT_LOG_PHASE = "codeql_query_runner"

# ==========================================
# 1. Constants and path conventions (single source of truth)
# ==========================================
# Six preprocessing scripts:
#   4 symbol indexes (consumed by symbol_ops) + 2 location indexes (consumed by validation)
PREPROCESS_SCRIPTS: List[str] = [
    "fetch_class_details",
    "fetch_func_details",
    "fetch_field_details",
    "fetch_call",
    "fetch_class_locs",
    "fetch_func_locs",
]

DEFAULT_CODEQL_BIN = os.environ.get("CODEQL_BIN", "codeql")

# codeql_scripts directory: resolved from *this module's file* location.
# Layout:
#   {repo_root}/codeql_scripts/
#   {repo_root}/codeql_ops/codeql_query_runner.py
# parents[0] = codeql_ops, parents[1] = repo_root
CODEQL_SCRIPT_DIR: Path = Path(__file__).resolve().parents[1] / "codeql_scripts"

# Output subdirectories (under project_data_path / output_path)
SYMBOL_INDEX_DIR = "symbol_index"   # index CSVs (pure data)
CODEQL_LOG_DIR = "codeql_logs"      # execution logs (kept separate from data)

# Fingerprint file path
MANIFEST_NAME = ".manifest.json"

def get_index_csv_path(project_data_path: str, script_name: str) -> str:
    """Single entry point for index CSV paths; shared by the runner (write) and symbol_ops (read) to prevent path drift."""
    return str(Path(project_data_path) / SYMBOL_INDEX_DIR / f"{script_name}.csv")


def count_index_rows(project_data_path: str, script_name: str) -> int:
    """
    Count data rows in an index CSV (excluding the header); 0 if missing, empty or unreadable.

    Used as the "project method count" denominator of the CodeQL Agent's match
    cardinality gate (script_name="fetch_func_locs"). Count with csv.reader rather
    than readlines to handle quoted fields containing newlines. All exceptions are
    swallowed and return 0: a missing index may only degrade the gate to a pure
    absolute threshold; it must never become a new failure point.
    """
    path = Path(get_index_csv_path(project_data_path, script_name))
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            next(reader, None)          # skip the header
            return sum(1 for _ in reader)
    except Exception:
        return 0


def get_missing_indices(project_data_path: str, scripts: Optional[List[str]] = None) -> List[str]:
    """Return script names whose index CSV is missing or empty, so the caller can decide whether to run preprocessing."""
    target = scripts or PREPROCESS_SCRIPTS
    return [
        name for name in target
        if not (lambda p: p.exists() and p.stat().st_size > 0)(Path(get_index_csv_path(project_data_path, name)))
    ]


class CodeQLQueryError(RuntimeError):
    """A CodeQL query failed to execute."""


# ==========================================
# 2. Running a single script
# ==========================================
def _run_single_script(
    script_name: str,
    codeql_db_path: str,
    project_data_path: str,
    codeql_bin: str,
    threads: int,
    timeout: int,
    keep_bqrs: bool,
    codeql_script_dir: Optional[str] = None,
) -> Dict[str, str]:
    script_dir = Path(codeql_script_dir) if codeql_script_dir else CODEQL_SCRIPT_DIR
    ql_path = script_dir / f"{script_name}.ql"

    index_dir = Path(project_data_path) / SYMBOL_INDEX_DIR
    log_dir = Path(project_data_path) / CODEQL_LOG_DIR
    index_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    csv_path = index_dir / f"{script_name}.csv"
    bqrs_path = index_dir / f"{script_name}.bqrs"
    log_path = log_dir / f"{script_name}.log"

    if not ql_path.exists():
        raise CodeQLQueryError(f"[{script_name}] query script not found: {ql_path}")

    # Step 1: query run -> bqrs
    # No --rerun: use CodeQL's incremental evaluation cache (reused when query/DB
    # are unchanged, recomputed automatically when the query changes).
    run_cmd = [
        codeql_bin, "query", "run",
        "--database", codeql_db_path,
        "--output", str(bqrs_path),
        "--threads", str(threads),
        str(ql_path),
    ]
    # Step 2: bqrs decode -> csv (with header, columns named by the select aliases)
    # Publish atomically to avoid a half-written file under concurrency.
    tmp_csv = csv_path.with_name(csv_path.name + ".tmp")
    decode_cmd = [codeql_bin, "bqrs", "decode", "--format", "csv",
                  "--output", str(tmp_csv), str(bqrs_path)]

    try:
        with open(log_path, "w", encoding="utf-8") as log_f:
            for cmd in (run_cmd, decode_cmd):
                StdoutLogger.info(f"[{script_name}] running: {' '.join(cmd)}", STDOUT_LOG_PHASE)
                try:
                    proc = run_codeql(cmd, timeout=timeout, stdout=log_f,
                                      stderr=subprocess.STDOUT)
                except subprocess.TimeoutExpired:
                    # The whole group must be reaped: killing only the direct
                    # child leaves JVM grandchildren holding
                    # <db>/db-java/default/cache/.lock, breaking later queries.
                    raise CodeQLQueryError(
                        f"[{script_name}] command timed out ({timeout}s; process group terminated): "
                        f"{' '.join(cmd)}\nsee log: {log_path}")
                if proc.returncode != 0:
                    raise CodeQLQueryError(
                        f"[{script_name}] command failed (exit {proc.returncode}): {' '.join(cmd)}\nsee log: {log_path}")
        os.replace(tmp_csv, csv_path)          # publish atomically only on success
    finally:
        if tmp_csv.exists():
            tmp_csv.unlink()                   # clean up the partial file on the failure path

    # Clean up intermediate artifacts
    if not keep_bqrs and bqrs_path.exists():
        bqrs_path.unlink()

    StdoutLogger.info(f"[{script_name}] completed: {csv_path}", STDOUT_LOG_PHASE)
    return {"script": script_name, "status": "success", "csv": str(csv_path)}


# ==========================================
# 3. Batch orchestration
# ==========================================
def run_codeql_preprocess(
    codeql_db_path: str,
    project_data_path: str,
    codeql_script_dir: Optional[str] = None,
    scripts: Optional[List[str]] = None,
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    threads: int = 4,
    timeout: int = 1200,
    force_rerun: bool = False,
    keep_bqrs: bool = False,
    raise_on_error: bool = True,
) -> Dict[str, Dict[str, str]]:
    """
    Run the CodeQL preprocessing scripts in batch.

    Args:
        codeql_db_path: CodeQL database path
        project_data_path: result root (= output_path)
        codeql_script_dir: .ql script directory; defaults to the module-level CODEQL_SCRIPT_DIR
        scripts: script names to run; defaults to all six
        codeql_bin: CodeQL executable; defaults to env CODEQL_BIN or "codeql"
        threads: threads for a single CodeQL query
        timeout: timeout per command (seconds)
        force_rerun: rerun everything, ignoring existing CSVs
        keep_bqrs: keep intermediate .bqrs files (for debugging)
        raise_on_error: whether to raise if any script fails

    Returns:
        {script_name: {"status": "success|skipped|failed", "csv": ..., "error": ...}}
    """
    if shutil.which(codeql_bin) is None:
        raise CodeQLQueryError(
            f"CodeQL executable not found: '{codeql_bin}'. "
            f"Install the CodeQL CLI or set the CODEQL_BIN environment variable."
        )
    if not os.path.isdir(codeql_db_path):
        raise CodeQLQueryError(f"CodeQL database path does not exist: {codeql_db_path}")

    os.makedirs(project_data_path, exist_ok=True)
    # Compare the cached .manifest (database path and script contents) with the
    # current state to decide what needs to be rerun.
    all_scripts = scripts or PREPROCESS_SCRIPTS
    target_scripts = all_scripts if force_rerun else \
        get_stale_scripts(project_data_path, codeql_db_path, scripts, codeql_script_dir)
    for n in [x for x in all_scripts if x not in target_scripts]:
        StdoutLogger.info(f"[{n}] cache is valid, skipping.", STDOUT_LOG_PHASE)

    results: Dict[str, Dict[str, str]] = {}

    for name in target_scripts:
        try:
            results[name] = _run_single_script(
                name, codeql_db_path, project_data_path,
                codeql_bin, threads, timeout, keep_bqrs, codeql_script_dir)
        except Exception as e:
            StdoutLogger.error(f"[{name}] failed: {e}", STDOUT_LOG_PHASE)
            results[name] = {"script": name, "status": "failed", "error": str(e)}

    failed = [n for n, r in results.items() if r["status"] == "failed"]
    if failed and raise_on_error:
        raise CodeQLQueryError(f"These CodeQL scripts failed: {', '.join(failed)}")

    # Record the current database path and script hashes so later runs can decide
    # whether a rerun is needed.
    if not failed and not get_missing_indices(project_data_path, all_scripts):
        _write_manifest(project_data_path, codeql_db_path, all_scripts, codeql_script_dir)

    return results

# ==========================================
# 4. Rerun logic: missing CSV / changed .ql content / changed CodeQL DB path
# ==========================================

def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def _read_manifest(project_data_path: str) -> Optional[dict]:
    p = Path(project_data_path) / SYMBOL_INDEX_DIR / MANIFEST_NAME
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except Exception:
        return None

def get_stale_scripts(
    project_data_path: str,
    codeql_db_path: str,
    scripts: Optional[List[str]] = None,
    codeql_script_dir: Optional[str] = None,
) -> List[str]:
    """Scripts that must (re)run: missing CSV / changed .ql content / changed DB path (all stale when no manifest)."""
    target = scripts or PREPROCESS_SCRIPTS
    script_dir = Path(codeql_script_dir) if codeql_script_dir else CODEQL_SCRIPT_DIR
    missing = set(get_missing_indices(project_data_path, target))

    manifest = _read_manifest(project_data_path)
    # No fingerprint or changed DB: rerun everything.
    if manifest is None:
        return list(target)   
    elif manifest.get("codeql_db_path") != str(codeql_db_path):
        return list(target)   

    # Compare against the recorded hashes and rerun scripts that changed.
    stale = []
    recorded = manifest.get("scripts", {})
    for name in target:
        ql = script_dir / f"{name}.ql"
        cur = _hash_file(ql) if ql.exists() else None
        if name in missing or recorded.get(name) != cur:
            stale.append(name)
    return stale

def _write_manifest(project_data_path, codeql_db_path, scripts=None, codeql_script_dir=None):
    script_dir = Path(codeql_script_dir) if codeql_script_dir else CODEQL_SCRIPT_DIR
    manifest = {
        "codeql_db_path": str(codeql_db_path),
        "generated_at": datetime.now().isoformat(),
        "scripts": {n: _hash_file(script_dir / f"{n}.ql") for n in (scripts or PREPROCESS_SCRIPTS)},
    }
    (Path(project_data_path) / SYMBOL_INDEX_DIR / MANIFEST_NAME).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


# ==========================================
# 5. Convenience entry point for LangGraph config
# ==========================================
def prepare_symbol_indices(config: dict, force_rerun: bool = False) -> Dict[str, Dict[str, str]]:
    """
    Read paths from a RunnableConfig's configurable section and run preprocessing.
    Required fields: codeql_db_path, project_data_path
    Optional field: codeql_script_dir (defaults to the module-level path)
    """
    configurable = config["configurable"]
    return run_codeql_preprocess(
        codeql_db_path=configurable["codeql_db_path"],
        project_data_path=configurable["project_data_path"],
        codeql_script_dir=configurable.get("codeql_script_dir"),
        force_rerun=force_rerun,
    )


# ==========================================
# 6. Command-line entry point (can run independently of the Agent flow)
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run CodeQL preprocess queries")
    parser.add_argument("--db", required=True, help="CodeQL database path")
    parser.add_argument("--out", required=True, help="project_data_path / output_path")
    parser.add_argument("--script-dir", default=None, help="Override .ql scripts directory")
    parser.add_argument("--scripts", nargs="*", default=None, help="Subset of scripts to run")
    parser.add_argument("--force", action="store_true", help="Force rerun")
    parser.add_argument("--keep-bqrs", action="store_true", help="Keep intermediate .bqrs files")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    run_codeql_preprocess(
        codeql_db_path=args.db,
        project_data_path=args.out,
        codeql_script_dir=args.script_dir,
        scripts=args.scripts,
        force_rerun=args.force,
        keep_bqrs=args.keep_bqrs,
    )