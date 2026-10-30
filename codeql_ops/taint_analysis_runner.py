"""
CodeQL Taint Analysis Runner Module
"""

import os
import json
import subprocess
import shutil

from codeql_ops.proc_utils import run_codeql

DEFAULT_CODEQL_BIN = os.environ.get("CODEQL_BIN", "codeql")

QL_SCRIPT_TEMPLATE = """\
/**
 * @name VulDetect Agent Taint Analysis
 * @description Custom taint tracking query.
 * @kind path-problem
 * @problem.severity error
 * @id {analysis_id}
 * @tags security
 */
import java
import VulDetectLib
import VulDetectFlow::PathGraph

from VulDetectFlow::PathNode source, VulDetectFlow::PathNode sink
where VulDetectFlow::flowPath(source, sink)
select
  sink.getNode(), source, sink,
  "Potential security vulnerability: data flows from $@ to a sensitive sink.",
  source.getNode(), "user-controlled source"
"""

def sarif_has_results(sarif_path: str) -> bool:
    """Whether the SARIF file contains non-empty results."""
    if not os.path.exists(sarif_path):
        return False
    try:
        with open(sarif_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return any(run.get("results") for run in data.get("runs", []))
    except Exception:
        return False


def _run_codeql_analyze(
    cmd: list,
    log_path: str,
    timeout: int = 3600,
) -> subprocess.CompletedProcess:
    """Run codeql analyze in its own process group; kill the whole group on timeout.

    Process-group reaping lives in `proc_utils.run_codeql`. Returns a
    CompletedProcess with .returncode/.stdout/.stderr preserved, so the caller
    interface is unchanged. stdout/stderr are written to the log file for
    post-mortem diagnosis.
    """
    proc = run_codeql(cmd, timeout=timeout, capture_output=True, text=True,
                      return_on_timeout=True)
    stdout, stderr = proc.stdout, proc.stderr

    # Persist stderr (and stdout) to the log file so orphan-process failures can
    # be diagnosed afterwards (run_codeql appends its timeout note to stderr).
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write(f"$ {' '.join(cmd)}\n\n=== STDOUT ===\n{stdout or ''}\n=== STDERR ===\n{stderr or ''}\n")

    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def run_database_analysis(
    project_work_dir_path: str,
    project_output_path: str,
    qll_script_content: str,
    codeql_db_path: str,
    analysis_id: str = "vuldetect/agent/taint-analysis",
    codeql_cli_path: str = "codeql",
    run_tag: str = "",                      # distinguishes repeated runs
):
    work_dir_path = os.path.join(project_work_dir_path, "taint_analysis")
    os.makedirs(work_dir_path, exist_ok=True)
    # TaintAnalysis.ql / VulDetectLib.qll use fixed filenames (the QL script
    # imports VulDetectLib, which requires the fixed module name) and are
    # overwritten on every run; only the SARIF output name varies with run_tag
    # so results from repeated runs can be kept.
    ql_script_path = os.path.join(work_dir_path, "TaintAnalysis.ql")
    with open(ql_script_path, 'w') as f:
        f.write(QL_SCRIPT_TEMPLATE.format(analysis_id = analysis_id.lower()))
    qll_script_path = os.path.join(work_dir_path, "VulDetectLib.qll")
    with open(qll_script_path, 'w') as f:
        f.write(qll_script_content)

    suffix = f"_{run_tag}" if run_tag else ""
    output_file_path = os.path.join(work_dir_path, f"taint_analysis_result{suffix}.sarif")
    log_file_path = os.path.join(work_dir_path, f"analysis{suffix}.log")
    result = _run_codeql_analyze(
        [
            codeql_cli_path, "database", "analyze", codeql_db_path, ql_script_path,
            "--format=sarifv2.1.0", "--rerun", f"--output={output_file_path}"
        ],
        log_path=log_file_path,
    )
    copied_target_dir = os.path.join(project_output_path, "taint_analysis")
    os.makedirs(copied_target_dir, exist_ok=True)
    if os.path.exists(output_file_path):
        shutil.copy(output_file_path, os.path.join(copied_target_dir, f"taint_analysis_result{suffix}.sarif"))
    if os.path.exists(log_file_path):
        shutil.copy(log_file_path, os.path.join(copied_target_dir, f"analysis{suffix}.log"))
    return result