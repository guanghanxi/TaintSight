"""
executor.py
CodeQL executor: wraps codeql CLI compile and run operations.
All intermediate files are persisted under work_dir, organized by spec_id/round.
"""
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from logger import StdoutLogger

from codeql_ops.proc_utils import run_codeql

# Stdout Log Phase
STDOUT_LOG_PHASE = "codeql_agent/executor"


@dataclass
class CommandResult:
    success: bool
    stdout: str = ""
    stderr: str = ""

# qlpack.yml template
QLPACK_TEMPLATE = """\
name: {analysis_id}
version: 0.0.1
dependencies:
  codeql/java-all: "*"
"""


class CodeQLExecutor:
    def __init__(self, cli_path: str, db_path: str, work_dir: Path, analysis_id: str):
        """
        Args:
            cli_path: path to the codeql CLI executable
            db_path:  CodeQL database path
            work_dir: working directory for all intermediate files
            analysis_id: qlpack.yml name field (recommended format: scope/name)
        """
        self.cli_path = cli_path
        self.db_path = db_path
        self.work_dir = work_dir
        self.analysis_id = analysis_id

        # Initialize qlpack.yml (idempotent; never overwrites)
        self._init_qlpack()

    def compile(
        self,
        ql_script: str,
        spec_id: str,
        round_num: int,
    ) -> CommandResult:
        """
        Compile check: codeql query compile
        Saved to work_dir/{spec_id}/round_{n}/query.ql
        """
        round_dir = self._ensure_round_dir(spec_id, round_num)
        ql_path = round_dir / "query.ql"
        ql_path.write_text(ql_script, encoding="utf-8")

        try:
            result = run_codeql(
                [self.cli_path, "query", "compile", str(ql_path)],
                capture_output=True, text=True, timeout=120,
            )
            return CommandResult(
                success=(result.returncode == 0),
                stdout=result.stdout,
                stderr=result.stderr,
            )
        except subprocess.TimeoutExpired:
            # run_codeql reaps the whole process group; a JVM orphan would hold the DB lock
            return CommandResult(success=False, stderr="Compile timed out (120s; process group terminated)")
        except OSError as e:
            # CLI unavailable / permission denied: fail without raising; the caller
            # treats this as an environmental failure
            return CommandResult(success=False, stderr=f"CodeQL CLI invocation failed: {type(e).__name__}: {e}")

    def run_query(
        self,
        ql_script: str,
        spec_id: str,
        round_num: int,
    ) -> CommandResult:
        """
        Run the query: codeql query run
        Files saved to work_dir/{spec_id}/round_{n}/
        """
        round_dir = self._ensure_round_dir(spec_id, round_num)
        ql_path = round_dir / "query.ql"
        bqrs_path = round_dir / "result.bqrs"
        csv_path = round_dir / "result.csv"

        # Write the .ql file (compile may have written it; overwrite to stay consistent)
        ql_path.write_text(ql_script, encoding="utf-8")

        try:
            # 1. Run the query
            result = run_codeql(
                [
                    self.cli_path, "query", "run",
                    "--database", self.db_path,
                    "--output", str(bqrs_path),
                    str(ql_path),
                ],
                capture_output=True, text=True, timeout=300,
            )

            if result.returncode != 0:
                return CommandResult(success=False, stderr=result.stderr)

            # 2. Decode BQRS -> CSV
            csv_content = self._bqrs_to_csv(bqrs_path, csv_path)
            
            # 3. Check the CSV conversion
            if csv_content.startswith("[CSV parse failed"):
                return CommandResult(
                    success=False, 
                    stderr=f"Query succeeded but result conversion failed: {csv_content}"
                )

            return CommandResult(
                success=True,
                stdout=csv_content,
                stderr=result.stderr,
            )
        except subprocess.TimeoutExpired:
            # Killing only the direct child leaves the JVM grandchild holding
            # <db>/db-java/default/cache/.lock, which breaks later queries on the
            # same database. run_codeql reaps the whole group.
            return CommandResult(success=False, stderr="Query timed out (300s; process group terminated)")
        except OSError as e:
            # CLI unavailable / permission denied: fail without raising; the caller
            # treats this as an environmental failure
            return CommandResult(success=False, stderr=f"CodeQL CLI invocation failed: {type(e).__name__}: {e}")

    def _bqrs_to_csv(self, bqrs_path: Path, csv_path: Path) -> str:
        """Convert a BQRS result file to a CSV string."""
        try:
            run_codeql(
                [
                    self.cli_path, "bqrs", "decode",
                    "--format", "csv",
                    "--output", str(csv_path),
                    str(bqrs_path),
                ],
                capture_output=True, text=True, timeout=60,
            )
            return csv_path.read_text(encoding="utf-8")
        except Exception as e:
            return f"[CSV parse failed: {e}]"

    def _ensure_round_dir(self, spec_id: str, round_num: int) -> Path:
        """Ensure work_dir/{spec_id}/round_{n}/ exists."""
        round_dir = self.work_dir / spec_id / f"round_{round_num}"
        round_dir.mkdir(parents=True, exist_ok=True)
        return round_dir

    def _init_qlpack(self):
        """
        Generate qlpack.yml in the work_dir root.
        Idempotent: skip if it exists so manual edits are preserved.
        """
        qlpack_path = self.work_dir / "qlpack.yml"

        if qlpack_path.exists():
            StdoutLogger.debug(f"qlpack.yml already exists; skipping: {qlpack_path}", STDOUT_LOG_PHASE)
            return

        # Note: the template escapes CodeQL braces by doubling them
        qlpack_content = QLPACK_TEMPLATE.format(analysis_id=self.analysis_id.lower())
        qlpack_path.write_text(qlpack_content, encoding="utf-8")
        StdoutLogger.info(f"Generated qlpack.yml: {qlpack_path}", STDOUT_LOG_PHASE)