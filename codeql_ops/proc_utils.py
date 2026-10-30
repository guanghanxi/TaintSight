"""
proc_utils.py -- process-group-safe wrapper for codeql subprocesses (single source of truth)

Why this exists
---------------
The codeql CLI spawns JVM children. `subprocess.run(cmd, timeout=T)` kills only
the direct child on timeout, leaving the JVM grandchild orphaned and holding
`<db>/db-java/default/cache/.lock`. Every later query on the same database then
fails with `cache directory is already locked by another running process`, is
classified as an environmental failure, and enough consecutive failures trip the
circuit breaker: the rest of the stage is skipped while the pipeline still
reports completion.

Therefore **every codeql invocation** must:
  1. use `start_new_session=True` so the child enters a new session/process
     group; `killpg` then cannot affect this pipeline itself;
  2. kill the whole group after a timeout;
  3. kill the whole group on **non-timeout exceptions** as well (e.g.
     KeyboardInterrupt from Ctrl-C) -- see the `except BaseException` branch in
     run_codeql, for the same reason: an orphan JVM holds the database lock.

The interface intentionally mirrors `subprocess.run` (same argument names,
returns CompletedProcess) and still raises `subprocess.TimeoutExpired` on
timeout, so callers only change which function they call.
"""
import os
import signal
import subprocess
from typing import Optional, Sequence

__all__ = ["kill_process_group", "run_codeql"]

# Time to wait for process reaping after killing the group; a JVM usually exits
# immediately after SIGKILL.
_REAP_TIMEOUT = 10


def _pgid_or_none(proc: subprocess.Popen):
    """Process-group pgid (for logging); None if the process has exited."""
    try:
        return os.getpgid(proc.pid)
    except (ProcessLookupError, PermissionError):
        return None


def kill_process_group(proc: subprocess.Popen) -> None:
    """Kill the whole process group (including codeql's JVM grandchildren) so none can orphan and hold the DB lock."""
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, PermissionError):
        # Process already exited or PID was reused: fall back to killing the direct child.
        proc.kill()
        return
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()


def run_codeql(
    cmd: Sequence[str],
    timeout: float,
    capture_output: bool = False,
    text: bool = False,
    stdout=None,
    stderr=None,
    cwd: Optional[str] = None,
    return_on_timeout: bool = False,
) -> subprocess.CompletedProcess:
    """Run codeql in its own process group; on timeout, reap the whole group first.

    Args:
        cmd: full command line
        timeout: timeout in seconds
        capture_output: True is equivalent to stdout=PIPE + stderr=PIPE (as in subprocess.run)
        text: text mode
        stdout/stderr: explicit redirection (e.g. to a log file, stderr=subprocess.STDOUT)
        cwd: working directory
        return_on_timeout: on timeout, return a CompletedProcess (negative return
            code from the signal, keeping captured stdout/stderr where possible)
            instead of raising TimeoutExpired. Use True where the caller wants to
            persist stdout/stderr for diagnosis.

    Returns:
        subprocess.CompletedProcess
    Raises:
        subprocess.TimeoutExpired: on timeout when return_on_timeout=False (the
            process group has already been reaped).
    """
    if capture_output:
        stdout = stderr = subprocess.PIPE

    proc = subprocess.Popen(
        list(cmd),
        stdout=stdout,
        stderr=stderr,
        text=text,
        cwd=cwd,
        # New session = new process group: codeql keeps spawning JVMs, so the
        # whole group must be reaped (without affecting this process).
        start_new_session=True,
    )

    out = err = None
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        pgid = _pgid_or_none(proc)      # must be read before reaping: getpgid fails afterwards
        kill_process_group(proc)
        try:
            out, err = proc.communicate(timeout=_REAP_TIMEOUT)
        except subprocess.TimeoutExpired:
            pass  # reaping timed out; the group already received SIGKILL
        # Record the cause here instead of letting callers guess from a negative
        # return code: processes killed by the OOM killer also have a negative
        # return code and cannot be distinguished from the signal value alone.
        note = (f"\n[proc_utils] timed out after {timeout}s; killed the whole process group "
                f"(pid={proc.pid}, pgid={pgid})")
        if return_on_timeout:
            rc = proc.returncode if proc.returncode is not None else -signal.SIGKILL
            return subprocess.CompletedProcess(list(cmd), rc, out, (err or "") + note)
        # Attach the note to TimeoutExpired so the caller's log records it
        raise subprocess.TimeoutExpired(list(cmd), timeout,
                                        output=out, stderr=(err or "") + note)
    except BaseException:
        # Non-timeout exceptions (most notably KeyboardInterrupt when a batch is
        # cancelled, or an error in the caller) **also** require reaping the whole
        # group: start_new_session detached the child from our process group, so
        # the terminal's SIGINT does not reach it and an orphan JVM keeps holding
        # <db>/db-java/default/cache/.lock -- the same leak as a timeout.
        # Order matters: TimeoutExpired must be handled first (it is an Exception).
        kill_process_group(proc)
        try:
            proc.communicate(timeout=_REAP_TIMEOUT)
        except Exception:
            pass  # do not hide the original exception if reaping fails
        raise

    return subprocess.CompletedProcess(list(cmd), proc.returncode, out, err)
