"""Path boundary guard for tools: never resolve an LLM-provided path outside project_root.

Why this is needed
------------------
The tools' `file_path` / `dir_path` arguments come from the LLM.
`Path(project_root) / file_path` discards `project_root` when `file_path` is
**absolute** (pathlib semantics: an absolute right operand replaces the left
side), and `..` behaves the same way, so tools could escape the project root.

Rules
-----
- **Reject all absolute paths** and explicitly ask for a project-relative path,
  rather than reinterpreting them as relative paths (which would produce an
  opaque "File not found" the model cannot learn from).
- After `resolve()`, a relative path must still be inside `project_root`
  (this also blocks symlink escapes).
- Rejection is expressed through the **return value**, not an exception, to
  match the existing tools' `Error: ...` style.
"""
import os
from pathlib import Path
from typing import Optional, Tuple


def resolve_in_project(project_root: str, user_path: str) -> Tuple[Optional[Path], str]:
    """Safely resolve user_path inside project_root.

    :return: (absolute path or None, rejection reason; empty string on success)
    """
    if not project_root:
        return None, "project_root is not configured; the tool cannot locate files"

    raw = "" if user_path is None else str(user_path).strip()
    if not raw:
        return None, "Path is empty"

    if Path(raw).is_absolute():
        return None, (
            f"Path outside the project: '{raw}' is an absolute path. Tools accept only "
            f"**paths relative to the project root** (e.g. src/main/java/com/example/App.java); "
            f"retry with a relative path."
        )

    root = Path(project_root).resolve()
    resolved = (root / raw).resolve()

    # Require resolved to be root itself or a descendant (using parents is stricter
    # than str.startswith; /proj-other is not treated as inside /proj).
    if resolved != root and root not in resolved.parents:
        return None, (
            f"Path outside the project: '{raw}' resolves to '{resolved}', which is "
            f"outside the project root '{root}'; access denied."
        )

    return resolved, ""
