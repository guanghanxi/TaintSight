import os
from pathlib import Path
from typing import List, Optional
from langchain.tools import tool
from langchain_core.runnables import RunnableConfig

from analysis_agent.utils import path_guard

# Limit output size per call to keep the context bounded
MAX_LINES_RETURN = 50
MAX_DIR_ENTRIES = 30


@tool
def read_file_content(
    file_path: str,
    config: RunnableConfig,
    start_line: int = 1,
    end_line: int = -1
) -> str:
    """Read the source content of a file.

    Args:
        file_path: Path relative to the project root (e.g. src/main/java/com/example/App.java)
        start_line: Start line (1-based), default 1
        end_line: End line (1-based), default -1 (read to the end)

    Returns:
        The requested code with line numbers. Oversized output is truncated with a hint.
    """
    project_root = config["configurable"].get("project_root")
    # Boundary guard: file_path comes from the LLM; absolute paths / `..` could resolve outside the project root
    full_path, deny_reason = path_guard.resolve_in_project(project_root, file_path)
    if full_path is None:
        return f"❌ Error: {deny_reason}"

    if not full_path.exists():
        return f"❌ Error: File not found at '{file_path}'"

    if full_path.is_dir():
        return f"❌ Error: '{file_path}' is a directory, not a file. Use list_directory_structure instead."

    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        total_lines = len(lines)

        # Convert to zero-based indices
        start_idx = max(0, start_line - 1)
        end_idx = total_lines if end_line == -1 else min(total_lines, end_line)
        selected_lines = lines[start_idx:end_idx]

        # Prefix each line with its number
        output_lines = []
        for i, line in enumerate(selected_lines):
            actual_line_num = start_idx + i + 1
            output_lines.append(f"{actual_line_num}: {line.rstrip()}")

        result = "\n".join(output_lines)

        # Safe truncation: prefer a blank-line boundary so a code block is not cut in half
        if len(result) > 4000:
            # Find the last blank line within 4000 characters as the cut point
            truncated = result[:4000]
            last_blank = truncated.rfind("\n\n")
            if last_blank > 3000:  # cut at the blank line when it is not too early
                truncated = truncated[:last_blank]

            return (
                truncated
                + f"\n... [Truncated at ~{start_idx + truncated.count(chr(10)) + 1}/{total_lines} lines. "
                + f"Use start_line/end_line to read specific ranges, "
                + f"or use find_method/get_class_outline for targeted extraction.]"
            )

        return result

    except Exception as e:
        return f"❌ Error reading file: {str(e)}"


@tool
def list_directory_structure(
    dir_path: str,
    config: RunnableConfig,
    max_depth: int = 2,
    file_extension: str = None
) -> str:
    """List the files and subdirectories under a directory.

    Args:
        dir_path: Directory path relative to the project root (e.g. src/main/java)
        max_depth: Maximum recursion depth, default 2, to keep output bounded
        file_extension: Optional file-suffix filter (e.g. ".java"). When set, only matching files are shown; directories are always shown.

    Returns:
        A directory tree as a string.
    """
    project_root = config["configurable"].get("project_root")
    # Boundary guard: same as read_file_content
    full_path, deny_reason = path_guard.resolve_in_project(project_root, dir_path)
    if full_path is None:
        return f"❌ Error: {deny_reason}"

    if not full_path.is_dir():
        return f"❌ Error: Directory not found or is a file: {dir_path}"

    def _tree(path: Path, prefix: str, current_depth: int) -> List[str]:
        if current_depth > max_depth:
            return []

        entries = sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        # Filter out hidden files and common non-code directories
        entries = [
            e for e in entries
            if not e.name.startswith('.')
            and e.name not in ['target', 'build', 'node_modules', '.git', '.idea', '__pycache__']
        ]

        # With a suffix filter, keep only matching files (directories are always kept)
        if file_extension:
            entries = [
                e for e in entries
                if e.is_dir() or e.name.endswith(file_extension)
            ]

        lines = []
        shown_entries = entries[:MAX_DIR_ENTRIES]

        for i, entry in enumerate(shown_entries):
            connector = "└── " if i == len(shown_entries) - 1 and len(entries) <= MAX_DIR_ENTRIES else "├── "
            suffix = "/" if entry.is_dir() else ""
            lines.append(f"{prefix}{connector}{entry.name}{suffix}")

            if entry.is_dir() and current_depth < max_depth:
                extension = "    " if i == len(shown_entries) - 1 else "│   "
                lines.extend(_tree(entry, prefix + extension, current_depth + 1))

        if len(entries) > MAX_DIR_ENTRIES:
            lines.append(f"{prefix}└── ... ({len(entries) - MAX_DIR_ENTRIES} more items)")

        return lines

    # Count files and directories
    file_count = sum(1 for _ in full_path.rglob('*') if _.is_file())
    dir_count = sum(1 for _ in full_path.rglob('*') if _.is_dir())

    tree_lines = [f"📂 {dir_path}/ ({dir_count} dirs, {file_count} files)"]
    tree_lines.extend(_tree(full_path, "", 1))
    return "\n".join(tree_lines)


@tool
def grep_code(
    pattern: str,
    config: RunnableConfig,
    file_extension: str = ".java",
    case_sensitive: bool = False,
    context_lines: int = 0,
    exclude_test: bool = False,
    max_results: int = 20
) -> str:
    """Search the project for code lines matching a regular expression.

    Args:
        pattern: Regular expression or keyword (e.g. "sanitize|escape", "Runtime\\.exec")
        file_extension: File-suffix filter, default ".java". Comma-separated suffixes are supported (e.g. ".java,.xml,.yml")
        case_sensitive: Whether matching is case-sensitive, default False
        context_lines: Context lines before/after each match, default 0 (no context)
        exclude_test: Whether to exclude test directories (src/test/), default False
        max_results: Maximum number of results, default 20

    Returns:
        Matches grouped by file, formatted as "file path:line number: matched content"
    """
    import subprocess

    project_root = config["configurable"].get("project_root")

    # Multiple suffixes: ".java,.xml,.yml" -> [".java", ".xml", ".yml"]
    extensions = [ext.strip() for ext in file_extension.split(",")]

    # Build the grep command
    cmd = ["grep", "-rn"]

    # Case sensitivity
    if not case_sensitive:
        cmd.append("-i")

    # Context lines
    if context_lines > 0:
        cmd.extend(["-C", str(context_lines)])

    # File-suffix filters (multiple allowed)
    for ext in extensions:
        cmd.extend(["--include", f"*{ext}"])

    # Exclude test directories
    if exclude_test:
        cmd.extend(["--exclude-dir", "test", "--exclude-dir", "tests"])

    # Extended regex + pattern + search path
    cmd.extend(["-E", pattern, project_root])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0 and not result.stdout:
            return f"✅ No matches found for pattern '{pattern}' in {file_extension} files."

        raw_lines = result.stdout.strip().split('\n')

        # Parse and format the output.
        # With context, lines look like "file:line-content" (context) or "file:line:content" (match), groups separated by "--"
        formatted_lines = []
        match_count = 0
        current_file = None

        for line in raw_lines:
            # Skip the group separator
            if line.strip() == "--":
                formatted_lines.append("---")
                continue

            # Parse "abs_path:line:content" (match) or "abs_path-line-content" (context)
            for sep in [':', '-']:
                parts = line.split(sep, 2)
                if len(parts) == 3 and parts[1].isdigit():
                    abs_path, line_num, content = parts
                    rel_path = os.path.relpath(abs_path, project_root)

                    # Group by file
                    if rel_path != current_file:
                        current_file = rel_path
                        formatted_lines.append(f"\n📄 {rel_path}:")

                    marker = "→" if sep == ":" else " "
                    formatted_lines.append(f"  {marker} L{line_num}: {content.strip()}")

                    if sep == ":":
                        match_count += 1
                    break

            if match_count >= max_results:
                formatted_lines.append(f"... (reached max_results={max_results}, more matches exist)")
                break

        if not formatted_lines:
            return f"✅ No matches found for pattern '{pattern}'."

        header = f"🔍 Found {match_count} matches for '{pattern}'"
        if exclude_test:
            header += " (excluding test directories)"
        return header + "\n" + "\n".join(formatted_lines)

    except subprocess.TimeoutExpired:
        return "❌ Grep timed out (>15s). Try narrowing the search pattern or file_extension."
    except Exception as e:
        return f"❌ Grep error: {str(e)}"