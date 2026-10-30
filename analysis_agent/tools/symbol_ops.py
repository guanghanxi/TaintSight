import os
import threading
from collections import OrderedDict
from typing import NamedTuple, Optional
import pandas as pd
from langchain_core.tools import tool
from pathlib import Path
from langchain_core.runnables import RunnableConfig

# codeql_ops is the top-level infrastructure module and the single source of truth for index CSV paths
from codeql_ops.codeql_query_runner import get_index_csv_path

from analysis_agent.utils import path_guard


# ==========================================
# 1. Symbol index cache (keyed by project_data_path / bounded LRU / thread-safe)
# ==========================================
# A module-level "current project" cache (one set of tables plus _loaded_path) is unsafe under
# concurrency: check-then-act without a lock, _loaded_path published before the data, and the four
# tables swapped non-atomically. With batch runs (a ThreadPoolExecutor plus LangGraph ToolNode's
# parallel tool calls) one project can read another project's index and stay permanently mis-bound.
# Instead, cache immutable bundles keyed by path: callers hold a local reference, the module has no
# "current project" semantics, and cross-project contamination is impossible by construction.


class SymbolIndexBundle(NamedTuple):
    """The four symbol-index tables for one project.

    Immutable means the binding is immutable: fields cannot be reassigned and no partial
    state exists. Callers are read-only (current tools only do df[mask] / sort_values /
    iloc / iterrows). Never mutate a DataFrame held by a bundle in place (e.g.
    df["x"] = ... / inplace=True), since other threads reading the same key share it.
    """
    class_details: pd.DataFrame
    func_details: pd.DataFrame
    field_details: pd.DataFrame
    call: pd.DataFrame


# Cache bound: by default covers the concurrently running keys under the production concurrency
# (C=8); projects scanned serially are evicted by the LRU.
_MAX_CACHED_PROJECTS = int(os.environ.get("SYMBOL_INDEX_CACHE_SIZE", "8"))

_index_cache: "OrderedDict[str, SymbolIndexBundle]" = OrderedDict()
# The lock protects only the dictionary. CSV I/O always happens outside the lock: this avoids
# serializing the four pandas.read_csv calls (which would serialize the whole batch) and makes the
# function naturally reentrant (no self-deadlock).
_index_cache_lock = threading.Lock()


def _safe_read_csv(csv_path: str) -> pd.DataFrame:
    if os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
        return pd.read_csv(csv_path)
    return pd.DataFrame()


def get_symbol_indices(project_data_path) -> SymbolIndexBundle:
    """Return the four index tables for project_data_path: path-keyed, thread-safe, bounded LRU.

    Unlike a "current project" global, this **returns** an immutable bundle that the caller
    holds locally, so under concurrency each thread only sees the data for its own key.
    """
    # Normalize Path/str: callers pass both, and normalization prevents the same directory from
    # being read twice under different types or relative spellings.
    key = os.path.abspath(str(project_data_path))

    # Fast path: short lock for lookup + LRU refresh (no I/O under the lock)
    with _index_cache_lock:
        hit = _index_cache.get(key)
        if hit is not None:
            _index_cache.move_to_end(key)
            return hit

    # Slow path: read from disk outside the lock
    bundle = SymbolIndexBundle(
        class_details=_safe_read_csv(get_index_csv_path(project_data_path, "fetch_class_details")),
        func_details=_safe_read_csv(get_index_csv_path(project_data_path, "fetch_func_details")),
        field_details=_safe_read_csv(get_index_csv_path(project_data_path, "fetch_field_details")),
        call=_safe_read_csv(get_index_csv_path(project_data_path, "fetch_call")),
    )

    # Short lock for insertion + LRU eviction. Concurrent misses for the same key produce
    # equivalent content, so the first one wins; an evicted bundle stays alive while a thread
    # holds a local reference (reference counting), so reads remain safe.
    with _index_cache_lock:
        existing = _index_cache.get(key)
        if existing is not None:
            return existing
        _index_cache[key] = bundle
        while len(_index_cache) > _MAX_CACHED_PROJECTS:
            _index_cache.popitem(last=False)   # evict the least recently used
        return bundle


def clear_symbol_index_cache():
    """Clear the index cache (call after the index is rebuilt)."""
    with _index_cache_lock:
        _index_cache.clear()


# ==========================================
# 2. Internal helpers
# ==========================================
def _read_code_by_loc(project_root: str, relative_file_path: str, start_line: int, end_line: int) -> str:
    """Read code by line range."""
    # Boundary guard (defense in depth): index file columns contain no absolute paths or `..`
    # in practice, but a corrupted/stale index could yield another project's path; the guard at
    # least guarantees the read never escapes the project root.
    full_path, deny_reason = path_guard.resolve_in_project(project_root, relative_file_path)
    if full_path is None or not full_path.exists():
        raise FileNotFoundError(deny_reason or (Path(project_root) / relative_file_path))
    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), end_line)
    return "".join(lines[start_idx:end_idx])


def _find_declaration_end(project_root: str, relative_file_path: str, start_line: int, max_scan: int = 15) -> int:
    """Scan down from start_line to the first '{' (start of the class body): the end line of the class declaration (including extends/implements/generics)."""
    full_path, _deny_reason = path_guard.resolve_in_project(project_root, relative_file_path)
    if full_path is None or not full_path.exists():
        return start_line
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        for i in range(start_line - 1, min(start_line - 1 + max_scan, len(lines))):
            if '{' in lines[i]:
                return i + 1
    except Exception:
        pass
    return start_line


def _clean_modifiers(modifiers) -> str:
    """'public;static' -> 'public static'"""
    if not isinstance(modifiers, str) or not modifiers:
        return ""
    return modifiers.replace(";", " ").strip()


def _simple_names(qualified_list) -> str:
    """'java.lang.Override;org.x.GetMapping' -> 'Override, GetMapping'"""
    if not isinstance(qualified_list, str) or not qualified_list:
        return ""
    names = [p.strip().split(".")[-1] for p in qualified_list.split(";") if p.strip()]
    return ", ".join(names)


# ==========================================
# search_class tool
# ==========================================
@tool
def search_class(
    name_pattern: str,
    config: RunnableConfig,
    super_type: Optional[str] = None,
    annotation: Optional[str] = None,
    max_results: int = 30,
    offset: int = 0,
) -> str:
    """Search Java classes in the project. Supports combined filtering by name, inheritance and annotations (conditions are ANDed).

    Args:
        name_pattern: Class-name match (substring, e.g. "Controller", "User"). Pass "" to skip name filtering.
                      All filter parameters use **literal substring** matching, not regex; use `grep_code` when regex is needed.
                      For nested classes use the full form such as "Outer$Inner" (`$` is treated literally).
        super_type: (optional) Superclass or interface filter (e.g. "HttpServlet", "Serializable"). Matches direct and indirect inheritance by substring. Omit to skip.
        annotation: (optional) Annotation filter (e.g. "RestController", "Service"), substring match. Omit to skip.
        max_results: Maximum results per call, default 30.
        offset: Pagination offset, default 0 (e.g. after 30 results, pass offset=30 for the next page).

    Returns:
        Metadata for matching classes (class name, fully qualified name, file path, line, kind,
        modifiers, inheritance, annotations).
        To inspect a class's members (fields, method signatures), use `get_class_outline(qualified_name="...")`.
    """
    project_data_path = config["configurable"].get("project_data_path")
    idx = get_symbol_indices(project_data_path)
    
    df = idx.class_details
    if df is None or df.empty:
        return "❌ Error: Class index not available."
    mask = pd.Series(True, index=df.index)
    
    # 1. Build the filter mask
    if name_pattern:
        mask &= df["name"].str.contains(name_pattern, case=False, na=False, regex=False)
    if super_type:
        mask &= df["super_types"].str.contains(super_type, case=False, na=False, regex=False)
    if annotation:
        mask &= df["annotations"].str.contains(annotation, case=False, na=False, regex=False)

    matched = df[mask]
    total = len(matched)
    
    if total == 0:
        return "✅ No classes found matching the criteria."

    # 2. Stable ordering for deterministic pagination
    matched = matched.sort_values(by=["file", "start_line"])
    
    # 3. Pagination slice
    page_data = matched.iloc[offset : offset + max_results]
    
    if page_data.empty:
        return f"⚠️ Offset {offset} is out of bounds. Total matches: {total}."

    # 4. Format the output
    lines = [f"🔍 Found {total} classes matching criteria (showing {offset + 1} to {offset + len(page_data)}):"]
    
    for i, (_, row) in enumerate(page_data.iterrows(), start=offset + 1):
        lines.append(f"\n[{i}] {row['name']} ({row['type_kind']})")
        lines.append(f"    Qualified: {row['qualified_name']}")
        lines.append(f"    File: {row['file']}:L{int(row['start_line'])}")
        
        # Optional details
        modifiers = _clean_modifiers(row.get("modifiers"))
        if modifiers:
            lines.append(f"    Modifiers: {modifiers}")
            
        super_types = row.get("super_types")
        if isinstance(super_types, str) and super_types:
            lines.append(f"    Extends/Implements: {super_types}")
            
        annotations = _simple_names(row.get("annotations"))
        if annotations:
            lines.append(f"    Annotations: @{annotations.replace(', ', ', @')}")

    # 5. Pagination and follow-up hints
    lines.append("")
    if offset + max_results < total:
        lines.append(f"💡 There are {total - (offset + max_results)} more results. Use `offset={offset + max_results}` to view the next page.")
    else:
        lines.append("💡 You have reached the end of the results.")
        
    lines.append('💡 To inspect the structure of a specific class, use `get_class_outline(qualified_name="...")`.')
    
    return "\n".join(lines)

# ==========================================
# 4. get_class_outline: class structure overview
# ==========================================
@tool
def get_class_outline(
    class_name: str,
    config: RunnableConfig,
) -> str:
    """Get a class structure overview: full class declaration (annotations/inheritance/generics) + fields + method signatures (no bodies).

    Args:
        class_name: Class name in one of two forms:
                    1. Fully qualified name (e.g. "com.example.controller.UserController"), recommended: precise in one step;
                    2. Simple name (e.g. "UserController"), exact match; if several classes share it, a list of
                       qualified-name candidates is returned and you must re-invoke with the qualified name.
                    For fuzzy search (substring, annotation/inheritance filters), use search_class first.

    Returns:
        The class structure overview (declaration, fields, method signatures).
        To read a specific method body, use get_method_definition(class_qualified_name=..., method_name=...).
    """
    project_root = config["configurable"].get("project_root")
    project_data_path = config["configurable"].get("project_data_path")
    idx = get_symbol_indices(project_data_path)
    df = idx.class_details
    if df is None or df.empty:
        return "❌ Error: Class index not available."

    # ============ Lookup fallback ladder ============
    if "." in class_name:
        # Step 1: exact fully qualified name
        candidates = df[df["qualified_name"] == class_name]
        if candidates.empty:
            return (f"❌ Class not found by qualified name '{class_name}'. "
                    f"Use search_class(name_pattern=\"{class_name.split('.')[-1]}\") for fuzzy discovery.")
    else:
        # Step 2: exact simple name
        candidates = df[df["name"] == class_name]
        if candidates.empty:
            return (f"❌ No class with exact name '{class_name}'. "
                    f"Use search_class(name_pattern=\"{class_name}\") for fuzzy discovery.")
        if len(candidates) > 1:
            # Disambiguate: return qualified-name candidates for a precise second call
            return (f"⚠️ Found {len(candidates)} classes named '{class_name}'. "
                    f"Please re-invoke with the fully qualified name:\n" +
                    "\n".join([f"- {row['qualified_name']}  ({row['file']})"
                               for _, row in candidates.head(5).iterrows()]) +
                    (f"\n... and {len(candidates) - 5} more." if len(candidates) > 5 else ""))

    target = candidates.iloc[0]
    qualified_name = target["qualified_name"]
    file_rel = target["file"]

    # ============ Assemble the outline ============
    # 1. Read the class declaration (annotations_start_line through the first '{'), including annotations and inheritance/generics
    decl_start = int(target["annotations_start_line"])
    decl_end = _find_declaration_end(project_root, file_rel, int(target["start_line"]))
    try:
        declaration = _read_code_by_loc(project_root, file_rel, decl_start, decl_end)
    except Exception as e:
        declaration = f"[Failed to read declaration: {e}]"

    # 2. Fields and method signatures from the index
    field_df = idx.field_details
    func_df = idx.func_details
    fields = field_df[field_df["class_qualified_name"] == qualified_name] \
        if field_df is not None and not field_df.empty else pd.DataFrame()
    callables = func_df[func_df["class_qualified_name"] == qualified_name] \
        if func_df is not None and not func_df.empty else pd.DataFrame()

    constructors = callables[callables["type_kind"] == "Constructor"] if not callables.empty else callables
    methods = callables[callables["type_kind"] != "Constructor"] if not callables.empty else callables

    # Sort by start_line so display order matches physical source order
    if not fields.empty:
        fields = fields.sort_values(by="start_line")
    if not constructors.empty:
        constructors = constructors.sort_values(by="start_line")
    if not methods.empty:
        methods = methods.sort_values(by="start_line")

    lines = [f"📍 Class: {qualified_name} ({target['type_kind']})",
             f"File: {file_rel}:L{int(target['start_line'])}-L{int(target['body_end_line'])}"]
    mods = _clean_modifiers(target.get("modifiers"))
    if mods:
        lines.append(f"Modifiers: {mods}")
    lines += ["", "Declaration:", f"```java\n{declaration}\n```"]

    lines += ["", f"Fields ({len(fields)}):"]
    if fields.empty:
        lines.append("  (none)")
    for _, f in fields.iterrows():
        lines.append(f"  - {_clean_modifiers(f.get('modifiers'))} {f['type']} {f['name']}  [L{int(f['start_line'])}]")

    if not constructors.empty:
        lines += ["", f"Constructors ({len(constructors)}):"]
        for _, c in constructors.iterrows():
            lines.append(f"  - {_clean_modifiers(c.get('modifiers'))} {c['string_signature']}  "
                         f"[L{int(c['start_line'])}-L{int(c['body_end_line'])}]")

    lines += ["", f"Methods ({len(methods)}):"]
    if methods.empty:
        lines.append("  (none)")
    for _, m in methods.iterrows():
        ann = _simple_names(m.get("annotations"))
        ann_str = f"  @{ann.replace(', ', ', @')}" if ann else ""
        lines.append(f"  - {_clean_modifiers(m.get('modifiers'))} {m['return_type']} {m['string_signature']}  "
                     f"[L{int(m['start_line'])}-L{int(m['body_end_line'])}]{ann_str}")

    # Note about CodeQL resolution behavior, to prevent misleading line numbers
    lines += [
        "",
        "💡 Note: The lists above include inherited fields/methods and implicit default constructors resolved by CodeQL. "
        "Some of them may not physically exist in this source file (e.g., their line numbers might overlap with the class declaration). "
        "Use `read_file_content` or `get_method_definition` to verify and read the actual source code."
    ]
    
    lines += ["", 'Use `get_method_definition(class_qualified_name="...", method_name="...", line_number=N)` to inspect specific method bodies.']
    return "\n".join(lines)

# ==========================================
# 5. search_method: method lookup
# ==========================================
@tool
def search_method(
    name_pattern: str = "",
    config: RunnableConfig = None,
    class_name_pattern: Optional[str] = None,
    annotation: Optional[str] = None,
    max_results: int = 40,
    offset: int = 0,
) -> str:
    """Search Java methods/constructors in the project. Supports combined filtering by method name, declaring class and annotations (conditions are ANDed).

    Args:
        name_pattern: Method-name match (substring, e.g. "sanitize", "execute"). Pass "" to skip name filtering.
                      A constructor's name is the simple name of its class and can be matched here too.
                      All filter parameters use **literal substring** matching, not regex; use `grep_code` when regex is needed.
        class_name_pattern: (optional) Declaring-class filter (qualified or simple name, e.g. "UserService", "com.example.service").
                            Substring match; omit to skip.
        annotation: (optional) Method annotation filter (e.g. "GetMapping", "Override"), substring match. Omit to skip.
        max_results: Maximum results per call, default 40.
        offset: Pagination offset, default 0 (e.g. after 40 results, pass offset=40 for the next page).

    Returns:
        Metadata for matching methods (qualified class name, signature, return type, line, file,
        modifiers, annotations).
        To read a method's full source, use `get_method_definition(class_qualified_name="...", method_name="...", line_number=N)`.
    """
    idx = get_symbol_indices(config["configurable"]["project_data_path"])

    df = idx.func_details
    if df is None or df.empty:
        return "❌ Error: Method index not available."
    mask = pd.Series(True, index=df.index)

    # 1. Build the filter mask
    if name_pattern:
        mask &= df["name"].str.contains(name_pattern, case=False, na=False, regex=False)
    if class_name_pattern:
        mask &= df["class_qualified_name"].str.contains(class_name_pattern, case=False, na=False, regex=False)
    if annotation:
        mask &= df["annotations"].str.contains(annotation, case=False, na=False, regex=False)

    matched = df[mask]
    total = len(matched)

    if total == 0:
        return "✅ No methods found matching the criteria."

    # 2. Stable ordering for deterministic pagination
    matched = matched.sort_values(by=["file", "start_line"])

    # 3. Pagination slice
    page_data = matched.iloc[offset:offset + max_results]
    if page_data.empty:
        return f"⚠️ Offset {offset} is out of bounds. Total matches: {total}."

    # 4. Format the output
    lines = [f"🔍 Found {total} methods matching criteria (showing {offset + 1} to {offset + len(page_data)}):"]
    for i, (_, r) in enumerate(page_data.iterrows(), start=offset + 1):
        kind = f"  [{r['type_kind']}]" if r["type_kind"] == "Constructor" else ""
        lines.append(f"\n[{i}] {r['class_qualified_name']}.{r['string_signature']} -> {r['return_type']}{kind}")
        lines.append(f"    line_number: {int(r['start_line'])} | File: {r['file']}")

        modifiers = _clean_modifiers(r.get("modifiers"))
        annotations = _simple_names(r.get("annotations"))
        if modifiers or annotations:
            extra = []
            if modifiers:
                extra.append(f"Modifiers: {modifiers}")
            if annotations:
                extra.append(f"Annotations: @{annotations.replace(', ', ', @')}")
            lines.append(f"    {' | '.join(extra)}")

    # 5. Pagination and follow-up hints
    lines.append("")
    if offset + max_results < total:
        lines.append(f"💡 There are {total - (offset + max_results)} more results. Use `offset={offset + max_results}` to view the next page.")
    else:
        lines.append("💡 You have reached the end of the results.")

    lines.append('💡 To read the full source of a method, use `get_method_definition(class_qualified_name="...", method_name="...", line_number=N)`.')

    return "\n".join(lines)

# ==========================================
# 6. get_method_definition (exact read)
# ==========================================
@tool
def get_method_definition(
    class_qualified_name: str,
    method_name: str,
    config: RunnableConfig,
    line_number: Optional[int] = None,
) -> str:
    """Read the full source of a method/constructor exactly (annotations, signature and body). This is an exact-read tool, not a fuzzy search; use search_method to discover candidates.

    Args:
        class_qualified_name: Fully qualified name of the declaring class (e.g. "com.example.controller.UserController"), exact match.
                              Copy it directly from search_method / search_class output.
        method_name: Method name (e.g. "updateToken"), exact match.
                     A constructor's name is the simple name of its class (for class UserController, pass "UserController").
        line_number: (optional) Start line of the method definition, used to disambiguate overloads.
                     Omit when the method has no overloads; when omitted no line filter is applied.
                     When several methods share the name (overloads), the line_number from search_method is required.

    Returns:
        Unique match: the full method source snippet (from the annotation lines through the end of the body).
        Overloads: a candidate list (line_number and signature of each), to re-invoke with line_number.
        No match: an error suggesting search_method to confirm the qualified class and method names.
    """
    project_root = config["configurable"]["project_root"]
    func_df = get_symbol_indices(config["configurable"]["project_data_path"]).func_details
    
    mask = (func_df["class_qualified_name"] == class_qualified_name) & \
           (func_df["name"] == method_name)
           
    if line_number is not None:
        mask &= (func_df["start_line"] == line_number)
        
    candidates = func_df[mask]
    if candidates.empty:
        return (f"❌ Method `{class_qualified_name}.{method_name}` not found" +
                (f" at line {line_number}" if line_number is not None else "") +
                f". Use search_method(name_pattern=\"{method_name}\") to verify the exact class and name.")
    if len(candidates) > 1:
        return f"⚠️ Found {len(candidates)} overloaded methods. Please specify line_number:\n" + \
               "\n".join([f"- line_number: {int(r['start_line'])} {r['string_signature']}" for _, r in candidates.iterrows()])
               
    row = candidates.iloc[0]
    code = _read_code_by_loc(project_root, row["file"], int(row["annotations_start_line"]), int(row["body_end_line"]))
    return f"📍 Found method in `{row['file']}`:\n\n```java\n{code}\n```"


# ==========================================
# 7. search_usage (call/instantiation site tracing)
# ==========================================
@tool
def search_usage(
    callee_name_pattern: str = "",
    config: RunnableConfig = None,
    callee_class_pattern: Optional[str] = None,
    callee_qualified_name: Optional[str] = None,
    max_results: int = 40,
    offset: int = 0,
) -> str:
    """Find call sites of methods/constructors in the project (including calls to third-party methods and calls in class-level initializers such as field initializers and static blocks).

    Two modes:
    1. Exact mode (data-flow tracing): pass callee_qualified_name to find every call site of one method;
    2. Fuzzy mode (risk scanning): pass callee_name_pattern / callee_class_pattern for substring
       matching, suitable for scanning risky calls such as "execute", "run", "write".

    Args:
        callee_qualified_name: (optional) Fully qualified callee name (e.g. "java.lang.Runtime.exec"), exact match.
                               When given, the two fuzzy parameters below are ignored.
                               Constructor calls use the form "java.io.FileInputStream.FileInputStream".
        callee_name_pattern: Callee simple-name match (substring, e.g. "execute").
                             Accepts comma-separated patterns OR-ed together (e.g. "execute,run,eval") for batch scanning.
                             Pass "" to skip name filtering.
                             For constructor calls the callee name is the class simple name (e.g. "FileInputStream" finds all instantiations).
                             All filter parameters use **literal substring** matching, not regex; use the comma form for multiple values.
        callee_class_pattern: (optional) Fully qualified declaring-class match (substring, e.g. "Runtime", "java.io").
                              Omit to skip class filtering.
        max_results: Maximum results per call, default 40.
        offset: Pagination offset, default 0 (e.g. after 40 results, pass offset=40 for the next page).

    Returns:
        Call sites (caller file, line range, caller context, callee signature and kind Method/Constructor).
        To read the full call with actual arguments, use
        `read_file_content(file_path=..., start_line=<call start>, end_line=<call end>)`.
    """
    idx = get_symbol_indices(config["configurable"]["project_data_path"])

    df = idx.call
    if df is None or df.empty:
        return "❌ Error: Call graph index not available."

    # ============ Priority 1: exact qualified name ============
    if callee_qualified_name:
        parts = callee_qualified_name.rsplit(".", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            return "❌ Invalid callee_qualified_name format. Use 'package.ClassName.methodName'."
        c_class, c_name = parts
        mask = (df["callee_class"] == c_class) & (df["callee_name"] == c_name)
    # ============ Priority 2: fuzzy matching (conditions ANDed) ============
    else:
        mask = pd.Series(True, index=df.index)
        if callee_name_pattern:
            # Comma-separated patterns OR-ed together
            patterns = [p.strip() for p in callee_name_pattern.split(",") if p.strip()]
            name_mask = pd.Series(False, index=df.index)
            for p in patterns:
                name_mask |= df["callee_name"].str.contains(p, case=False, na=False, regex=False)
            mask &= name_mask
        if callee_class_pattern:
            mask &= df["callee_class"].str.contains(callee_class_pattern, case=False, na=False, regex=False)

    matched = df[mask]
    total = len(matched)

    if total == 0:
        if callee_qualified_name:
            return (f"✅ No usages found for '{callee_qualified_name}'. "
                    f"Try fuzzy mode: search_usage(callee_name_pattern=\"{callee_qualified_name.rsplit('.', 1)[-1]}\").")
        return "✅ No usages found matching the criteria."

    # Stable ordering for deterministic pagination
    matched = matched.sort_values(by=["caller_file", "caller_start_line"])

    # Pagination slice
    page_data = matched.iloc[offset:offset + max_results]
    if page_data.empty:
        return f"⚠️ Offset {offset} is out of bounds. Total matches: {total}."

    # Format the output
    lines = [f"🔍 Found {total} usages (showing {offset + 1} to {offset + len(page_data)}):"]
    for _, r in page_data.iterrows():
        lines.append(
            f"- {r['caller_file']}:L{int(r['caller_start_line'])}-L{int(r['caller_end_line'])} "
            f"(in {r['caller_context']}) -> [{r['callee_type']}] {r['callee_class']}.{r['callee_signature']}"
        )

    # Pagination and follow-up hints
    lines.append("")
    if offset + max_results < total:
        lines.append(f"💡 There are {total - (offset + max_results)} more results. Use `offset={offset + max_results}` to view the next page, "
                     f"or narrow the search with callee_class_pattern.")
    else:
        lines.append("💡 You have reached the end of the results.")

    lines.append('💡 To inspect the full call including actual arguments, use '
                 '`read_file_content(file_path="...", start_line=N, end_line=M)` with the line range shown above.')

    return "\n".join(lines)