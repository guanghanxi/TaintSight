"""
predicate_guard.py
Static predicate soundness check: detects disjuncts in LLM-generated CodeQL
predicates that leave node variables unconstrained.

Background:
In QL, `and` binds tighter than `or`, so `A and B or C and D` parses as
`(A and B) or (C and D)`. If any disjunct leaves a node variable unconstrained
(node for source/sink, node1/node2 for flow_step, c for summary), the predicate
is true for any node in the program. Match sets can then explode while still
being non-empty and hitting the ground-truth path, so weaker validation passes
them silently.

This module calls no LLM, does not depend on CodeQL, and performs no semantic
analysis: it recursively judges the syntax of the predicate body so rewriting
feedback can point at the offending disjunct. Actual blocking is decided by
ResultValidator.

Rules:
  top-level or  -> every disjunct must guarantee binding
  top-level and -> any conjunct guaranteeing binding is enough
  leaf          -> occurrence of `<var>.` counts as bound
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Predicate signature: predicate <name>(<params>)
_PRED_SIG_RE = re.compile(r"\bpredicate\s+([A-Za-z_]\w*)\s*\(", re.S)
_BINDER_RE = re.compile(r"\b(exists|forall)\s*\(")
_KEYWORD_RE = {"and": re.compile(r"\band\b"), "or": re.compile(r"\bor\b")}


# ============================================================
#  1. Lexical pass: identify literals before comments
# ============================================================

# Characters inside literals that confuse structural parsing: brackets change depth, `|` looks like a binder separator
_LITERAL_NEUTRALIZE = str.maketrans({c: "_" for c in "()[]{}|"})
# and / or inside literals would be split into boolean terms
_WORD_NEUTRALIZE_RE = re.compile(r"\b(?:and|or)\b")


def sanitize_for_parsing(ql: str) -> str:
    """
    Single pass: strip `//` and `/* */` comments and neutralize characters in
    string literals that would confuse structural parsing (brackets, `|`,
    standalone `and`/`or`). Everything else is preserved with character length
    unchanged, so reported snippets remain readable to the model.

    The order matters: string literals must be recognized before comments.
    Otherwise a `//` inside a literal such as an XML namespace URL is treated as
    a line comment, quotes go out of sync and the rest of the body is swallowed.
    """
    out: List[str] = []
    i, n = 0, len(ql)
    while i < n:
        ch = ql[i]

        # String literals (support \" escapes)
        if ch == '"':
            j = i + 1
            while j < n:
                if ql[j] == "\\":
                    j += 2
                    continue
                if ql[j] == '"':
                    j += 1
                    break
                j += 1
            literal = ql[i:j]
            masked = literal.translate(_LITERAL_NEUTRALIZE)
            out.append(_WORD_NEUTRALIZE_RE.sub(
                lambda m: "_" * len(m.group(0)), masked,
            ))
            i = j
            continue

        # Line comment
        if ch == "/" and i + 1 < n and ql[i + 1] == "/":
            j = ql.find("\n", i)
            if j == -1:
                break
            i = j
            continue

        # Block comment
        if ch == "/" and i + 1 < n and ql[i + 1] == "*":
            j = ql.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue

        out.append(ch)
        i += 1

    return "".join(out)


# ============================================================
#  2. Predicate signature and body extraction
# ============================================================

def _split_top_level_commas(text: str) -> List[str]:
    """Split on depth-0 commas (commas inside generics such as `Map<A, B>` are kept)."""
    parts, depth, start = [], 0, 0
    for i, c in enumerate(text):
        if c in "<([{":
            depth += 1
        elif c in ">)]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


_IDENT_RE = re.compile(r"[A-Za-z_]\w*")


def parse_predicate_params(predicate_code: str) -> Tuple[str, List[str]]:
    """
    Parse `predicate <name>(<params>)` and return (predicate name, parameter names).

    Each parameter name is the last identifier in its declaration
    (`DataFlow::Node node1` -> `node1`; `Call c` -> `c`). Names are parsed from
    the predicate's own signature rather than hardcoded per role, so renaming
    by the model cannot defeat the check.
    """
    m = _PRED_SIG_RE.search(predicate_code)
    if not m:
        return "", []

    # Locate the right bracket matching the signature's left bracket
    open_idx = predicate_code.index("(", m.start())
    depth, close_idx = 0, -1
    for i in range(open_idx, len(predicate_code)):
        c = predicate_code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                close_idx = i
                break
    if close_idx == -1:
        return m.group(1), []

    names: List[str] = []
    for param in _split_top_level_commas(predicate_code[open_idx + 1: close_idx]):
        idents = _IDENT_RE.findall(param)
        if idents:
            names.append(idents[-1])
    return m.group(1), names


def extract_predicate_body(predicate_code: str) -> Optional[str]:
    """Extract the brace-delimited body; None if there is no signature or no matching brace."""
    m = _PRED_SIG_RE.search(predicate_code)
    if not m:
        return None
    start = predicate_code.find("{", m.end())
    if start == -1:
        return None

    depth = 0
    for i in range(start, len(predicate_code)):
        c = predicate_code[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return predicate_code[start + 1: i]
    return None


# ============================================================
#  3. Recursive boolean-structure analysis
# ============================================================

def _split_top_level(expr: str, keyword: str) -> List[str]:
    """
    Split on `and` / `or` keywords at grouping-bracket depth 0.

    Only () / [] / {} are tracked, not < >. In QL, `<` is both a generic
    argument delimiter and a comparison operator and cannot be distinguished
    statically; treating `<` in `a < b and c` as an opening bracket would hide
    the following `and`. Generic arguments never contain `and` / `or` / `|`,
    so ignoring < > is safe.
    """
    pat = _KEYWORD_RE[keyword]
    parts: List[str] = []
    depth, start, i, n = 0, 0, 0, len(expr)
    while i < n:
        c = expr[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0:
            m = pat.match(expr, i)
            if m:
                parts.append(expr[start:i])
                i = m.end()
                start = i
                continue
        i += 1
    parts.append(expr[start:])
    return [p.strip() for p in parts]


def _strip_parens(expr: str) -> str:
    """Strip outer parentheses that wrap the entire expression."""
    e = expr.strip()
    while len(e) >= 2 and e.startswith("(") and e.endswith(")"):
        depth, matched = 0, -1
        for i, c in enumerate(e):
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    matched = i
                    break
        if matched != len(e) - 1:
            break
        e = e[1:-1].strip()
    return e


def _normalize_binders(expr: str) -> str:
    """
    Normalize `exists(vars | BODY)` / `forall(vars | BODY)` to `(BODY)` while
    preserving surrounding context.

    Do not replace the whole expression with the first exists body: in
    `exists(...) and exists(...)`, later exists binders (often binding node2)
    would be dropped and cause false positives.
    """
    out: List[str] = []
    i, n = 0, len(expr)
    while i < n:
        m = _BINDER_RE.match(expr, i)
        if not m:
            out.append(expr[i])
            i += 1
            continue

        open_idx = m.end() - 1                      # binder's opening bracket
        # Locate the matching closing bracket and the depth-1 `|` in one pass.
        # Breaking as soon as `|` is found would leave close_idx at -1 and the
        # binder would be treated as incomplete and skipped, hiding real defects.
        depth, close_idx, bar = 0, -1, -1
        j = open_idx
        while j < n:
            c = expr[j]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    close_idx = j
                    break
            elif c == "|" and depth == 1 and bar == -1:
                prev = expr[j - 1] if j > 0 else ""
                nxt = expr[j + 1] if j + 1 < n else ""
                if prev != "|" and nxt != "|":
                    bar = j
            j += 1

        if bar == -1 or close_idx == -1:
            # Incomplete syntax: keep as-is to avoid false judgments
            end = close_idx + 1 if close_idx != -1 else n
            out.append(expr[i:end])
            i = end
            continue

        out.append("(" + _normalize_binders(expr[bar + 1: close_idx]) + ")")
        i = close_idx + 1

    return "".join(out)


def _var_bound_re(var: str) -> re.Pattern:
    """`<var>.` -- its occurrence means the node variable is bound."""
    return re.compile(r"\b" + re.escape(var) + r"\s*\.")


def _guarantees_binding(expr: str, var: str) -> bool:
    """Recursively decide whether the boolean expression guarantees binding of var."""
    e = _strip_parens(_normalize_binders(expr))

    ors = _split_top_level(e, "or")
    if len(ors) > 1:
        return all(_guarantees_binding(b, var) for b in ors)

    ands = _split_top_level(e, "and")
    if len(ands) > 1:
        return any(_guarantees_binding(a, var) for a in ands)

    return bool(_var_bound_re(var).search(e))


def _collect_unbound(expr: str, var: str, out: List[Dict[str, str]]) -> bool:
    """
    Recursively collect fragments that leave var unbound; return whether the
    expression guarantees binding.

    Only top-level or branches and leaves with no binding conjunct are
    reported: those are the places the model must fix.
    """
    e = _strip_parens(_normalize_binders(expr))

    ors = _split_top_level(e, "or")
    if len(ors) > 1:
        ok = True
        for branch in ors:
            if not _collect_unbound(branch, var, out):
                ok = False
        return ok

    ands = _split_top_level(e, "and")
    if len(ands) > 1:
        if any(_guarantees_binding(a, var) for a in ands):
            return True
        out.append({"var": var, "branch": _snippet(e)})
        return False

    if _var_bound_re(var).search(e):
        return True
    out.append({"var": var, "branch": _snippet(e)})
    return False


def _snippet(expr: str, max_len: int = 240) -> str:
    """Flatten to one line and truncate for feedback text."""
    flat = " ".join(expr.split())
    return flat if len(flat) <= max_len else flat[:max_len] + " …"


# ============================================================
#  4. Public entry point
# ============================================================

@dataclass
class PredicateCheck:
    """Result of one predicate soundness check."""
    checked: bool                                    # whether the predicate and parameters parsed
    predicate_name: str = ""
    vars: List[str] = field(default_factory=list)    # node variable names parsed from the signature
    unbound: List[Dict[str, str]] = field(default_factory=list)   # [{var, branch}]

    @property
    def sound(self) -> bool:
        """Parsed successfully and no unbound disjuncts."""
        return self.checked and not self.unbound


def check_predicate(predicate_code: str) -> PredicateCheck:
    """
    Check whether a predicate has a disjunct with unconstrained node variables.

    If the signature or body cannot be parsed, return `checked=False`; the
    caller should fall back to generic feedback and not block (prefer a missed
    detection over a false accusation).
    """
    if not predicate_code:
        return PredicateCheck(checked=False)

    # Lexical pass must precede body extraction: literals and comments confuse structural parsing
    cleaned = sanitize_for_parsing(predicate_code)
    name, vars_ = parse_predicate_params(cleaned)
    body = extract_predicate_body(cleaned)
    if not name or not vars_ or body is None:
        return PredicateCheck(checked=False, predicate_name=name, vars=vars_)

    unbound: List[Dict[str, str]] = []
    for var in vars_:
        _collect_unbound(body, var, unbound)

    # The same fragment may be reported for several variables; dedupe, keep order
    seen, deduped = set(), []
    for item in unbound:
        key = (item["var"], item["branch"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)

    return PredicateCheck(
        checked=True, predicate_name=name, vars=vars_, unbound=deduped,
    )
