from pathlib import Path
from typing import List, Optional, Tuple
from collections import OrderedDict
import difflib
import os
import re
import threading
from pydantic import BaseModel, Field
from analysis_agent.executor_agent.executor_data_model import CodeResult


class VerifyStatus(str):
    FILE_NOT_FOUND = "file_not_found"
    NOT_A_FILE = "not_a_file"        # not a regular readable file (often a directory)
    CODE_MISMATCH = "code_mismatch"
    SUCCESS = "success"
    NOT_PROJECT_CODE = "not_project_code"


class VerifyResult(BaseModel):
    status: str
    message: str = ""
    resolved_file_path: Optional[str] = None  # path actually resolved on disk


class CodeResultVerifier:
    def __init__(
        self,
        project_root: str,
        line_threshold: float = 0.6,   # minimum similarity for a single line match
        fragment_threshold: float = 0.5, # minimum similarity for a code block match
        max_cached_files: int = 64,   # maximum number of cached files
    ):
        self.project_root = Path(project_root)
        self.line_threshold = line_threshold
        self.fragment_threshold = fragment_threshold
        # Bounded LRU cache: reuse normalized line sets of hot files while capping memory
        self._max_cached_files = max_cached_files
        self._file_cache: "OrderedDict[str, set[str]]" = OrderedDict()

    def verify(self, result: CodeResult) -> VerifyResult:
        """Two-step check: file first, then code content"""

        # Not project code
        if not result.is_from_project:
            return VerifyResult(
                status=VerifyStatus.NOT_PROJECT_CODE,
                message="External code, no verification needed"
            )

        # File path validation
        if not result.file_path:
            return VerifyResult(
                status=VerifyStatus.FILE_NOT_FOUND,
                message="file_path is empty"
            )

        file_path = self._resolve_file(result.file_path)
        if not file_path:
            return VerifyResult(
                status=VerifyStatus.FILE_NOT_FOUND,
                message=f"File Path not found: {result.file_path}"
            )
        
        # Compute the relative path
        rel_path = self._to_relative(file_path)

        # Must be a regular file (not a directory, device, or permission-denied path)
        if not file_path.is_file():
            return VerifyResult(
                status=VerifyStatus.NOT_A_FILE,
                message=f"Path is not a regular file: {rel_path}",
                resolved_file_path=rel_path
            )
        
        # Code content validation
        source_lines = self._get_source_lines(file_path)
        code_matched = self._verify_fragments(source_lines, result.code_snippet)

        if not code_matched:
            return VerifyResult(
                status=VerifyStatus.CODE_MISMATCH,
                message=f"Code does not appear to be from {file_path}",
                resolved_file_path=rel_path
            )

        return VerifyResult(
            status=VerifyStatus.SUCCESS,
            message=f"Verified: code from {file_path}",
            resolved_file_path=rel_path
        )

    def _verify_fragments(self, source_lines: set[str], fragments: List[str]) -> bool:
        """Validate all fragments: the overall matched-line ratio must reach the threshold"""

        total_lines = 0
        matched_lines = 0

        for fragment in fragments:
            fragment_lines = [l for l in fragment.strip().split('\n') if l.strip()]
            if not fragment_lines:
                continue

            total_lines += len(fragment_lines)
            for line in fragment_lines:
                if self._find_line_in_source(line, source_lines):
                    matched_lines += 1

        # Judge over the whole input: all lines of all fragments counted together
        if total_lines == 0:
            return False

        overall_ratio = matched_lines / total_lines
        return overall_ratio >= self.fragment_threshold

    def check_snippet_containment(
        self,
        example_snippet: List[str],
        reference_snippet: List[str],
        threshold: float = 0.8,
    ) -> Tuple[bool, float, List[str]]:
        """Check whether example_snippet is a (fuzzy) subset of reference_snippet.

        Unlike the symmetric ratio in verify(), this only requires every line of the example to
        be found in the cited evidence entry. A specification example is by design a
        [focused subset] of the upstream evidence entry: `result_data_prompt.md` asks for
        "only the most distinctive core statements, ignoring long unrelated logic in between",
        so a symmetric ratio against the larger original text is structurally unsatisfiable.

        :return: (passed, hit coverage, list of unmatched lines)
        """
        ref_lines: set[str] = set()
        for fragment in reference_snippet or []:
            for line in fragment.strip().split('\n'):
                normalized = self._normalize(line)
                if normalized:
                    ref_lines.add(normalized)

        total_lines = 0
        unmatched: List[str] = []
        for fragment in example_snippet or []:
            for line in fragment.strip().split('\n'):
                if not line.strip():
                    continue
                total_lines += 1
                if not self._find_line_in_source(line, ref_lines):
                    unmatched.append(line.strip())

        if total_lines == 0:
            return False, 0.0, []

        coverage = (total_lines - len(unmatched)) / total_lines
        return coverage >= threshold, coverage, unmatched

    def _find_line_in_source(self, line: str, source_lines: set[str]) -> bool:
        """Whether a single line is found in the file (fuzzy match)"""
        normalized = self._normalize(line)
        if not normalized:
            return True

        if normalized in source_lines:
            return True

        best = max(
            (difflib.SequenceMatcher(None, normalized, s).ratio() for s in source_lines),
            default=0
        )
        return best >= self.line_threshold

    def _get_source_lines(self, file_path: Path) -> set[str]:
        """Read and cache the normalized line set (LRU eviction bounds memory)"""
        key = str(file_path)
        if key in self._file_cache:
            self._file_cache.move_to_end(key)   # hit: refresh recency
            return self._file_cache[key]

        text = file_path.read_text(encoding='utf-8', errors='ignore')
        lines = {self._normalize(l) for l in text.split('\n') if self._normalize(l)}

        self._file_cache[key] = lines
        while len(self._file_cache) > self._max_cached_files:
            self._file_cache.popitem(last=False)  # evict the least recently used
        return lines

    def clear_cache(self):
        """Clear the file cache manually"""
        self._file_cache.clear()

    def _normalize(self, text: str) -> str:
        """Normalize a code line"""
        text = text.strip()
        text = re.sub(r'//.*$', '', text)
        text = re.sub(r'/\*.*?\*/', '', text)
        text = re.sub(r'\s+', ' ', text)
        text = text.replace("'", '"')
        return text.strip()

    def _resolve_file(self, file_path: str) -> Optional[Path]:
        """Resolve a file path"""
        direct = self.project_root / file_path
        if direct.exists():
            return direct

        # Fall back to matching by file name
        basename = Path(file_path).name
        candidates = list(self.project_root.rglob(basename))
        if len(candidates) == 1:
            return candidates[0]
        
        if len(candidates) > 1:
            return max(
                candidates,
                key=lambda p: difflib.SequenceMatcher(None, str(p), file_path).ratio()
            )
        
        return None
    
    def _to_relative(self, file_path: Path) -> str:
        """Convert to a path relative to project_root"""
        try:
            return str(file_path.relative_to(self.project_root))
        except ValueError:
            return str(file_path)
        
# Multi-instance cache keyed by (project, thresholds, cache size) so concurrent projects
# do not interfere. A single shared "current project" instance is unsafe: thread A could get
# thread B's verifier and resolve A's evidence against B's project_root, misreporting it as
# file_not_found / code_mismatch. Each verifier owns its own _file_cache, so reuse must be
# keyed; lookups and inserts happen under the same short lock.
_MAX_CACHED_VERIFIERS = 4

_verifier_cache: "OrderedDict[tuple, CodeResultVerifier]" = OrderedDict()
_verifier_cache_lock = threading.Lock()


def get_verifier(
    project_root: str,
    line_threshold: float = 0.8,
    fragment_threshold: float = 0.75,
    max_cached_files: int = 32,
) -> CodeResultVerifier:
    """Return the CodeResultVerifier for this (project, thresholds, cache size) combination.

    - The same key reuses one instance, maximizing hot-file hits in its _file_cache;
    - Different keys get independent instances that never overwrite each other.
    """
    # Normalize Path/str and include max_cached_files in the key (a key without it returns an
    # instance with the wrong cache size).
    key = (os.path.abspath(str(project_root)), line_threshold, fragment_threshold, max_cached_files)

    # Fast path: table lookup plus LRU refresh under a short lock
    with _verifier_cache_lock:
        hit = _verifier_cache.get(key)
        if hit is not None:
            _verifier_cache.move_to_end(key)
            return hit

    # Construction is cheap (Path + OrderedDict, no disk I/O), so keep it outside the lock
    candidate = CodeResultVerifier(
        project_root=project_root,
        line_threshold=line_threshold,
        fragment_threshold=fragment_threshold,
        max_cached_files=max_cached_files,
    )

    with _verifier_cache_lock:
        existing = _verifier_cache.get(key)
        if existing is not None:
            _verifier_cache.move_to_end(key)
            return existing
        _verifier_cache[key] = candidate
        while len(_verifier_cache) > _MAX_CACHED_VERIFIERS:
            _verifier_cache.popitem(last=False)
        return candidate


def clear_verifier_cache():
    """Clear the verifier cache."""
    with _verifier_cache_lock:
        _verifier_cache.clear()


# ========== Usage ==========

# verifier = CodeResultVerifier(
#     project_root="/path/to/project",
#     line_threshold=0.6,
#     fragment_threshold=0.5
# )

# result = CodeResult(
#     code_description="SQL injection",
#     is_from_project=True,
#     file_path="src/UserDao.java",
#     code_snippet=[
#         "public List<User> findByName(String name) {",
#         'String sql = "SELECT * FROM users WHERE name = \'" + name + "\'";',
#         "return jdbcTemplate.query(sql);"
#     ]
# )

# verify_result = verifier.verify(result)
# print(f"Status: {verify_result.status}")
# print(f"Resolved: {verify_result.resolved_file_path}")
# print(f"Message: {verify_result.message}")