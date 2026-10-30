#!/usr/bin/env python3
"""
T1 -- fusion round-1 prompt replay (zero LLM / zero CodeQL).

Background: the round-1 dedup verdict must stay byte-identical across releases, because
round 1 is the read-only "pre-existing knowledge" round. This script takes **real
production** fusion request transcripts from an archived batch, re-renders them through the
current rendering entry point, and asserts byte equality. If that holds, round-1 LLM
behavior is unchanged and later modules cannot alter the surviving set.

Three assertions (run for every archived project):
  A1  system_prompt byte-identical (including the GLOBAL_SYSTEM_PROMPT prefix)
  A2  user_prompt   byte-identical (including the serialized all_specs_json, i.e. digest
      construction plus json.dumps arguments)
  A3  the spec_id set in analyzer_final_state == all digests - discarded_spec_ids of the
      verdict response

Usage:
    python T1_fusion_round1_replay.py [--archive <archive_dir>] [--limit N]

The archive must have been produced by this release (or an older one whose round-1 prompts
are byte-identical); set T1_ARCHIVE or pass --archive.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Import this release's own package
VERSION_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(VERSION_ROOT))

from analysis_agent.fusion import _render_fusion_prompts  # noqa: E402

DEFAULT_ARCHIVE = Path(os.environ.get(
    "T1_ARCHIVE",
    str(VERSION_ROOT / "test/data/fusion_replay"),
))

HEAD_MARKER = "[Global specification digest (with origin_direction)]\n"
TAIL_MARKER = "\n\n========================================\n[Output format and data-structure dictionary (strictly follow)]"


def split_archived_user_prompt(user_prompt: str):
    """Extract and deserialize all_specs_json from an archived user_prompt."""
    start = user_prompt.index(HEAD_MARKER) + len(HEAD_MARKER)
    end = user_prompt.index(TAIL_MARKER, start)
    return json.loads(user_prompt[start:end])


def last_discarded_ids(fusion_dir: Path):
    """Return discarded_spec_ids from the latest verdict response."""
    tries = sorted(fusion_dir.glob("tries_*_response.json"),
                   key=lambda p: int(p.stem.split("_")[1]))
    for path in reversed(tries):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        content = raw.get("data", {}).get("content")
        if not isinstance(content, str):
            continue
        text = content.strip()
        if text.startswith("```"):
            text = text.strip("`")
            text = text[text.index("{"):text.rindex("}") + 1]
        try:
            parsed = json.loads(text)
        except Exception:
            continue
        if isinstance(parsed, dict) and "discarded_spec_ids" in parsed:
            return list(parsed["discarded_spec_ids"]), path.name
    return None, None


def check_project(prompt_file: Path) -> tuple[bool, str]:
    fusion_dir = prompt_file.parent
    archived = json.loads(prompt_file.read_text(encoding="utf-8"))
    archived_user = archived["user_prompt"]
    archived_system = archived["system_prompt"]

    summaries = split_archived_user_prompt(archived_user)
    system_prompt, user_prompt = _render_fusion_prompts(summaries)

    if system_prompt != archived_system:
        return False, "A1 system_prompt mismatch"
    if user_prompt != archived_user:
        return False, "A2 user_prompt mismatch"

    final_state = fusion_dir.parents[1] / "analyzer_final_state.json"
    if not final_state.exists():
        return True, "A1/A2 ok (no analyzer_final_state; A3 skipped)"
    kept_state = json.loads(final_state.read_text(encoding="utf-8"))
    kept_ids = {s["spec_id"] for s in kept_state["taint_specifications"]}

    discarded, resp_name = last_discarded_ids(fusion_dir)
    if discarded is None:
        return True, "A1/A2 ok (no usable verdict response; A3 skipped)"
    all_ids = {s["spec_id"] for s in summaries}
    expect_kept = all_ids - set(discarded)
    if expect_kept != kept_ids:
        return False, (f"A3 mismatch: expected to keep {len(expect_kept)}, archive has {len(kept_ids)}, "
                       f"delta {sorted(expect_kept ^ kept_ids)[:5]} (response {resp_name})")
    return True, f"A1/A2/A3 ok ({len(all_ids)} digests -> {len(kept_ids)} kept, {len(discarded)} discarded)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", default=str(DEFAULT_ARCHIVE))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    root = Path(args.archive)
    if not root.is_dir():
        print(f"✗ archive root does not exist: {root}")
        return 1

    files = sorted(root.glob("*/**/logs/analysis_agent/fusion/fusion_dedup_prompt.json"))
    if args.limit:
        files = files[: args.limit]
    if not files:
        print(f"✗ no fusion_dedup_prompt.json found under: {root}")
        return 1

    print(f"== T1 fusion round-1 replay: {len(files)} projects ==")
    ok = bad = 0
    for path in files:
        slug = path.relative_to(root).parts[0]
        try:
            passed, msg = check_project(path)
        except Exception as e:  # noqa: BLE001
            passed, msg = False, f"exception {type(e).__name__}: {e}"
        if passed:
            ok += 1
        else:
            bad += 1
            print(f"  ✗ {slug}: {msg}")
    print(f"\nResult: {ok}/{len(files)} passed, {bad} failed")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
