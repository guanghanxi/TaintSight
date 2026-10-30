#!/usr/bin/env python3
"""
run_one.py -- run VulDetectPipeline on a single target.

Both inputs are exact paths to existing directories; no dataset layout is assumed:

  --project-source  the checked-out source tree of the target project
  --codeql-db       the CodeQL database built from that source tree

run_id      = <llm_tag>_<batch_ts>_<cwe_id>   (or --run-id)
analysis_id = CodeQL pack name; defaults to vuldetect/<sanitized project_slug>

The run is resumable: if a previous run already produced a SARIF result or a
deliberate "skipped" record under the same output directory, it is not repeated
unless --force is given.
"""
import argparse
import json
import logging
import os
import re
import sys
import traceback
from datetime import datetime

from vul_detect_agent import VulDetectPipeline
from codeql_ops.codeql_query_runner import PREPROCESS_SCRIPTS

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s][%(levelname)s] %(message)s")
log = logging.getLogger("run_one")


def run_id_sanitize(s) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", str(s)).strip("_")


def analysis_id_sanitize(name: str) -> str:
    """Return a QL pack name component (lowercase letters and digits only)."""
    return re.sub(r"[^a-z0-9]+", "", name.lower()) or "project"


def gen_run_paths(output_root: str, slug: str, run_id: str):
    project_path = os.path.join(output_root, slug)
    return (project_path,
            os.path.join(project_path, run_id, "logs"),
            os.path.join(project_path, run_id, "outputs"),
            os.path.join(project_path, run_id, "work_dir"))


def verify_product(out_dir: str) -> dict:
    """Check that the run produced a usable final product.

    A pipeline status of "completed" only means control flow reached the end.
    The CodeQL analysis may still have written nothing (for example when a
    circuit breaker skipped every remaining predicate), so the product itself
    is verified here.

    codeql_agent_skipped.json is a deliberate terminal state (the analyzer
    found no source/sink pair), and a SARIF with an empty results array is a
    valid "nothing found" conclusion. Only a missing/unparsable SARIF or one
    without runs is a failure.
    """
    if os.path.exists(os.path.join(out_dir, "codeql_agent_skipped.json")):
        return {"ok": True, "product": "skipped"}
    sarif = os.path.join(out_dir, "taint_analysis", "taint_analysis_result.sarif")
    if not os.path.exists(sarif):
        return {"ok": False, "product": None, "reason": "sarif_missing"}
    try:
        with open(sarif, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return {"ok": False, "product": None,
                "reason": f"sarif_unparsable: {type(e).__name__}: {e}"}
    if not data.get("runs"):
        return {"ok": False, "product": None, "reason": "sarif_no_runs"}
    return {"ok": True, "product": "sarif"}


def _scan_analysis_degradations(run_root: str) -> dict:
    """Collect analysis-side degradation records; return counts by kind.

    Records:
    - llm_degradation.json: the LLM call still failed after retries.
    - fallback.json: a deterministic fallback was produced after retries were
      exhausted.
    - budget_trim.json: the token budget guard trimmed the conversation.
    - PAIRING_VIOLATION.json: the tool-call pairing self-check was triggered.
    """
    analysis_root = os.path.join(run_root, "logs", "analysis_agent")
    out = {}
    if not os.path.isdir(analysis_root):
        return out

    for fname, key in (("llm_degradation.json", "llm_degradation"),
                       ("fallback.json", "analysis_fallback"),
                       ("budget_trim.json", "budget_trim"),
                       ("PAIRING_VIOLATION.json", "pairing_violation")):
        files = []
        for dirpath, _dirnames, filenames in os.walk(analysis_root):
            if fname in filenames:
                files.append(os.path.join(dirpath, fname))
        if not files:
            continue
        by_kind = {}
        for p in files:
            try:
                with open(p, encoding="utf-8") as f:
                    kind = json.load(f).get("kind") or "unknown"
            except Exception:
                kind = "unreadable"
            by_kind[kind] = by_kind.get(kind, 0) + 1
        out[key] = {"count": len(files), "by_kind": by_kind}
    return out


def degradation_markers(out_dir: str) -> dict:
    """Collect stage-3 and analysis-side degradation records.

    Their presence means the run finished but some conclusions came from a
    degraded path; surface them instead of reporting a clean "completed".
    """
    out = {}
    p = os.path.join(out_dir, "codeql_agent_circuit_break.json")
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
            out["circuit_break"] = {
                "consecutive_env_failures": d.get("consecutive_env_failures"),
                "tripped_by": d.get("tripped_by"),
                "skipped_specs": len(d.get("skipped_spec_ids") or []),
            }
        except Exception as e:
            out["circuit_break"] = {"error": f"{type(e).__name__}: {e}"}
    p = os.path.join(out_dir, "codeql_agent_assembly_guard.json")
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
            out["assembly_guard"] = {"missing_roles": d.get("missing_roles")}
        except Exception as e:
            out["assembly_guard"] = {"error": f"{type(e).__name__}: {e}"}
    out.update(_scan_analysis_degradations(os.path.dirname(os.path.abspath(out_dir))))
    return out


def _dump_exception(target_dir: str, filename: str, error_text: str, meta: dict):
    """Write exception details next to the run logs; never raise from here."""
    try:
        os.makedirs(target_dir, exist_ok=True)
        path = os.path.join(target_dir, f"{filename}.log")
        with open(path, "w", encoding="utf-8") as f:
            f.write("===== Pipeline Exception =====\n")
            f.write(f"Timestamp : {datetime.now().isoformat()}\n")
            f.write(f"Meta      :\n{json.dumps(meta, ensure_ascii=False, indent=2, default=str)}\n")
            f.write("\n===== Traceback =====\n")
            f.write(error_text)
            f.write("\n")
        log.info(f"Exception saved: {path}")
    except Exception as e:
        log.error(f"Could not save exception file {target_dir}/{filename}.log: {e}")


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="Run VulDetectPipeline on one project using exact source and CodeQL database paths.")
    ap.add_argument("--project-source", required=True,
                    help="Exact path to the target project's source tree")
    ap.add_argument("--codeql-db", required=True,
                    help="Exact path to a prebuilt CodeQL database for that source tree")
    ap.add_argument("--cwe-id", required=True, help="CWE identifier, e.g. CWE-078")
    ap.add_argument("--output-root", required=True,
                    help="Directory that receives <project_slug>/<run_id>/")
    ap.add_argument("--project-name", default=None,
                    help="Project identifier shown to the agents; <owner>/<repo> recommended "
                         "(default: source directory name)")
    ap.add_argument("--project-slug", default=None,
                    help="Name used in the output path (default: source directory name)")
    ap.add_argument("--analysis-id", default=None,
                    help="CodeQL pack name as <scope>/<name> (default: vuldetect/<sanitized project_slug>)")
    ap.add_argument("--run-id", default=None,
                    help="Explicit run id (default: <llm_tag>_<batch_ts>_<cwe_id>)")
    ap.add_argument("--batch-ts", default=None,
                    help="Timestamp placed in the default run id (default: now)")
    ap.add_argument("--provider", default="deepseek")
    ap.add_argument("--model", default="deepseek-flash")
    ap.add_argument("--llm-tag", default=None,
                    help="Prefix for the default run id (default: sanitized provider_model)")
    ap.add_argument("--llm-extra-kwargs", default=None,
                    help="JSON object merged into llm_config, e.g. '{\"temperature\": 0}'")
    ap.add_argument("--codeql-bin", default=os.environ.get("CODEQL_BIN", "codeql"))
    ap.add_argument("--codeql-script-dir", default=None,
                    help="Directory containing the six stage-1 .ql scripts (default: bundled codeql_scripts/)")
    ap.add_argument("--force", action="store_true",
                    help="Run even if a completion marker already exists")
    ap.add_argument("--dry-run", action="store_true",
                    help="Validate inputs, print the resolved configuration, and exit")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    project_source = os.path.abspath(args.project_source)
    codeql_db = os.path.abspath(args.codeql_db)
    output_root = os.path.abspath(args.output_root)

    if not os.path.isdir(project_source):
        raise SystemExit(f"--project-source is not a directory: {project_source}")
    if not os.path.isdir(codeql_db):
        raise SystemExit(f"--codeql-db is not a directory: {codeql_db}")
    if not os.path.exists(os.path.join(codeql_db, "codeql-database.yml")):
        raise SystemExit(f"--codeql-db does not look like a CodeQL database "
                         f"(missing codeql-database.yml): {codeql_db}")

    if args.codeql_script_dir:
        script_dir = os.path.abspath(args.codeql_script_dir)
        if not os.path.isdir(script_dir):
            raise SystemExit(f"--codeql-script-dir is not a directory: {script_dir}")
        missing = [n for n in PREPROCESS_SCRIPTS
                   if not os.path.exists(os.path.join(script_dir, f"{n}.ql"))]
        if missing:
            raise SystemExit(f"--codeql-script-dir {script_dir} is missing scripts {missing}; "
                             f"all six scripts are required")
    else:
        script_dir = None

    project_slug = args.project_slug or os.path.basename(os.path.normpath(project_source))
    project_name = args.project_name or project_slug
    if args.analysis_id:
        analysis_id = args.analysis_id.lower()
        # CodeQL pack names are <scope>/<name>; both parts use lowercase
        # letters, digits and hyphens. An invalid name is silently ignored by
        # the toolchain, so reject it here.
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*/[a-z0-9][a-z0-9-]*", analysis_id):
            raise SystemExit("--analysis-id must look like '<scope>/<name>' using "
                             "lowercase letters, digits and hyphens")
    else:
        analysis_id = f"vuldetect/{analysis_id_sanitize(project_slug)}"

    llm_config = {"provider": args.provider, "model": args.model}
    if args.llm_extra_kwargs:
        extra_kwargs = json.loads(args.llm_extra_kwargs)
        if not isinstance(extra_kwargs, dict):
            raise SystemExit("--llm-extra-kwargs must be a JSON object, e.g. '{\"temperature\": 0}'")
        llm_config.update(extra_kwargs)

    llm_tag = args.llm_tag or run_id_sanitize(f"{args.provider}_{args.model}")
    batch_ts = args.batch_ts or datetime.now().strftime("%m%d_%H%M")
    run_id = args.run_id or f"{llm_tag}_{batch_ts}_{args.cwe_id}"

    if not re.fullmatch(r"[A-Za-z0-9._-]+", run_id):
        raise SystemExit(f"--run-id may only contain letters, digits, '.', '_' and '-': {run_id}")

    project_data_path, log_dir, out_dir, work_dir = gen_run_paths(output_root, project_slug, run_id)
    base = {
        "project_slug": project_slug,
        "run_id": run_id,
        "analysis_id": analysis_id,
        "cwe_id": args.cwe_id,
        "project_source": project_source,
        "codeql_db": codeql_db,
        "output_root": output_root,
        "llm_config": llm_config,
    }

    log.info(f"project      : {project_name} ({project_slug})")
    log.info(f"source       : {project_source}")
    log.info(f"codeql db    : {codeql_db}")
    log.info(f"run_id       : {run_id}")
    log.info(f"llm          : {llm_config}")

    sarif_path = os.path.join(out_dir, "taint_analysis", "taint_analysis_result.sarif")
    skipped_path = os.path.join(out_dir, "codeql_agent_skipped.json")
    if not args.force and (os.path.exists(sarif_path) or os.path.exists(skipped_path)):
        reason = "sarif_exists" if os.path.exists(sarif_path) else "skipped_record_exists"
        log.info(f"[SKIP] {project_slug} already has a completion marker ({reason})")
        _write_summary(output_root, project_slug, run_id, {**base, "status": "skipped_existing",
                                             "skip_reason": reason})
        return 0

    if args.dry_run:
        log.info("[DRY RUN] inputs validated; no pipeline was started")
        _write_summary(output_root, project_slug, run_id, {**base, "status": "dry_run"})
        return 0

    os.makedirs(output_root, exist_ok=True)
    try:
        pipeline = VulDetectPipeline(
            project_name=project_name, project_slug=project_slug,
            codeql_db_path=codeql_db, project_source_path=project_source,
            project_data_path=project_data_path, codeql_cli_path=args.codeql_bin,
            codeql_script_dir=script_dir,
        )
        result = pipeline.run(
            cwe_id=args.cwe_id, run_id=run_id,
            run_output_dir=out_dir, run_work_dir=work_dir, run_log_dir=log_dir,
            llm_config=llm_config, analysis_id=analysis_id,
        )
        status = result.get("status")
        entry = {**base, "status": status, "result": result}

        markers = degradation_markers(out_dir)
        if markers:
            entry["degraded"] = markers
            log.warning(f"[DEGRADED] {project_slug} has degradation records: {markers}")

        verdict = verify_product(out_dir)
        entry["product_check"] = verdict
        if status == "completed" and not verdict["ok"]:
            log.error(f"[INCOMPLETE] {project_slug} reported completed but product verification "
                      f"failed ({verdict['reason']})")
            entry["status"] = "incomplete"
            entry["pipeline_status"] = status

        _write_summary(output_root, project_slug, run_id, entry)
        log.info(f"Final status: {entry['status']}")
        return 0 if entry["status"] in ("completed", "skipped_existing") else 1
    except Exception:
        err = traceback.format_exc()
        _dump_exception(log_dir, "pipeline_exception", err, base)
        log.error(f"[EXCEPTION] {project_slug} failed; details saved to "
                  f"{os.path.join(log_dir, 'pipeline_exception.log')}")
        _write_summary(output_root, project_slug, run_id, {**base, "status": "exception", "error": err})
        return 1


def _write_summary(output_root: str, project_slug: str, run_id: str, entry: dict):
    os.makedirs(output_root, exist_ok=True)
    path = os.path.join(output_root, f"run_summary_{project_slug}_{run_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entry, f, ensure_ascii=False, indent=2, default=str)
    log.info(f"Summary written to {path}")


if __name__ == "__main__":
    sys.exit(main())
