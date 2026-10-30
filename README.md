# VulDetectAgent

VulDetectAgent is a multi-agent pipeline for static vulnerability detection in Java
projects. Given a target project's source tree and a prebuilt CodeQL database, it uses
LLM agents to derive taint specifications (sources, sinks and propagation steps), turns
those specifications into CodeQL queries, and runs a final taint analysis whose findings
are written as SARIF.

## Architecture

The pipeline is orchestrated by `vul_detect_agent.py` (`VulDetectPipeline`) and runs in
four phases:

1. **CodeQL preprocessing** (`codeql_ops/codeql_query_runner.py`) -- runs the bundled
   stage-1 queries in `codeql_scripts/` to build a symbol index for the target database.
2. **Analyzer Agent** (`analysis_agent/`) -- explores the source to produce taint
   specifications:
   - a direction builder proposes project-specific exploration directions
     (`analysis_agent/direction/`), complemented by deterministic direction templates;
   - each direction is explored by an executor subgraph driven by a
     Planner -> Executor -> Reviewer -> Result Extract -> Plan Update loop
     (`analysis_agent/graph.py`, `analysis_agent/plan_nodes.py`,
     `analysis_agent/process_nodes.py`, `analysis_agent/executor_agent/`);
   - duplicate specifications across directions are fused and deduplicated
     (`analysis_agent/fusion.py`).
3. **CodeQL Agent** (`codeql_agent/`) -- per specification, generates and repairs a QL
   predicate, validates it against the database, and assembles the final query library.
4. **Taint analysis** (`codeql_ops/taint_analysis_runner.py`) -- evaluates the assembled
   query and writes the SARIF result.

The stage-1 queries and the taint-query template live in `codeql_scripts/` and
`codeql_agent/prompts/`.

## Requirements

- Python 3.12 or newer
- [CodeQL CLI](https://codeql.github.com/docs/codeql-cli/) with the Java query pack
  available
- A prebuilt CodeQL database (and the matching source tree) for every target project
- API credentials for at least one supported LLM provider (`deepseek`, `qwen`,
  `openai`, `zai`, `anthropic`)

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` lists the third-party packages imported by the project; it is a
starting point, not a locked environment.

## Configuration

Copy `.env.example` to `.env` and fill in the values you need (never commit `.env`):

```bash
cp .env.example .env
```

The code loads `.env` from its own directory or any parent directory, so a `.env` placed
at the repository root is found when running from a subdirectory. Existing environment
variables take precedence.

| Variable | Purpose |
|---|---|
| `DEEPSEEK_API_KEY`, `DASHSCOPE_API_KEY`, `OPENAI_API_KEY`, `ZAI_API_KEY`, `ANTHROPIC_API_KEY` | Provider credentials |
| `OPENAI_PROXY_URL`, `ANTHROPIC_PROXY_URL` | Optional OpenAI-compatible / Anthropic-compatible endpoint overrides |
| `CODEQL_BIN` | Path to the CodeQL executable (default `codeql`) |
| `SYMBOL_INDEX_CACHE_SIZE` | Number of parsed symbol indexes kept in memory (default 8) |
| `MODEL_TOKEN_LIMIT` | Model input limit used by the budget guard |
| `MODEL_TOKEN_BUDGET_RATIO`, `MODEL_SINGLE_MSG_RATIO` | Budget-guard thresholds |
| `FUSION_GROUP_MAPPING` | Set to `0`/`false` to disable the second fusion mapping round |

Model selection is per run via `--provider` and `--model`; arbitrary extra client
kwargs can be passed with `--llm-extra-kwargs '{"temperature": 0}'`.

## Experimental data

The `data/` directory contains the dataset used in our experiments. It is provided for
reference and reproducibility; `run_one.py` does not read these files.

| File | Contents |
|---|---|
| `data/selected_cve_project_slug.csv` | One row per evaluated project/CVE pair: numeric id, CVE id, project slug, CWE id/name, repository owner and name, tag, advisory, buggy commit, fix commits and a short patch note. |
| `data/fix_info.csv` | Per-fix locations for each CVE: project slug, CVE id, commit, file, class and method names, and their line ranges. |

## Running a single case

`run_one.py` runs exactly one target. Both inputs are exact paths to existing
directories -- no dataset layout or path concatenation is assumed:

- `--project-source`: the checked-out source tree of the target;
- `--codeql-db`: a CodeQL database built from that source tree.

First validate the inputs without spending tokens:

```bash
python run_one.py \
  --project-source /absolute/path/to/project-sources/example-project \
  --codeql-db /absolute/path/to/codeql-dbs/example-project \
  --project-name owner/repo \
  --cwe-id CWE-078 \
  --output-root /absolute/path/to/output \
  --provider deepseek --model deepseek-flash \
  --dry-run
```

Remove `--dry-run` to execute:

```bash
python run_one.py \
  --project-source /absolute/path/to/project-sources/example-project \
  --codeql-db /absolute/path/to/codeql-dbs/example-project \
  --project-name owner/repo \
  --cwe-id CWE-078 \
  --output-root /absolute/path/to/output \
  --provider deepseek --model deepseek-flash
```

Key flags:

- `--project-name` / `--project-slug` -- project identifier shown to the agents and
  the name used in the output path (default: the source directory name). Prefer an
  `<owner>/<repo>` identifier for `--project-name`.
- `--analysis-id` -- CodeQL pack name in `<scope>/<name>` form (default:
  `vuldetect/<sanitized project slug>`).
- `--run-id` -- explicit run id; by default it is `<llm_tag>_<batch_ts>_<cwe_id>`.
- `--batch-ts` -- timestamp used in the default run id (default: now).
- `--llm-tag` -- prefix for the default run id (default: sanitized `provider_model`).
- `--llm-extra-kwargs '{"...": ...}'` -- extra keyword arguments for the LLM client.
- `--codeql-bin` / `--codeql-script-dir` -- CodeQL executable and stage-1 query
  directory (default: `codeql` on `PATH` and the bundled `codeql_scripts/`).
- `--force` -- run again even if a completion marker already exists.

Runs are resumable: if the target already produced
`outputs/taint_analysis/taint_analysis_result.sarif` or
`outputs/codeql_agent_skipped.json` under the same output directory, the run is skipped.
Use `--force` to override this.

## Output layout

```
<output-root>/
  run_summary_<project_slug>_<run_id>.json  # status, resolved paths and degradation markers
  <project_slug>/
    <run_id>/
      logs/                              # agent prompts, responses and degradation records
      outputs/                           # final products
        taint_analysis/taint_analysis_result.sarif
        codeql_agent_spec_scripts.json
        codeql_agent_skipped.json        # present when no source/sink pair exists
        codeql_agent_circuit_break.json  # present when stage 3 stopped early
        codeql_agent_assembly_guard.json # present when a role could not be assembled
      work_dir/                          # intermediate artifacts and the assembled query
```

`run_summary_<project_slug>_<run_id>.json` records the final status (`completed`, `skipped_existing`,
`no_specs`, `skipped_incomplete_specs`, `incomplete`, `exception`, ...), the exact input
paths that were used, and any degradation markers such as `llm_degradation`,
`analysis_fallback`, `budget_trim`, `pairing_violation`, `circuit_break` and
`assembly_guard`.

The process exit code is `0` for `completed` and `skipped_existing`, and `1` for other
terminal states or an exception.

## Tests

Offline regression tests live in `test/offline/`. They do not contact the network.
Self-contained tests:

```bash
python test/offline/T7_llm_fallback_injection.py
python test/offline/T8_provider_aware_backoff.py
```

`T8` re-runs `T7` as a subtest. Both accept `--post-root` (default: the repository root).

The remaining tests replay recorded artifacts and require external inputs, supplied
through environment variables or flags:

| Test | Requires |
|---|---|
| `T1_fusion_round1_replay.py` | a recorded fusion archive (`T1_ARCHIVE`) |
| `T2T3_fusion_behavior.py` | a baseline prompt module for comparison (`T2T3_BASELINE_ROOT`) |
| `T5_predicate_name_replay.py` | a recorded run artifact and a legacy assembler (`T5_RUN_DIR`, `T5_LEGACY_ASSEMBLER`) |
| `T6_symbol_index_cache_race.py` | an unpatched pre-fix tree (`T6_PRE_ROOT`) |

These are historical regression checks; they are kept for reference but are not
runnable from a fresh checkout without the corresponding archives.

## License

License: TBD
