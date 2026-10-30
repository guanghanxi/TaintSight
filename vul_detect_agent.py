"""
orchestrator.py
VulDetectAgent top-level orchestrator: Analyzer Agent -> CodeQL Agent -> (Evaluation Agent)
"""
import json
import os
import traceback
from datetime import datetime
from pathlib import Path

from langchain_core.language_models.chat_models import BaseChatModel
from pydantic import TypeAdapter, BaseModel
from typing import Dict, Any, List

from llm_model import get_llm_based_on_simple_config
from global_data_model.analysis_result import SpecificationUnion, TaintSpecificationList
from analysis_agent.graph import build_analyzer_agent
from analysis_agent.direction.direction_builder import build_directions
from analysis_agent.fusion import fusion_dedup_specs
from analysis_agent.utils.result_update import gen_spec_ids
from codeql_agent.agent import CodeQLAgent
from codeql_agent.codeql_agent_data import CodeQLAgentOutput

from codeql_ops.codeql_query_runner import run_codeql_preprocess
from codeql_ops.taint_analysis_runner import run_database_analysis
from logger import StdoutLogger

# Stdout Log Phase
STDOUT_LOG_PHASE = "Vul_Detect_Agent"

# Non-Java asset suffixes. If all supporting examples of a specification fall
# on these assets, its source/sink targets are outside Java (which the Java
# CodeQL pack cannot analyze), so the specification is dropped before the
# CodeQL Agent runs.
NON_JAVA_ASSET_EXTS = (
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue",
    ".py", ".rb", ".go", ".php", ".pl",
    ".sh", ".bash", ".zsh", ".ps1", ".bat",
    ".css", ".scss", ".less", ".html", ".htm", ".jsp", ".ftl", ".vm", ".mustache",
    ".xml", ".yaml", ".yml", ".json", ".toml", ".properties", ".sql",
)

class VulDetectPipeline:
    """End-to-end vulnerability detection pipeline."""

    def __init__(
        self,
        project_name: str, # <repo_owner>/<repo_name>
        project_slug: str,
        codeql_db_path: str,
        project_source_path: str,
        project_data_path: str,     # project-level shared data (symbol index, etc.)
        codeql_cli_path: str = "codeql",
        codeql_script_dir: str = None,  # stage-1 .ql directory; None = bundled codeql_scripts/
    ):
        self.project_name = project_name
        self.project_slug = project_slug
        self.codeql_db_path = codeql_db_path
        self.project_source_path = project_source_path
        self.codeql_cli_path = codeql_cli_path
        self.project_data_path = Path(project_data_path)
        # Optional override for validating an alternate query set. Changing the
        # directory invalidates the manifest hashes of modified scripts, so only
        # those are re-run; unchanged scripts reuse cached CSVs.
        self.codeql_script_dir = codeql_script_dir
  
    def run(
        self,
        cwe_id: str,
        run_id: str,                # this run's id
        run_output_dir: str,        # this run: final outputs
        run_work_dir: str,          # this run: intermediate artifacts
        run_log_dir: str,           # this run: logs
        analysis_id: str = "vuldetect/agent",
        llm_config: Dict[str, Any] = None,
        skip_analyzer: bool = False,
        upstream_result_path: str = None,
    ) -> dict:
        """
        Run the full pipeline.

        Args:
            skip_analyzer: if True, skip the Analyzer Agent and load specifications
                directly from upstream_result_path
            upstream_result_path: path to an existing Analyzer Agent output file
        """

        # Per-run directories
        self.cwe_id = cwe_id
        self.analysis_id = analysis_id
        self.output_dir = Path(run_output_dir)
        self.work_dir = Path(run_work_dir)
        self.log_dir = Path(run_log_dir)

        # Per-run LLM settings
        if llm_config is None:
            self.llm_config = {
                "provider": "deepseek", 
                "model": "deepseek-v4-flash"
            }
        else:
            self.llm_config = llm_config
        
        for d in (self.work_dir, self.log_dir, self.output_dir):
            d.mkdir(parents=True, exist_ok=True)

        StdoutLogger.info("="*30 + f"\n🚀Start VulDetectPipeline: {self.project_slug} <{run_id}>\n" + "="*30, STDOUT_LOG_PHASE)

        # ============ Phase 1&2: CodeQL Scripts Runner + Analyzer Agent ============
        if skip_analyzer and upstream_result_path:
            StdoutLogger.info(f"Skipping CodeQL Scripts Runner and Analyzer Agent; loading existing results: {upstream_result_path}", STDOUT_LOG_PHASE)
            spec_list = self._load_specifications(upstream_result_path)
        else:
            StdoutLogger.info("Phase 1: running CodeQL Query Runner", STDOUT_LOG_PHASE)
            run_codeql_preprocess(
                codeql_db_path = self.codeql_db_path,
                project_data_path = self.project_data_path,
                codeql_script_dir = self.codeql_script_dir,
                codeql_bin = self.codeql_cli_path,
                keep_bqrs = True
            )
            StdoutLogger.info("Phase 2: running Analyzer Agent")

            spec_list = self._run_analyzer()

        if not spec_list:
            StdoutLogger.warning(f"{run_id}: Analyzer Agent produced no specifications; pipeline stopped.", STDOUT_LOG_PHASE)
            return {"status": "no_specs", "spec_count": 0}

        StdoutLogger.info(f"Analyzer Agent produced {len(spec_list)} specifications", STDOUT_LOG_PHASE)

        # ============ Phase 2.5a: specification language guard ============
        spec_list = self._filter_out_of_language_specs(spec_list)
        if not spec_list:
            StdoutLogger.warning(
                f"{run_id}: no specifications left after the language guard; pipeline stopped.", STDOUT_LOG_PHASE
            )
            return {"status": "no_specs", "spec_count": 0}

        # ============ Phase 2.5: specification completeness (source + sink required) ============
        roles = {spec.role for spec in spec_list}
        missing_roles = [r for r in ("source", "sink") if r not in roles]
        if missing_roles:
            StdoutLogger.warning(
                f"{run_id}: spec_list is missing {missing_roles}; "
                f"skipping CodeQL Agent and final taint analysis to save compute.",
                STDOUT_LOG_PHASE
            )
            self._write_skipped_record(missing_roles, spec_count=len(spec_list))
            return {
                "status": "skipped_incomplete_specs",
                "run_id": run_id,
                "spec_count": len(spec_list),
                "missing_roles": missing_roles,
                "work_dir": str(self.work_dir),
                "log_dir": str(self.log_dir),
            }

        # ============ Phase 3: CodeQL Agent ============
        StdoutLogger.info("Phase 3: running CodeQL Agent", STDOUT_LOG_PHASE)
        agent_output: CodeQLAgentOutput = self._run_codeql_agent(spec_list)

        # ============ Phase 4: final taint analysis ============
        # Persist per-spec scripts for debugging and reuse
        spec_scripts_path = self.output_dir / "codeql_agent_spec_scripts.json"
        with open(spec_scripts_path, "w", encoding="utf-8") as f:
            json.dump(agent_output.spec_scripts, f, ensure_ascii=False, indent=2)

        # Persist the two CodeQL-stage degradation records (same convention as
        # codeql_agent_skipped.json, for batch-level inspection):
        # - codeql_agent_circuit_break.json : stage ended early after repeated failures
        # - codeql_agent_assembly_guard.json: all key roles failed; script has zero source/sink
        for filename, payload in (
            ("codeql_agent_circuit_break.json", agent_output.circuit_break),
            ("codeql_agent_assembly_guard.json", agent_output.assembly_guard),
        ):
            if payload:
                with open(self.output_dir / filename, "w", encoding="utf-8") as f:
                    json.dump(payload, f, ensure_ascii=False, indent=2)

        StdoutLogger.info("Phase 4: running final taint analysis", STDOUT_LOG_PHASE)
        analysis_result = self._run_final_taint_analysis(agent_output)

        return {
            "status": "completed",
            "run_id": run_id,
            "spec_count": len(spec_list),
            "qll_script": agent_output.final_script,
            "spec_scripts": agent_output.spec_scripts,
            "work_dir": str(self.work_dir),
            "log_dir": str(self.log_dir),
            "analysis_returncode": analysis_result.returncode,
        }

    def _run_analyzer(self,) -> List[SpecificationUnion]:
        """Run the multi-direction Analyzer Agent: build directions, explore them
        sequentially, fuse duplicates, and return the global specification list."""
        # ---- Direction construction ----
        builder_llm = get_llm_based_on_simple_config(self.llm_config)
        builder_log_dir = self.log_dir / "analysis_agent" / "direction_builder"
        os.makedirs(builder_log_dir, exist_ok=True)

        directions = build_directions(
            cwe_id=self.cwe_id,
            project_name=self.project_name,
            project_root=self.project_source_path,
            project_data_path=str(self.project_data_path),
            llm=builder_llm,
            log_dir=str(builder_log_dir),
        )

        # Persist the direction manifest for traceability
        manifest = [
            {
                "direction_id": d.direction_id,
                "name": d.name,
                "seed": d.seed,
                "max_executed_objectives": d.max_executed_objectives,
                "injection_text": d.injection_text,
            }
            for d in directions
        ]
        with open(builder_log_dir / "directions_manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)

        adapter = TypeAdapter(List[SpecificationUnion])
        global_specs: List[SpecificationUnion] = []

        for k, direction in enumerate(directions):
            # Directory names include the index and seed for per-direction inspection
            direction_log_dir = self.log_dir / "analysis_agent" / f"direction_{k + 1:02d}_{direction.seed}"
            os.makedirs(direction_log_dir, exist_ok=True)

            # Store full direction info here so problems can be diagnosed without the manifest
            with open(direction_log_dir / "direction_info.json", "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "direction_id": direction.direction_id,
                        "name": direction.name,
                        "seed": direction.seed,
                        "max_executed_objectives": direction.max_executed_objectives,
                        "injection_text": direction.injection_text,
                    },
                    f, ensure_ascii=False, indent=2,
                )

            StdoutLogger.info(
                f"🧭 Direction {k + 1}/{len(directions)} [{direction.direction_id}] {direction.name}",
                STDOUT_LOG_PHASE,
            )

            # Initial state and runner config
            analysis_agent_initial_state = {
                "project_root": self.project_source_path,
                "project_name": self.project_name,
                "cwe_id": self.cwe_id,
                "direction_id": direction.direction_id,
                "exploration_direction": direction.injection_text,
                "max_steps": 15,
                "step_count": 0,
                "status": "init",
                "taint_specifications": [],
                "executed_objectives_count": 0,
                "max_executed_objectives_count": direction.max_executed_objectives,
            }
            analysis_agent_config = {
                "configurable": {
                  "project_root": self.project_source_path,
                  "loggging_path": str(direction_log_dir),
                  "project_data_path": self.project_data_path,
                  "target_model_config": self.llm_config
                }
            }
            analyzer = build_analyzer_agent()
            # A single-direction failure (e.g. a node raising after retries) must
            # not abort the whole project: log it, skip that direction, continue.
            try:
                final_state = analyzer.invoke(analysis_agent_initial_state, config=analysis_agent_config)

                # Extract this direction's raw specifications and tag their origin
                raw_specs = final_state.get("taint_specifications", [])
                direction_specs = adapter.validate_python(raw_specs)
                origin_tag = f"{direction.direction_id}:{direction.name}"
                for spec in direction_specs:
                    spec.origin_direction = origin_tag
                # Regenerate globally unique spec_ids (avoids obj_XXXX prefix clashes)
                gen_spec_ids(direction_specs, prefix=f"d{k + 1:02d}")

                # Save the final state after spec_id renumbering so that
                # analyzer_final_state.json and raw_specifications.json agree
                state_log_path = direction_log_dir / "analyzer_final_state.json"
                with open(state_log_path, "w", encoding="utf-8") as f:
                    json.dump(self._serialize_state(final_state), f, ensure_ascii=False, indent=2)

                # Save this direction's specifications
                raw_specs_path = direction_log_dir / "raw_specifications.json"
                with open(raw_specs_path, "w", encoding="utf-8") as f:
                    json.dump([s.model_dump(mode="json") for s in direction_specs], f, ensure_ascii=False, indent=2)
            except Exception:
                err = traceback.format_exc()
                StdoutLogger.warning(
                    f"Direction [{direction.direction_id}] {direction.name} failed; "
                    f"skipping it and continuing with the remaining directions:\n{err}",
                    STDOUT_LOG_PHASE,
                )
                with open(direction_log_dir / "direction_exception.log", "w", encoding="utf-8") as f:
                    f.write(f"Timestamp: {datetime.now().isoformat()}\n"
                            f"Direction: {direction.direction_id} [{direction.seed}] {direction.name}\n\n{err}")
                continue

            global_specs.extend(direction_specs)

            StdoutLogger.info(
                f"Direction [{direction.direction_id}] produced {len(direction_specs)} specifications",
                STDOUT_LOG_PHASE,
            )

        # Cross-direction fusion (the aggregation module only de-duplicates)
        fusion_llm = get_llm_based_on_simple_config(self.llm_config)
        fusion_log_dir = str(self.log_dir / "analysis_agent" / "fusion")
        global_specs = fusion_dedup_specs(global_specs, fusion_llm, fusion_log_dir)

        # Save the fused global specifications (also serves as the analyzer_final_state.json marker)
        combined_state = {
            "taint_specifications": [s.model_dump(mode="json") for s in global_specs],
            "direction_count": len(directions),
            "directions": [
                {"direction_id": d.direction_id, "name": d.name, "seed": d.seed}
                for d in directions
            ],
        }
        marker_log_path = self.log_dir / "analysis_agent" / "analyzer_final_state.json"
        with open(marker_log_path, "w", encoding="utf-8") as f:
            json.dump(combined_state, f, ensure_ascii=False, indent=2)
        marker_output_path = self.output_dir / "analyzer_final_state.json"
        with open(marker_output_path, "w", encoding="utf-8") as f:
            json.dump(combined_state, f, ensure_ascii=False, indent=2)

        return global_specs

    def _filter_out_of_language_specs(
        self, spec_list: List[SpecificationUnion]
    ) -> List[SpecificationUnion]:
        """Drop specifications whose source/sink targets fall entirely on non-Java assets.

        The Java CodeQL pack cannot analyze JS, shell, Python and similar assets;
        such specifications compile to nothing and produce unrelated noise.
        The rule is conservative: drop only when *all* supporting example paths
        have a non-Java suffix. A single `.java` example keeps the specification,
        so mixed Java-plus-illustration specs are not lost.
        """
        kept, dropped = [], []
        for spec in spec_list:
            paths = [e.file_path for e in spec.ground_truth_examples if e.file_path]
            has_java = any(p.endswith(".java") for p in paths)
            all_known_non_java = bool(paths) and all(
                p.lower().endswith(NON_JAVA_ASSET_EXTS) for p in paths
            )
            if all_known_non_java and not has_java:
                dropped.append({
                    "spec_id": spec.spec_id,
                    "role": spec.role,
                    "origin_direction": spec.origin_direction,
                    "file_paths": paths,
                })
            else:
                kept.append(spec)

        if dropped:
            record = {
                "status": "filtered",
                "reason": "language guard: source/sink targets are non-Java assets",
                "dropped_count": len(dropped),
                "kept_count": len(kept),
                "dropped": dropped,
                "timestamp": datetime.now().isoformat(),
            }
            for target_dir in (self.output_dir, self.log_dir):
                with open(target_dir / "codeql_agent_spec_guard.json", "w", encoding="utf-8") as f:
                    json.dump(record, f, ensure_ascii=False, indent=2)
            StdoutLogger.warning(
                f"{self.project_slug}: language guard dropped {len(dropped)} non-Java "
                f"specifications ({', '.join(str(d['spec_id']) for d in dropped)})",
                STDOUT_LOG_PHASE,
            )
        return kept

    def _write_skipped_record(self, missing_roles: List[str], spec_count: int):
        record = {
            "status": "skipped",
            "reason": "spec_list is missing required roles (source/sink); skipping CodeQL Agent and final taint analysis",
            "missing_roles": missing_roles,
            "cwe_id": self.cwe_id,
            "spec_count": spec_count,
            "timestamp": datetime.now().isoformat(),
        }
        for target_dir in (self.output_dir, self.log_dir):
            with open(target_dir / "codeql_agent_skipped.json", "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, indent=2)

    def _run_codeql_agent(
        self,
        spec_list: List[SpecificationUnion],
    ) -> CodeQLAgentOutput:
        """Run the CodeQL Agent to generate the final .qll script."""
        agent = CodeQLAgent(
            llm=get_llm_based_on_simple_config(self.llm_config),
            codeql_db_path=self.codeql_db_path,
            project_source_path=self.project_source_path,
            logging_path=str(self.log_dir / "codeql_agent"),
            work_dir=self.work_dir, # shared by the CodeQL Agent and final taint analysis
            analysis_id=self.analysis_id,
            codeql_cli_path=self.codeql_cli_path,
            project_data_path=str(self.project_data_path),   # denominator source for match gating (symbol_index/)
        )
        return agent.run(spec_list)

    def _run_final_taint_analysis(self, agent_output: CodeQLAgentOutput):
        """Run the final taint analysis."""
        result = run_database_analysis(
            project_work_dir_path=self.work_dir,
            project_output_path=self.output_dir,
            qll_script_content=agent_output.final_script,
            codeql_db_path=self.codeql_db_path,
            analysis_id= self.analysis_id,
            codeql_cli_path=self.codeql_cli_path,
        )
        return result


    def _serialize_state(self, state: dict) -> dict:
        """
        Convert AnalyzerState to a plain JSON-compatible dict.

        Large/runtime fields such as messages and _tools are dropped; only core
        business state is kept.
        """
        def _clean(obj: Any) -> Any:
            # 1. Pydantic models (plan, blackboard, ...)
            if isinstance(obj, BaseModel):
                return obj.model_dump(mode="json")
            # 2. Common non-JSON types such as sets
            if isinstance(obj, (set, frozenset)):
                return list(obj)
            # 3. Recurse into containers
            if isinstance(obj, dict):
                return {k: _clean(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [_clean(v) for v in obj]
            # 4. Native types are returned as-is
            if isinstance(obj, (str, int, float, bool, type(None))):
                return obj
            # 5. Fallback so unknown objects cannot crash json.dump
            try:
                json.dumps(obj)
                return obj
            except (TypeError, ValueError):
                return f"<non_serializable:{type(obj).__name__}>"

        clean_state = {}
        # Explicitly dropped: bulky logs, runtime objects, internal state
        skip_keys = {"messages", "_tools", "tools"}

        for key, value in state.items():
            if key.startswith("_") or key in skip_keys:
                continue
            clean_state[key] = _clean(value)
            
        return clean_state

    def _load_specifications(self, path: str) -> List[SpecificationUnion]:
        """Load specifications from an upstream file (full state dict or plain list)."""
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        raw_specs = raw.get("taint_specifications", raw) if isinstance(raw, dict) else raw
        return TypeAdapter(List[SpecificationUnion]).validate_python(raw_specs)
    