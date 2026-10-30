"""
agent.py
CodeQL Agent controller: walks specifications single-threadedly, generating,
validating and retrying each one, then assembles the final script.
"""
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple
import os
import csv
import io
from enum import Enum

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, BaseMessage, message_to_dict

# Global Module
from global_data_model.analysis_result import TaintSpecificationList, SpecificationUnion
from logger import StdoutLogger, log_local, log_json, log_message

# CodeQL Agent Local Module
from codeql_agent.role_registry import ROLE_REGISTRY, RoleConfig
from codeql_agent.codeql_agent_data import SpecResult, CodeQLAgentOutput
from codeql_agent.prompt_builder import PromptBuilder
from codeql_agent.script_builder import ScriptBuilder
from codeql_agent.executor import CodeQLExecutor
from codeql_agent.validator import ResultValidator
from codeql_agent.assembler import ConfigAssembler
from codeql_ops.codeql_query_runner import count_index_rows
from codeql_agent.interaction_history import InteractionHistory
from codeql_agent import retry_policy

# Stdout Log Phase
STDOUT_LOG_PHASE = "codeql_agent"

class ValidationStatus(Enum):
    PASSED = "passed"                   # compiles, non-empty, hits GT
    COMPILE_ERROR = "compile_error"     # compilation failed
    RUNTIME_ERROR = "runtime_error"     # execution failed
    EMPTY_RESULT = "empty_result"       # compiled but empty result
    GT_NOT_HIT = "gt_not_hit"           # non-empty but no GT hit
    SCOPE_ABNORMAL = "scope_abnormal"   # abnormal match scope: unconstrained node or oversized endpoint match

@dataclass
class ExecutionResult:
    """Combined compile/execute/validate result."""
    status: ValidationStatus
    error_detail: str = ""          # detailed compile/runtime error
    query_output: str = ""          # query result CSV (used for GT analysis)
    diagnostics: dict = field(default_factory=dict)   # scope diagnostics (see ResultValidator.validate)


# ============================================================
#  CodeQL Agent
# ============================================================

class CodeQLAgent:
    def __init__(
        self,
        llm: BaseChatModel,
        codeql_db_path: str,
        project_source_path: str,
        logging_path: str,
        work_dir: str = "/tmp/codeql_agent",
        analysis_id: str = "vuldetect/agent",   # qlpack.yml id used by the analysis
        codeql_cli_path: str = "codeql",
        project_data_path: Optional[str] = None,   # project data dir containing symbol_index/ (denominator for match gating)
    ):
        self.llm = llm
        self.db_path = codeql_db_path
        self.cli_path = codeql_cli_path
        self.project_source_path = Path(project_source_path)
        self.logging_path = Path(logging_path)
        self.work_dir = Path(work_dir)
        self.analysis_id = analysis_id

        # Ensure directories exist
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.logging_path.mkdir(parents=True, exist_ok=True)

        # Initialize submodules
        self.prompt_builder = PromptBuilder()
        self.script_builder = ScriptBuilder()
        self.executor = CodeQLExecutor(
            cli_path=self.cli_path,
            db_path=self.db_path,
            work_dir=self.work_dir,
            analysis_id = self.analysis_id
        )
        # Denominator for match-count gating: project method count (computed once;
        # 0 when the index is missing, which degrades to the absolute threshold)
        self.project_method_count = (
            count_index_rows(project_data_path, "fetch_func_locs")
            if project_data_path else 0
        )
        # Total API calls: used only as scale reference in feedback (not a gating denominator)
        self.project_api_call_count = (
            count_index_rows(project_data_path, "fetch_call")
            if project_data_path else 0
        )
        self.validator = ResultValidator(project_method_count=self.project_method_count)
        self.assembler = ConfigAssembler()

    # ----------------------------------------------------------
    #  Main entry point
    # ----------------------------------------------------------
    def run(self, spec_list: List[SpecificationUnion]) -> CodeQLAgentOutput:
        """
        Main flow: iterate over all specifications, generate and validate each,
        then assemble. Returns the complete CodeQL taint-analysis script.

        Consecutive failures of environmental origin trip a circuit breaker that
        ends this stage early (see retry_policy).
        """
        StdoutLogger.info(f"Processing {len(spec_list)} specifications", STDOUT_LOG_PHASE)

        breaker = retry_policy.EnvironmentCircuitBreaker(log_dir=str(self.logging_path))
        requested_roles = {s.role for s in spec_list}
        validated: list[SpecResult] = []
        failed: list[SpecResult] = []
        not_attempted: list[str] = []

        for idx, spec in enumerate(spec_list):
            # Assign a spec_id if upstream did not provide one
            if not spec.spec_id:
                spec.spec_id = f"{spec.role}_{uuid.uuid4().hex[:8]}"

            # Circuit breaker tripped: skip the remaining specs
            if breaker.tripped:
                not_attempted.append(spec.spec_id)
                continue

            StdoutLogger.info(f"[{idx+1}/{len(spec_list)}] "
                        f"spec {spec.spec_id} (role={spec.role})", STDOUT_LOG_PHASE)

            result = self._process_single_spec(spec)

            if result.success:
                validated.append(result)
                if result.gt_verified:
                    StdoutLogger.info(f"  passed (GT verified, {result.attempts} attempts)", STDOUT_LOG_PHASE)
                elif result.oversized:
                    # Distinguish from a plain degradation: the match surface is far
                    # beyond the project scale and may inflate the result set
                    StdoutLogger.warning(
                        f"  passed with scope degradation (oversized match set, "
                        f"{result.attempts} attempts): predicate matches too broadly; "
                        f"SARIF results may be inflated",
                        STDOUT_LOG_PHASE,
                    )
                else:
                    StdoutLogger.warning(f"  passed with degradation (GT not hit, {result.attempts} attempts)", STDOUT_LOG_PHASE)
            else:
                failed.append(result)
                StdoutLogger.warning(f"  failed: {result.error_summary}", STDOUT_LOG_PHASE)

            if breaker.observe(result.failure_kind, spec.spec_id, result.error_summary):
                skipped = [s.spec_id for s in spec_list[idx + 1:] if s.spec_id]
                breaker.persist(skipped_spec_ids=skipped)

        circuit_break = breaker.to_record(not_attempted) if breaker.tripped else None

        # Deterministic assembly
        final_script = self.assembler.assemble(validated)

        # Post-assembly self-check: are key roles (source/sink) entirely missing?
        assembly_guard = retry_policy.check_assembly(
            validated, requested_roles=requested_roles, log_dir=str(self.logging_path),
        )

        StdoutLogger.info(
            f"Done: {len(validated)} succeeded, {len(failed)} failed"
            + (f", {len(not_attempted)} skipped by circuit breaker" if not_attempted else ""),
            STDOUT_LOG_PHASE,
        )
        return CodeQLAgentOutput(
            final_script=final_script,
            validated=validated,
            failed=failed,
            not_attempted=not_attempted,
            circuit_break=circuit_break,
            assembly_guard=assembly_guard,
        )

    # ----------------------------------------------------------
    #  Per-specification processing loop
    # ----------------------------------------------------------
    def _process_single_spec(self, spec: SpecificationUnion) -> SpecResult:
        """Generate-and-validate loop for one specification.

        Every retry-exhausted path funnels into retry_policy.finalize_spec(): if a
        candidate that compiled and returned non-empty results exists, it is
        degraded-but-accepted rather than discarded, regardless of exit path.
        """
        config = ROLE_REGISTRY[spec.role]
        predicate_name = config.predicate_name_template.format(spec_id=spec.spec_id)
        # Offset needed to map CodeQL line numbers from the wrapped script back to the model's code
        line_offset = self.script_builder.predicate_line_offset(config)

        # Fixed prefix
        system_prompt = self.prompt_builder.build_system_prompt()
        initial_user_msg = self.prompt_builder.build_initial_user_message(spec, predicate_name)

        # Log the global prompt
        log_target_dir = os.path.join(self.logging_path, spec.spec_id)
        log_json(log_target_dir, "global_prompt",
                {"system_prompt": system_prompt, "initial_user_msg": initial_user_msg})

        # State tracking
        history = InteractionHistory()
        compile_fail_count = 0
        empty_fail_count = 0
        gt_fail_count = 0
        runtime_code_fail_count = 0      # code-level runtime failures only (environmental failures are not retried)
        llm_error_count = 0
        scope_fail_count = 0             # scope rewrites (unconstrained node / oversized match)

        # GT tolerance: remember the last candidate that compiled and returned non-empty
        last_valid_code: Optional[str] = None
        last_valid_attempt: int = 0
        # Two scope flags maintained by the SCOPE_ABNORMAL branch and passed to
        # every finalize_spec exit:
        #   oversized  -- candidate is merely broad; may be accepted with a marker
        #   defective  -- candidate has unconstrained node variables (proof of a
        #                 defect) and must never be revived
        last_valid_oversized: bool = False
        last_valid_defective: bool = False

        for attempt in range(1, config.max_total_attempts + 1):

            # ---- Step 1: build messages and call the LLM (bounded backoff; never raises) ----
            messages = self._build_messages(system_prompt, initial_user_msg, history, attempt, log_target_dir)
            response: Optional[AIMessage] = retry_policy.invoke_with_backoff(
                self.llm, messages, spec_id=spec.spec_id, log_dir=log_target_dir,
            )
            if response is None:
                llm_error_count += 1
                log_json(log_target_dir, f"round_{attempt}_result", {
                    "pass_validation": False,
                    "failure_type": retry_policy.FailureKind.LLM_ERROR,
                    "note": "LLM call failed repeatedly; no candidate this round",
                })
                continue

            # ---- Step 2: extract code ----
            predicate_code = self._extract_code_block(response.content)

            # Normalize at extraction time. If the LLM ignores the requested name,
            # renaming only inside build() would leave the execution script, the
            # SpecResult and the persisted codeql_agent_spec_scripts.json with
            # different names, so the assembler's definition and reference would
            # disagree and Phase 4 would fail with "could not resolve predicate".
            # Normalizing here keeps all three consistent (an identity transform
            # when already compliant; build() calls it again idempotently). This
            # also covers all three SpecResult construction points: success,
            # degraded acceptance in finalize_spec, and the empty-code failure.
            predicate_code = self.script_builder.normalize_predicate_name(
                predicate_code, predicate_name, config
            )

            if not predicate_code:
                # Share the compile-error budget to bound the no-code loop
                compile_fail_count += 1
                if compile_fail_count > config.max_compile_retries:
                    return retry_policy.finalize_spec(
                        spec, attempts=attempt,
                        reason="No valid code block produced; retries exhausted",
                        failure_kind=retry_policy.FailureKind.NO_CODE,
                        last_valid_code=last_valid_code, last_valid_attempt=last_valid_attempt,
                        last_valid_oversized=last_valid_oversized,
                        last_valid_defective=last_valid_defective,
                        log_dir=log_target_dir,
                        detail=f"No CodeQL code block in {compile_fail_count} consecutive replies",
                    )
                self._record_failure(
                    history, response, log_target_dir, attempt,
                    feedback_text=self.prompt_builder.build_no_code_message(),
                    failure_type="no_code",
                )
                continue

            # ---- Step 3: wrap -> compile -> run -> validate ----
            exec_result = self._execute_and_validate(
                spec, config, predicate_name, predicate_code, attempt
            )

            # ---- Step 4: handle by validation status ----
            if exec_result.status == ValidationStatus.PASSED:
                self._log_round(log_target_dir, attempt, response, passed=True)
                return SpecResult(
                    spec_id=spec.spec_id, role=spec.role, success=True,
                    predicate_code=predicate_code, spec=spec,
                    attempts=attempt, gt_verified=True,
                    failure_kind=retry_policy.FailureKind.PASSED,
                )

            elif exec_result.status == ValidationStatus.COMPILE_ERROR:
                compile_fail_count += 1
                diagnosis = retry_policy.diagnose_compile_error(exec_result.error_detail, line_offset)
                log_json(log_target_dir, f"round_{attempt}_compile_diagnosis", diagnosis.to_dict())
                if compile_fail_count > config.max_compile_retries:
                    return retry_policy.finalize_spec(
                        spec, attempts=attempt,
                        reason="Compile retries exhausted",
                        failure_kind=retry_policy.FailureKind.COMPILE_EXHAUSTED,
                        last_valid_code=last_valid_code, last_valid_attempt=last_valid_attempt,
                        last_valid_oversized=last_valid_oversized,
                        last_valid_defective=last_valid_defective,
                        log_dir=log_target_dir,
                        detail=f"Compilation failed {compile_fail_count} consecutive times; last diagnosis: {diagnosis.one_line_summary()}",
                    )
                self._record_failure(
                    history, response, log_target_dir, attempt,
                    feedback_text=self.prompt_builder.build_error_feedback_message(diagnosis),
                    failure_type="compile_error",
                    error_summary=diagnosis.one_line_summary(),
                )

            elif exec_result.status == ValidationStatus.RUNTIME_ERROR:
                category = retry_policy.classify_runtime_error(exec_result.error_detail)

                if category == retry_policy.ENVIRONMENTAL:
                    # Mark this spec failed: environmental faults are unrelated to the
                    # predicate and retrying cannot help. More importantly, never feed
                    # such stderr back as "please fix your code", which would push the
                    # model to change an otherwise-correct rule.
                    self._log_round(
                        log_target_dir, attempt, response, passed=False,
                        note="Environmental execution failure; not retried: "
                             + retry_policy.summarize_error(exec_result.error_detail),
                    )
                    return retry_policy.finalize_spec(
                        spec, attempts=attempt,
                        reason="Environmental execution failure (not retried)",
                        failure_kind=retry_policy.FailureKind.RUNTIME_ENV,
                        last_valid_code=last_valid_code, last_valid_attempt=last_valid_attempt,
                        last_valid_oversized=last_valid_oversized,
                        last_valid_defective=last_valid_defective,
                        log_dir=log_target_dir,
                        detail="Environmental execution failure, unrelated to the predicate: "
                               + retry_policy.summarize_error(exec_result.error_detail),
                    )

                runtime_code_fail_count += 1
                diagnosis = retry_policy.diagnose_runtime_error(exec_result.error_detail)
                log_json(log_target_dir, f"round_{attempt}_run_diagnosis", diagnosis.to_dict())
                if runtime_code_fail_count > config.max_runtime_retries:
                    return retry_policy.finalize_spec(
                        spec, attempts=attempt,
                        reason="Code-level execution failure; retries exhausted",
                        failure_kind=retry_policy.FailureKind.RUNTIME_CODE_EXHAUSTED,
                        last_valid_code=last_valid_code, last_valid_attempt=last_valid_attempt,
                        last_valid_oversized=last_valid_oversized,
                        last_valid_defective=last_valid_defective,
                        log_dir=log_target_dir,
                        detail=f"Execution failed {runtime_code_fail_count} consecutive times; "
                               + f"last diagnosis: {retry_policy.summarize_error(exec_result.error_detail)}",
                    )
                self._record_failure(
                    history, response, log_target_dir, attempt,
                    feedback_text=self.prompt_builder.build_error_feedback_message(diagnosis),
                    failure_type="runtime_error",
                    error_summary=diagnosis.one_line_summary(),
                )

            elif exec_result.status == ValidationStatus.EMPTY_RESULT:
                empty_fail_count += 1
                if empty_fail_count > config.max_empty_retries:
                    return retry_policy.finalize_spec(
                        spec, attempts=attempt,
                        reason="Empty result; retries exhausted",
                        failure_kind=retry_policy.FailureKind.EMPTY_EXHAUSTED,
                        last_valid_code=last_valid_code, last_valid_attempt=last_valid_attempt,
                        last_valid_oversized=last_valid_oversized,
                        last_valid_defective=last_valid_defective,
                        log_dir=log_target_dir,
                        detail=f"Query returned no results {empty_fail_count} consecutive times (compiles but matches no nodes)",
                    )
                self._record_failure(
                    history, response, log_target_dir, attempt,
                    feedback_text=self.prompt_builder.build_empty_result_message(),
                    failure_type="empty_result",
                )

            elif exec_result.status == ValidationStatus.SCOPE_ABNORMAL:
                # Abnormal match scope (validator.validate steps 2/3): the result set
                # is out of control, so the rule itself must be rewritten rather than
                # narrowed piecemeal as in the GT-not-hit case.
                scope_fail_count += 1
                diag = exec_result.diagnostics or {}
                reason_kind = diag.get("reason", "")

                if reason_kind == "unbound_node":
                    # Proof of a defect: the predicate accepts any node. Even if the
                    # budget runs out, it must not be revived as a degraded candidate
                    # (finalize_spec refuses to accept it).
                    last_valid_defective = True
                else:
                    # Oversized: merely broad, not proof of a defect; rewrite, then accept with a marker if budget runs out
                    last_valid_code = predicate_code
                    last_valid_attempt = attempt
                    last_valid_oversized = True

                if scope_fail_count > config.max_scope_retries:
                    self._log_round(log_target_dir, attempt, response, passed=False,
                                    note=f"Scope rewrites exhausted ({reason_kind}); not accepted as degraded")
                    return retry_policy.finalize_spec(
                        spec, attempts=attempt,
                        reason="Abnormal match scope; rewrites exhausted",
                        failure_kind=retry_policy.FailureKind.SCOPE_EXHAUSTED,
                        last_valid_code=last_valid_code, last_valid_attempt=last_valid_attempt,
                        last_valid_oversized=last_valid_oversized,
                        last_valid_defective=last_valid_defective,
                        degraded_kind=retry_policy.FailureKind.SCOPE_DEGRADED,
                        log_dir=log_target_dir,
                        detail=f"Abnormal match scope {scope_fail_count} consecutive times ({reason_kind}); "
                               + f"last diagnosis: {self._scope_diag_summary(diag)}",
                    )

                self._record_failure(
                    history, response, log_target_dir, attempt,
                    feedback_text=self.prompt_builder.build_scope_abnormal_message(
                        spec=spec,
                        diagnostics=diag,
                        retry_index=scope_fail_count,
                        max_retries=config.max_scope_retries,
                        project_api_call_count=self.project_api_call_count,
                    ),
                    failure_type="scope_abnormal",
                    error_summary=self._scope_diag_summary(diag),
                )

            elif exec_result.status == ValidationStatus.GT_NOT_HIT:
                gt_fail_count += 1

                # Record a degraded candidate: compiles and returns non-empty
                last_valid_code = predicate_code
                last_valid_attempt = attempt

                if gt_fail_count > config.max_gt_retries:
                    # GT tolerance: degrade to "not verified"
                    self._log_round(log_target_dir, attempt, response,
                                    passed=False, note="GT retries exhausted; accepted without GT verification")
                    return retry_policy.finalize_spec(
                        spec, attempts=attempt,
                        reason="GT not hit; retries exhausted",
                        failure_kind=retry_policy.FailureKind.DEGRADED_GT,
                        last_valid_code=last_valid_code, last_valid_attempt=last_valid_attempt,
                        last_valid_oversized=last_valid_oversized,
                        last_valid_defective=last_valid_defective,
                        log_dir=log_target_dir,
                        detail=f"GT not hit in {gt_fail_count} consecutive rounds; accepting the current candidate as degraded",
                    )

                # Build detailed GT-miss feedback
                feedback = self._build_gt_miss_feedback(spec, exec_result.query_output)
                self._record_failure(
                    history, response, log_target_dir, attempt,
                    feedback_text=feedback,
                    failure_type="gt_not_hit",
                )

        # Loop ended: total attempts exhausted (finalize_spec accepts a degraded candidate if one exists)
        if llm_error_count >= config.max_total_attempts:
            reason = "LLM calls failed repeatedly; no candidate code produced"
            failure_kind = retry_policy.FailureKind.LLM_ERROR
        else:
            reason = "Total retry budget exhausted"
            failure_kind = retry_policy.FailureKind.TOTAL_EXHAUSTED

        return retry_policy.finalize_spec(
            spec, attempts=config.max_total_attempts,
            reason=reason, failure_kind=failure_kind,
            last_valid_code=last_valid_code, last_valid_attempt=last_valid_attempt,
            last_valid_oversized=last_valid_oversized,
            last_valid_defective=last_valid_defective,
            log_dir=log_target_dir,
            detail=f"Reached the per-spec attempt cap of {config.max_total_attempts}",
        )

    def _build_messages(
        self,
        system_prompt: str,
        initial_user_msg: str,
        history: InteractionHistory,
        attempt: int,                 # generation round
        log_target_dir: str                  # log directory
    ) -> list[BaseMessage]:
        """Build the message list for this LLM call."""
        messages: list[BaseMessage] = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=initial_user_msg),
        ]

        # Compressed summary of older rounds (available from round 3 onward)
        if history.total_rounds >= 2:
            summary_text = history.build_compressed_summary()
            if summary_text:
                messages.append(HumanMessage(content=summary_text))
                log_json(log_target_dir, f"round_{attempt}_history", {"summary": summary_text})

        # Latest round in full: raw AIMessage plus detailed feedback
        if history.total_rounds >= 1:
            last = history.records[-1]
            messages.append(last.raw_ai_message)
            messages.append(HumanMessage(content=last.feedback_text))

        return messages

    def _execute_and_validate(
        self,
        spec: SpecificationUnion,
        config: RoleConfig,
        predicate_name: str,   # predicate name
        predicate_code: str,   # actual predicate code
        round_num: int,        # round number
    ) -> ExecutionResult:
        """
        Wrap the LLM predicate into a full script, then compile, run and validate.
        All intermediate files are persisted under work_dir/{spec_id}/round_{n}/.
        """
        # Wrap
        ql_script = self.script_builder.build(spec, config, predicate_name, predicate_code)

        # Compile
        compile_result = self.executor.compile(ql_script, spec.spec_id, round_num)
        if not compile_result.success:
            return ExecutionResult(
                status=ValidationStatus.COMPILE_ERROR,
                error_detail=compile_result.stderr,
            )

        # Run
        query_result = self.executor.run_query(ql_script, spec.spec_id, round_num)
        if not query_result.success:
            return ExecutionResult(
                status=ValidationStatus.RUNTIME_ERROR,
                error_detail=query_result.stderr,
            )

        # Validate (predicate_code is required by the scope/binding checks)
        validation = self.validator.validate(
            query_output=query_result.stdout, spec=spec, predicate_code=predicate_code,
        )

        if validation.passed:
            return ExecutionResult(
                status=ValidationStatus.PASSED,
                query_output=query_result.stdout,
                diagnostics=validation.diagnostics,
            )

        # Map each failure type explicitly; an else fallback would collapse
        # scope_abnormal into GT_NOT_HIT and deny it its own rewrite budget
        status_map = {
            "empty_result": ValidationStatus.EMPTY_RESULT,
            "scope_abnormal": ValidationStatus.SCOPE_ABNORMAL,
            "gt_not_hit": ValidationStatus.GT_NOT_HIT,
        }
        return ExecutionResult(
            status=status_map.get(validation.failure_type, ValidationStatus.GT_NOT_HIT),
            query_output=query_result.stdout,
            diagnostics=validation.diagnostics,
        )

    def _record_failure(
        self,
        history: InteractionHistory,
        response: AIMessage,
        log_target_dir: str,
        attempt: int,
        feedback_text: str,
        failure_type: str,
        error_summary: str = "",
    ):
        """Record one failed round in history and write the log."""
        logging_info = history.add_round(
            ai_message=response,
            feedback_text=feedback_text,
            failure_type=failure_type,
            error_summary=error_summary,
        )
        log_json(log_target_dir, f"round_{attempt}_result", logging_info)

    @staticmethod
    def _scope_diag_summary(diag: dict) -> str:
        """Flatten scope diagnostics to one line for logs and SpecResult.error_summary."""
        kind = diag.get("reason", "")
        if kind == "unbound_node":
            vars_ = sorted({u.get("var", "") for u in diag.get("unbound", [])})
            return (f"Predicate has a disjunct with unconstrained node variables "
                    f"({vars_}), {diag.get('result_count', 0)} matches")
        ratio = diag.get("method_ratio")
        ratio_txt = f", {ratio * 100:.0f}% of project methods" if isinstance(ratio, float) else ""
        return f"Oversized match count: {diag.get('result_count', 0)} results{ratio_txt}"

    def _build_gt_miss_feedback(self, spec: SpecificationUnion, query_output: str) -> str:
        """Build detailed feedback for a GT miss."""
        matched_snippets = self._read_matched_code_snippets(query_output)
        return self.prompt_builder.build_gt_miss_message(
            expected_paths=self.validator._extract_gt_paths(spec),
            matched_locations=self.validator._parse_csv(query_output),
            matched_code_snippets=matched_snippets,
        )

    # ----------------------------------------------------------
    #  LLM calls
    # ----------------------------------------------------------
    @staticmethod
    def _extract_code_block(content) -> str:
        """Extract the CodeQL code block from an LLM reply."""
        import re
        # Defensive: multimodal/thinking models may return content as a list of parts
        if not isinstance(content, str):
            if isinstance(content, list):
                content = " ".join(
                    part if isinstance(part, str) else str(part.get("text", ""))
                    for part in content
                )
            else:
                content = str(content or "")

        # Prefer a ```codeql ... ``` or ``` ... ``` block
        pattern = r"```(?:codeql|ql)?\s*\n(.*?)```"
        match = re.search(pattern, content, re.DOTALL)
        if match:
            return match.group(1).strip()
        # Without a fenced block, return the content as-is (assume raw code)
        return content.strip()

    # Read source context for matched nodes
    def _read_matched_code_snippets(
        self,
        csv_output: str,
        max_snippets: int = 5,
        context_lines: int = 5,
    ) -> List[str]:
        """
        Extract source context for matched nodes from the query results.
        Used on a GT miss to show the model which code actually matched.

        Args:
            csv_output:    query result CSV text
            max_snippets:  maximum snippets to extract (controls token usage)
            context_lines: lines of context before and after the match
        Returns:
            Snippet list, each formatted as:
            "--- File: {relative_path}:{line} ---\n{code}"
        """
        # Parse the CSV and collect all locations
        locations = self._parse_locations_from_csv(csv_output)

        if not locations:
            return []

        snippets: List[str] = []

        for rel_path, line_num in locations[:max_snippets]:
            snippet = self._read_code_at_location(rel_path, line_num, context_lines)
            if snippet:
                snippets.append(snippet)

        return snippets

    def _parse_locations_from_csv(self, csv_output: str) -> List[Tuple[str, int]]:
        """
        Parse query CSV output into (relative_path, line_number) pairs.
        Supports both single-column location and two-column location1/location2.

        Location format: "relative/path/to/File.java:42:5"
        """
        locations: List[Tuple[str, int]] = []

        try:
            reader = csv.reader(io.StringIO(csv_output))
            header = next(reader, None)  # skip the header row

            for row in reader:
                for cell in row:
                    cell = cell.strip()
                    if not cell:
                        continue
                    # Parse "path:line:col"
                    parts = cell.rsplit(":", 2)
                    if len(parts) == 3:
                        rel_path = parts[0]
                        try:
                            line_num = int(parts[1])
                            locations.append((rel_path, line_num))
                        except ValueError:
                            continue

        except Exception as e:
            StdoutLogger.debug(f"Failed to parse CSV locations: {e}", STDOUT_LOG_PHASE)

        return locations

    def _read_code_at_location(
        self,
        rel_path: str,
        line_num: int,
        context_lines: int,
    ) -> Optional[str]:
        """
        Read source context at the given location.

        Args:
            rel_path:      file path relative to the project root
            line_num:      matched line number (1-based)
            context_lines: lines of context before and after
        Returns:
            Snippet annotated with the file, or None on read failure
        """
        # Absolute path
        abs_path = Path(self.project_source_path) / rel_path

        if not abs_path.exists():
            StdoutLogger.debug(f"File not found: {abs_path}", STDOUT_LOG_PHASE)
            return None

        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except Exception as e:
            StdoutLogger.debug(f"Failed to read {abs_path}: {e}", STDOUT_LOG_PHASE)
            return None

        # Context range (line_num is 1-based)
        start = max(0, line_num - 1 - context_lines)
        end = min(len(all_lines), line_num + context_lines)

        # Extract code with line-number markers
        code_lines: List[str] = []
        for i in range(start, end):
            marker = ">>>" if i == line_num - 1 else "   "  # mark the matched line
            code_lines.append(f"{marker} {i + 1:4d} | {all_lines[i].rstrip()}")

        code_block = "\n".join(code_lines)

        return f"--- File: {rel_path}:{line_num} ---\n{code_block}"

    def _log_round(self,
                   log_target_dir: str,   # log directory
                   attempt: int,          # generation round
                   response: AIMessage,   # raw LLM response
                   passed: bool,          # whether validation passed
                   note: str = "None"     # details
        ): 
        """
        Log a successful generation (or a degraded success without GT verification),
        as well as special cases.
        """
        log_file_name = f"round_{attempt}_result"
        log_json(log_target_dir, log_file_name, 
                  {
                     "raw_response": message_to_dict(response),
                     "pass_validation": passed,
                     "note": note
                  }
        )