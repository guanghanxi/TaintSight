import re
from typing import List, Optional, Tuple
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage, RemoveMessage

# global module 
from global_data_model.analysis_result import TaintSpecificationList, SpecificationUnion, ResultDeduplication

# analysis agent local module
from analysis_agent.data_model.review_node_data import ReviewVerdict, ActiveObjectiveContext, RefinementRecord
from analysis_agent.executor_agent.executor_data_model import CodeResult, ExecutionResult
from analysis_agent.data_model.plan_data_model import PlanUpdateResult, AnalysisPlan, InvestigationObjective

from analysis_agent.utils import code_verify

# Result validation helpers for each agent node

# Shared helper: extract a structured error message from a parse failure
def get_parse_error_message(parsing_error) -> HumanMessage:
    # Extract and format the error so the LLM knows exactly what was wrong
    error_detail = "Unknown parse error (the output may be invalid JSON or wrapped in Markdown fences such as ```json)"
    if parsing_error:
        # For a Pydantic ValidationError, surface the field error path
        if hasattr(parsing_error, "errors"):
            errs = []
            for err in parsing_error.errors():
                # loc is the field path, e.g. ('specifications', 0, 'node_pattern', 'method_pattern')
                loc = " -> ".join(str(l) for l in err.get("loc", []))
                msg = err.get("msg", "")
                errs.append(f"- field path [{loc}]: {msg}")
            error_detail = "\n".join(errs)
        else:
            # Other exceptions, e.g. json.JSONDecodeError
            error_detail = str(parsing_error)

    return HumanMessage(
        f"❌ Validation failed: could not parse the result JSON or validate its data structure.\n"
        f"[Error details]:\n{error_detail}\n\n"
        f"Check the JSON syntax, required fields, enum constraints and nesting levels, "
        f"output no Markdown markers, and regenerate valid JSON.\n"
    )


# Result validation for the Review Agent
def check_review_agent_result(parsed_output: ReviewVerdict, # output produced by the Review Agent
                              active_objective: ActiveObjectiveContext, # active objective before update
                              is_refinement: bool) -> Tuple[bool, Optional[HumanMessage], Optional[ActiveObjectiveContext]]:
    # Returned on success: the updated objective
    new_active_objective = active_objective.model_copy(deep=True)

    # b. Validate that the execution result was merged correctly
    new_result = None # merged result
    if not parsed_output.integrated_summary or not parsed_output.integrated_report: # triggered when either is empty
        if is_refinement and not active_objective.refinements[-1].execution_result.is_self_contained:
            # Refinement round whose new execution result is not self-contained
            required_fields = []
            if not parsed_output.integrated_summary: required_fields.append("`integrated_summary`")
            if not parsed_output.integrated_report: required_fields.append("`integrated_report`")
            return False, \
              HumanMessage(f"❌ Validation failed: this is a refinement round and the new execution result is not self-contained (is_self_contained is False), but {", ".join(required_fields)} is empty; regenerate the result\n"), \
              None
        
        elif is_refinement: # refinement round with a self-contained result: adopt it as cur_result
            new_result = active_objective.refinements[-1].execution_result.model_copy(deep=True)
        else: # first execution
            new_result = active_objective.initial_result.model_copy(deep=True)
            new_result.is_self_contained = True # force the self-contained flag
    else: # both fields present: build the result directly
        new_result = ExecutionResult(
            execution_summary=parsed_output.integrated_summary,
            execution_report =  parsed_output.integrated_report,
            is_self_contained = True
        )

    # c. Validate status
    if parsed_output.status not in ["COMPLETE", "NEEDS_REFINEMENT", "FAILED"]:
        return False, \
            HumanMessage(f"❌ Validation failed: invalid status value {parsed_output.status}; status must be one of 'COMPLETE', 'NEEDS_REFINEMENT', 'FAILED'. Regenerate the result\n"), \
            None
        
      
    if parsed_output.status == "NEEDS_REFINEMENT": # and ((not parsed_output.reason) or (not parsed_output.refinement_goal) or (not parsed_output.refinement_expected_output)):
        # NEEDS_REFINEMENT requires a reason, a goal and an expected output
        required_fields = []
        if not parsed_output.reason: required_fields.append("`reason`") 
        if not parsed_output.refinement_goal: required_fields.append("`refinement_goal`") 
        if not parsed_output.refinement_expected_output: required_fields.append("`refinement_expected_output`") 
        if len(required_fields) != 0:
            return False, \
                HumanMessage(f"❌ Validation failed: status is `NEEDS_REFINEMENT` but {", ".join(required_fields)} is empty; regenerate the result\n"), \
                None
        
    # d. Merge code snippets (refinement rounds only)
    # TODO:
    # Note: the case where 1) parsed_output.integrated_summary or integrated_report is empty while
    #     new_result.is_self_contained is true is not handled: it would arguably mean accepting all of
    #     new_result.code_results and dropping cur_result.code_results, which should correspond to
    #     2) parsed_output.reserved_code_ids empty and parsed_output.add_all_new true. If 1) holds but
    #     2) does not, one could either raise an error or simply accept new_result.code_results without
    #     merging. This case is rare and is intentionally left unhandled for now.
    new_code_results: List[CodeResult] = []
    if is_refinement:
        prev_cr_list = active_objective.cur_result.code_results or [] # guard against None
        new_cr_list = active_objective.refinements[-1].execution_result.code_results or []
        prev_code_results_id_pos_map = {cr.id: i for i, cr in  enumerate(prev_cr_list)}
        new_code_results_id_pos_map = {cr.id: i for i, cr in  enumerate(new_cr_list)}
        if parsed_output.reserve_all_existing: # keep every existing code id
            new_code_results.extend(prev_cr_list)
        else:
            non_exist_prev_cr_ids = set(parsed_output.reserved_code_ids) - set(prev_code_results_id_pos_map.keys())
            if len(non_exist_prev_cr_ids) != 0:
                return False, \
                  HumanMessage(f"❌ Validation failed: these `reserved_code_ids` do not exist in the previous results: {", ".join(non_exist_prev_cr_ids)}; regenerate the result\n"), \
                  None
            else:
                for cr_id in parsed_output.reserved_code_ids:
                    new_code_results.append(prev_cr_list[prev_code_results_id_pos_map[cr_id]])
        
        if parsed_output.add_all_new: # add every code id from the new execution result
            new_code_results.extend(new_cr_list)
        else:
            non_exist_new_cr_ids = set(parsed_output.added_code_ids) - set(new_code_results_id_pos_map.keys())
            if len(non_exist_new_cr_ids) != 0:
                return False, \
                  HumanMessage(f"❌ Validation failed: these `added_code_ids` do not exist in this round's results: {", ".join(non_exist_new_cr_ids)}; regenerate the result\n"), \
                  None
            else:
                for cr_id in parsed_output.added_code_ids:
                    new_code_results.append(new_cr_list[new_code_results_id_pos_map[cr_id]])

    else: 
        new_code_results = active_objective.initial_result.code_results # first execution: copy code_results as-is

    # Renumber the merged code_results; deep-copy so the original data is not mutated
    new_code_results_deep_coopied: List[CodeResult] = []
    for i, cr in enumerate(new_code_results):
        new_cr = cr.model_copy(deep=True)
        new_cr.id = f"prev_cr_{i+1:03d}"
        new_code_results_deep_coopied.append(new_cr)

    # Only after all checks pass, update active_objective starting with its status
    new_active_objective.status = parsed_output.status
    new_active_objective.reason = parsed_output.reason

    # If the status is NEEDS_REFINEMENT, append to the refinements list
    if new_active_objective.status == "NEEDS_REFINEMENT":
        new_active_objective.refinements.append(RefinementRecord(
            refinement_reason = parsed_output.reason,
            refinement_goal = parsed_output.refinement_goal,
            refinement_expected_output = parsed_output.refinement_expected_output,
            execution_result= None # filled in when the refinement execution completes
        ))

    # Attach the merged code_results, then store new_result as cur_result
    new_result.code_results = new_code_results_deep_coopied
    new_active_objective.cur_result = new_result 
    return True, None, new_active_objective

## Result validation for the Result Extract Agent

def _canon_code_result_id(raw_id: Optional[str]) -> str:
    """Normalize a code_result id, tolerating common formatting drift from the LLM.

    prev_cr_001 / cr_001 / prevcr1 / cr1 / prev_cr_1 all normalize to cr1.
    Ids that do not look like cr ids fall back to "lowercase alphanumerics only".
    """
    normalized = re.sub(r'[^a-z0-9]', '', (raw_id or "").lower())
    match = re.match(r'^(?:prev)?cr0*(\d+)$', normalized)
    return f"cr{int(match.group(1))}" if match else normalized


def check_extract_result(
    parsed_output: TaintSpecificationList,
    project_root: str,
    code_results: Optional[List[CodeResult]] = None
) -> Tuple[bool, Optional[HumanMessage], Optional[TaintSpecificationList]]:
    """
    Validate the TaintSpecificationList produced by the Extract Agent.
    with_structured_output already guarantees structural validity, so the focus here is
    business rules plus code authenticity.

    Two modes for code-authenticity checks:
    - [Provenance-anchored mode] code_results is not None: look up the cited evidence entry via
      example.source_code_result_id and check that (a) the id really exists, (b) file_path matches
      it, and (c) code_snippet is a fuzzy subset of that entry. We deliberately do not compare
      against the source file on disk: specification examples keep only the most distinctive core
      statements by design, so they are a focused subset of the evidence entry and a symmetric
      similarity ratio against the original text is structurally unsatisfiable (and would exhaust retries).
    - [Physical-comparison mode] code_results is None (legacy path / node fallback): fall back to
      comparing against the source file on disk.
    """
    if not parsed_output.specifications:
        # An empty list is allowed (e.g. the hypothesis was fully refuted)
        return True, None, parsed_output

    verifier = code_verify.get_verifier(project_root) if (project_root or code_results) else None

    # Build the id index for provenance mode (keep both raw and normalized keys)
    code_result_index = {}
    valid_ids = []
    if code_results is not None:
        for cr in code_results:
            if cr.id:
                code_result_index[cr.id] = cr
                code_result_index.setdefault(_canon_code_result_id(cr.id), cr)
                valid_ids.append(cr.id)

    # spec_id is no longer produced by the LLM; it is assigned deterministically later
    # # 1. spec_id uniqueness check
    # spec_ids = [spec.spec_id for spec in parsed_output.specifications]
    # if len(spec_ids) != len(set(spec_ids)):
    #     duplicates = [sid for sid in spec_ids if spec_ids.count(sid) > 1]
    #     return False, \
    #         HumanMessage(f"❌ Validation failed: duplicate `spec_id` in `specifications`: {set(duplicates)}. Every specification id must be globally unique.\n"), \
    #         None

    # 2. Validate each specification
    for i, spec in enumerate(parsed_output.specifications):
        sid = spec.spec_id

        # 2.1 Summary: mapping_type and index consistency
        if spec.role == "summary":
            if spec.mapping_type in ("arg_to_return", "arg_to_this") and spec.source_arg_index is None:
                return False, \
                    HumanMessage(f"❌ Validation failed: specification `{sid}` has `mapping_type` `{spec.mapping_type}` but is missing the required `source_arg_index`.\n"), \
                    None
            if spec.mapping_type == "this_to_arg" and spec.target_arg_index is None:
                return False, \
                    HumanMessage(f"❌ Validation failed: specification `{sid}` has `mapping_type` `{spec.mapping_type}` but is missing the required `target_arg_index`.\n"), \
                    None

        # 2.2 ground_truth_examples count
        if not spec.ground_truth_examples or len(spec.ground_truth_examples) < 1:
            return False, \
                HumanMessage(f"❌ Validation failed: `ground_truth_examples` of specification `{sid}` must not be empty; provide at least 1 example.\n"), \
                None

        # 2.3 Code authenticity
        for j, example in enumerate(spec.ground_truth_examples):
            # Normalize purpose: synthetic examples are always illustration and never validation targets
            if not example.is_from_project:
                example.purpose = "illustration"
                example.source_code_result_id = None  # synthetic examples have no provenance anchor
                continue  # skip authenticity checks for synthetic code

            # Project examples must pass validation regardless of purpose, so "illustration"
            # cannot be used as an excuse for fabricating project code
            if not example.file_path:
                return False, \
                    HumanMessage(f"❌ Validation failed: example {j+1} of specification `{sid}` has `is_from_project=True` but an empty `file_path`.\n"), \
                    None

            # ---------- Provenance-anchored mode ----------
            if code_results is not None:
                raw_id = example.source_code_result_id
                if not raw_id:
                    return False, \
                        HumanMessage(
                            f"❌ Validation failed: example {j+1} of specification `{sid}` has `is_from_project=True` but no `source_code_result_id`.\n"
                            f"You must name the evidence-pool entry this example was copied from. Available ids: {valid_ids}\n"
                            f"Fill in one id that really exists.\n"
                        ), \
                        None

                referenced = code_result_index.get(raw_id) or code_result_index.get(_canon_code_result_id(raw_id))
                if referenced is None:
                    return False, \
                        HumanMessage(
                            f"❌ Validation failed: `source_code_result_id` = `{raw_id}` of example {j+1} in specification `{sid}` does not exist.\n"
                            f"The only ids that exist in the evidence pool are: {valid_ids}\n"
                            f"Do not invent ids; use one from the list above.\n"
                        ), \
                        None

                # file_path must match the cited entry, preventing "cite A's id but write B's path"
                if (referenced.file_path or "").strip().lstrip("./") != (example.file_path or "").strip().lstrip("./"):
                    return False, \
                        HumanMessage(
                            f"❌ Validation failed: example {j+1} of specification `{sid}` has `file_path` `{example.file_path}`, "
                            f"which does not match the cited evidence entry `{raw_id}` (`{referenced.file_path}`).\n"
                            f"Keep the two consistent.\n"
                        ), \
                        None

                if verifier:
                    contained, coverage, unmatched = verifier.check_snippet_containment(
                        example.code_snippet, referenced.code_snippet
                    )
                    if not contained:
                        return False, \
                            HumanMessage(
                                f"❌ Validation failed: `code_snippet` of example {j+1} in specification `{sid}` is not a subset "
                                f"of evidence entry `{raw_id}` (line hit rate {coverage:.0%}).\n"
                                f"These lines were not found in the cited evidence entry:\n"
                                + "\n".join(f"  - {line}" for line in unmatched) + "\n"
                                f"Select ONLY the most distinctive core statements from `{raw_id}`; do not rewrite, concatenate or complete them.\n"
                            ), \
                            None
                continue

            # ---------- Physical-comparison mode (legacy path / node fallback) ----------
            # Adapt to the CodeResult interface for a physical check
            temp_cr = CodeResult(
                code_description=spec.description,
                is_from_project=True,
                file_path=example.file_path,
                code_snippet=example.code_snippet
            )

            if verifier:
                verify_res = verifier.verify(temp_cr)
                if verify_res.status == code_verify.VerifyStatus.FILE_NOT_FOUND:
                    return False, \
                        HumanMessage(
                            f"❌ Validation failed: file path `{example.file_path}` of example {j+1} in specification `{sid}` does not exist.\n"
                            f"Use the real paths provided in the upstream `code_results`; do not fabricate them.\n"
                        ), \
                        None
                elif verify_res.status == code_verify.VerifyStatus.CODE_MISMATCH:
                    return False, \
                        HumanMessage(
                            f"❌ Validation failed: code of example {j+1} in specification `{sid}` does not match the actual content of `{verify_res.resolved_file_path}`!\n"
                            f"Details: {verify_res.message}\n"
                            f"Do not fabricate or over-edit snippets from the upstream `code_results`; reuse them verbatim.\n"
                        ), \
                        None

    return True, None, parsed_output


def check_plan_update_result(
    parsed_output: PlanUpdateResult,
    plan: AnalysisPlan,
    active_obj_id: str
) -> Tuple[bool, Optional[HumanMessage]]:
    """
    Validate the structured output of the Plan Update Agent.
    Returns: (passed, error message)
    """
    # 1. resolution_summary must not be empty
    if not parsed_output.resolution_summary or not parsed_output.resolution_summary.strip():
        return False, HumanMessage(
            "❌ Validation failed: `resolution_summary` must not be empty. Summarize the key findings for the current objective from a global perspective.\n"
        )

    # 2. Collect the ids of pending objectives (excluding the active one and completed ones)
    pending_obj_ids = {
        obj.id for obj in plan.objectives
        if obj.status == "pending" and obj.id != active_obj_id
    }
    all_obj_ids = {obj.id for obj in plan.objectives}

    # 3. Validate discarded_objectives
    for i, disc in enumerate(parsed_output.discarded_objectives):
        if not disc.obj_id:
            return False, HumanMessage(
                f"❌ Validation failed: item {i+1} of `discarded_objectives` has an empty `obj_id`.\n"
            )
        if disc.obj_id == active_obj_id:
            return False, HumanMessage(
                f"❌ Validation failed: the currently active objective `{disc.obj_id}` cannot be discarded (the system updates its status automatically).\n"
            )
        if disc.obj_id not in pending_obj_ids:
            return False, HumanMessage(
                f"❌ Validation failed: `obj_id` (`{disc.obj_id}`) of item {i+1} in `discarded_objectives` "
                f"is not a pending objective. Only pending objectives can be discarded.\n"
                f"Current pending objectives: {sorted(pending_obj_ids)}\n"
            )
        if not disc.reason or not disc.reason.strip():
            return False, HumanMessage(
                f"❌ Validation failed: item {i+1} of `discarded_objectives` has an empty `reason`.\n"
            )

    # 4. Validate added_objectives
    if parsed_output.added_objectives:
        added = parsed_output.added_objectives
        # 4.1 Validate the insertion position
        if added.insert_after_obj_id is not None:
            if added.insert_after_obj_id not in all_obj_ids:
                return False, HumanMessage(
                    f"❌ Validation failed: `added_objectives.insert_after_obj_id` (`{added.insert_after_obj_id}`) "
                    f"does not exist in the current plan.\n"
                    f"All objective ids: {sorted(all_obj_ids)}\n"
                )
        # 4.2 Validate the new objectives
        if not added.new_objectives:
            return False, HumanMessage(
                "❌ Validation failed: `added_objectives.new_objectives` is an empty list. "
                "If no new objectives are needed, set `added_objectives` to null.\n"
            )
        for i, obj in enumerate(added.new_objectives):
            if not obj.goal or not obj.goal.strip():
                return False, HumanMessage(
                    f"❌ Validation failed: item {i+1} of `added_objectives.new_objectives` has an empty `goal`.\n"
                )
            if not obj.expected_output or not obj.expected_output.strip():
                return False, HumanMessage(
                    f"❌ Validation failed: item {i+1} of `added_objectives.new_objectives` has an empty `expected_output`.\n"
                )

    # 5. Validate core_hypotheses_update (when provided, must contain 1-5 items)
    if parsed_output.core_hypotheses_update is not None:
        if len(parsed_output.core_hypotheses_update) < 1 or len(parsed_output.core_hypotheses_update) > 5:
            return False, HumanMessage(
                f"❌ Validation failed: `core_hypotheses_update` must contain 1-5 items, "
                f"but has {len(parsed_output.core_hypotheses_update)}.\n"
            )

    return True, None
