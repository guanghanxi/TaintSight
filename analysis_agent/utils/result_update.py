from typing import List

# global module 
from global_data_model.analysis_result import TaintSpecificationList, SpecificationUnion

# analysis agent local module
from analysis_agent.data_model.plan_data_model import PlanUpdateResult, AnalysisPlan, InvestigationObjective


# Apply the result produced by plan_update_node to the global plan
def apply_plan_update(
    plan: AnalysisPlan,
    parsed_output: PlanUpdateResult,
    # active_obj_id: str,
    # review_status: str
) -> AnalysisPlan:
    """
    Apply a validated PlanUpdateResult to an AnalysisPlan.
    Returns the updated plan (deep copy).
    """
    new_plan = plan.model_copy(deep=True)

    # This is handled in plan_promotion_node.
    # # 1. Update the current objective's status and conclusion
    # for obj in new_plan.objectives:
    #     if obj.id == active_obj_id:
    #         if review_status == "FAILED":
    #             obj.status = "discarded"
    #         else:
    #             obj.status = "resolved"
    #         obj.resolution_summary = parsed_output.resolution_summary
    #         break

    # 2. Update global knowledge
    if parsed_output.project_profile_update:
        new_plan.project_profile = parsed_output.project_profile_update
    if parsed_output.core_hypotheses_update is not None:
        new_plan.core_hypotheses = parsed_output.core_hypotheses_update

    # 3. Apply discards
    discard_map = {d.obj_id: d.reason for d in parsed_output.discarded_objectives}
    for obj in new_plan.objectives:
        if obj.id in discard_map:
            obj.status = "discarded"
            obj.resolution_summary = discard_map[obj.id]

    # 4. Apply additions (with deterministic IDs)
    if parsed_output.added_objectives and parsed_output.added_objectives.new_objectives:
        added = parsed_output.added_objectives
        # Find the current maximum ID number so new IDs do not collide
        max_id_num = 0
        for obj in new_plan.objectives:
            if obj.id and obj.id.startswith("obj_"):
                try:
                    max_id_num = max(max_id_num, int(obj.id.split("_")[-1]))
                except ValueError:
                    pass

        new_objs = []
        for i, new_obj in enumerate(added.new_objectives):
            new_objs.append(InvestigationObjective(
                id=f"obj_{max_id_num + i + 1:04d}",
                goal=new_obj.goal,
                expected_output=new_obj.expected_output,
                status="pending",
                execution_narrative="",
                resolution_summary=None
            ))

        # Determine the insertion position
        if added.insert_after_obj_id:
            insert_idx = None
            for idx, obj in enumerate(new_plan.objectives):
                if obj.id == added.insert_after_obj_id:
                    insert_idx = idx + 1
                    break
            if insert_idx is not None:
                new_plan.objectives[insert_idx:insert_idx] = new_objs
            else:
                new_plan.objectives.extend(new_objs)
        else:
            new_plan.objectives.extend(new_objs)

    return new_plan

# Deterministically assign spec_ids to specifications
def gen_spec_ids(specifications: List[SpecificationUnion], prefix: str = ""):
    prefix_str = f"{prefix}_" if prefix else ""

    # Count how many specifications of each role the current objective produced
    role_counters = {}
    for spec in specifications:
        role = spec.role
        role_counters[role] = role_counters.get(role, 0) + 1
        # Deterministic, traceable ID (prefix_str already ends with an underscore)
        spec.spec_id = f"{prefix_str}{role}_{role_counters[role]:02d}"
    