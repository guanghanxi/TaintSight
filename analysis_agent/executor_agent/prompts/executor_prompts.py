# ==========================================
#  Global user prompt
#  Introduces the current task; shared by the Updater and the Analyzer.
#  1. Global User Prompt: initial execution mode
# ==========================================
EXECUTION_USER_GLOBAL_INITIAL_TEMPLATE = """[Background profile loaded by the system]
Project name: {project_name}
Project profile: {project_profile}
Target CWE: {cwe_id}

Core macro hypotheses:
{core_hypotheses}

[Completed/discarded investigation objectives (historical conclusions)]
{completed_objectives_text}

[Current focus objective (highest priority, applies throughout)]
ID: {objective_id}
Task description: {objective_goal}
Expected output: {expected_output}
"""


# ==========================================
# 2. Global User Prompt: Refinement mode
# ==========================================
EXECUTION_USER_GLOBAL_REFINEMENT_TEMPLATE = """[Background profile loaded by the system]
Project name: {project_name}
Project profile: {project_profile}
Target CWE: {cwe_id}

[Targeted refinement task]
Original objective ID: {objective_id}
Original task description: {objective_goal}
Original expected output: {expected_output}
Note: the above is the initial task information. You previously judged this task complete; your earlier findings are below. The actual task now is a targeted refinement on top of them; do not repeat existing content.

[Previous execution result (to be improved)]
Execution summary: <execution_summary>{prev_execution_summary}</execution_summary>
Execution report:
<execution_report>
{prev_execution_report}
</execution_report>

Code snippet results:
{prev_code_results}

Note: the above is your previously completed investigation. The current task is a targeted refinement on top of it; do not repeat existing content.

[Targeted refinement task]
Refinement reason: {refinement_reason}
Refinement goal: {refinement_goal}
Refinement expected output: {refinement_expected_output}

Note: this targeted refinement task is the task you actually need to complete.
"""
