from typing import List, Dict, Any

# global module 
from global_data_model.analysis_result import TaintSpecificationList, SpecificationUnion

# analysis agent local module
from analysis_agent.data_model.plan_data_model import PlanUpdateResult, AnalysisPlan, InvestigationObjective

# ==========================================
# Text helpers
#
# 1. Concatenate the global objective list
# ==========================================
def gen_global_objectives_text(plan: AnalysisPlan, include_uncompleted_objective: bool = True):
    lines = []
    for obj in plan.objectives:
        # Skip unfinished objectives when not requested
        if obj.status not in ["resolved", "discarded"] and not include_uncompleted_objective:
            continue
        
        # 1. Format the status label (e.g. [RESOLVED] or [PENDING])
        status_tag = f"[{obj.status.upper()}]"
        status_icon = {"pending": "⏳", "investigating": "🔍", "resolved": "✅", "discarded": "❌"}.get(obj.status, "❓")
        # 2. Build the base line (:<12 aligns the status tags)
        base_text = f"{status_icon} {status_tag:<12} {obj.id} (status: {obj.status}): {obj.goal}"
        
        # 3. Append the conclusion when the objective is resolved/discarded and has one
        if obj.status in ["resolved", "discarded"] and obj.resolution_summary:
            # Newline + `↳` gives a visual indent so the LLM separates goal from conclusion
            base_text += f"\n  ↳ Conclusion: {obj.resolution_summary}"
            
        lines.append(base_text)

    return "\n".join(lines) if lines else "No global plan yet"

def extract_spec_summary(spec: SpecificationUnion) -> Dict[str, Any]:
    """
    Compress a large Specification into a minimal summary for LLM comparison, saving tokens.
    """
    summary = {
        "spec_id": spec.spec_id,
        "role": spec.role,
        "description": spec.description,
    }
    
    # Extract the core matching intent by role
    if spec.role in ["source", "sink"]:
        # Extract matching_description from node_pattern
        if hasattr(spec.node_pattern, "matching_description"):
            summary["matching_intent"] = spec.node_pattern.matching_description
        elif hasattr(spec.node_pattern, "matching_intent"): # CustomLogicPattern
            summary["matching_intent"] = spec.node_pattern.matching_intent
    elif spec.role == "summary":
        summary["matching_intent"] = spec.matching_description
        summary["mapping_type"] = spec.mapping_type
    elif spec.role == "flow_step":
        summary["matching_intent"] = spec.pattern.matching_intent
        
    return summary

# Top-level layout of the target project

from pathlib import Path

def get_top_level_layout(project_root: str) -> str:
    """
    Return the project's top-level directory layout (root level 1, core source
    directories level 2). Used by the Planner for low-cost project profiling.
    """
    root_path = Path(project_root)
    if not root_path.exists() or not root_path.is_dir():
        return "Cannot read the project root"

    # Ignore noise directories unrelated to vulnerability analysis
    IGNORE_DIRS = {
        '.git', '.idea', '.vscode', '.settings', '.github',
        'node_modules', 'target', 'build', 'bin', 'out', 
        '.gradle', '__pycache__', '.DS_Store', 'logs'
    }
    
    # Drill one level into these directories (depth 2) to expose Java packages or submodules
    DRILL_DOWN_DIRS = {'src', 'app', 'lib', 'core', 'internal', 'pkg', 'main', 'java'}
    
    lines = []
    
    try:
        # Level 1: directories first, then files, alphabetically
        level_1_entries = sorted(
            [e for e in root_path.iterdir() if e.name not in IGNORE_DIRS and not e.name.startswith('.')],
            key=lambda x: (not x.is_dir(), x.name.lower())
        )
    except PermissionError:
        return "Permission denied while reading the project root"

    for i, entry in enumerate(level_1_entries):
        is_last = (i == len(level_1_entries) - 1)
        prefix = "└── " if is_last else "├── "
        
        if entry.is_dir():
            lines.append(f"{prefix}{entry.name}/")
            # Drill down: expand core source directories to level 2
            if entry.name.lower() in DRILL_DOWN_DIRS:
                try:
                    level_2_entries = sorted(
                        [e for e in entry.iterdir() if e.name not in IGNORE_DIRS],
                        key=lambda x: (not x.is_dir(), x.name.lower())
                    )
                    # Cap at 15 entries to keep the prompt from exploding on large source trees
                    for j, sub_entry in enumerate(level_2_entries[:15]): 
                        sub_is_last = (j == len(level_2_entries) - 1) or (j == 14)
                        sub_prefix = "    └── " if sub_is_last else "    ├── "
                        suffix = "/" if sub_entry.is_dir() else ""
                        lines.append(f"{sub_prefix}{sub_entry.name}{suffix}")
                    if len(level_2_entries) > 15:
                        lines.append("    └── ... (more directories/packages omitted)")
                except PermissionError:
                    pass
        else:
            lines.append(f"{prefix}{entry.name}")
            
    return "\n".join(lines) if lines else "(empty directory)"