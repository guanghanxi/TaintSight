"""
prompt_builder.py
Prompt builder: separates prompt content from code via Jinja2 templates.
"""
from pathlib import Path
from typing import List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from global_data_model.analysis_result import SpecificationUnion

# Locate the prompts directory relative to this file, not the working directory
_CURRENT_DIR = Path(__file__).resolve().parent
_DEFAULT_PROMPTS_DIR = _CURRENT_DIR / "prompts"
_DEFAULT_EXPERIENCE_PATH = _CURRENT_DIR / "prompts" / "CodeQL_Experience_V4.1.md"

class PromptBuilder:
    def __init__(
        self,
        prompts_dir: Optional[str] = None,
        codeql_experience_path: Optional[str] = None,
    ):
        # Fall back to paths relative to __file__
        self.prompts_dir = Path(prompts_dir) if prompts_dir else _DEFAULT_PROMPTS_DIR
        _exp_path = Path(codeql_experience_path) if codeql_experience_path else _DEFAULT_EXPERIENCE_PATH

        self.experience_text = self._load_experience(_exp_path)

        # Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(str(self.prompts_dir)),
            autoescape=select_autoescape([]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    @staticmethod
    def _load_experience(path: Path) -> str:
        if path.exists():
            return path.read_text(encoding="utf-8")
        return "[CodeQL experience file not found; check the path]"

    # ----------------------------------------------------------
    #  System prompt (identical across calls, benefits from prefix caching)
    # ----------------------------------------------------------
    def build_system_prompt(self) -> str:
        template = self.env.get_template("system_prompt.jinja2")
        return template.render(experience_text=self.experience_text)

    # ----------------------------------------------------------
    #  Initial user message (routed by spec role)
    # ----------------------------------------------------------
    def build_initial_user_message(
        self,
        spec: SpecificationUnion,
        predicate_name: str,
    ) -> str:
        if spec.role in ("source", "sink"):
            template_name = "user_messages/source_sink.jinja2"
        elif spec.role == "summary":
            template_name = "user_messages/summary.jinja2"
        elif spec.role == "flow_step":
            template_name = "user_messages/flow_step.jinja2"
        else:
            raise ValueError(f"Unknown spec role: {spec.role}")

        template = self.env.get_template(template_name)
        return template.render(spec=spec, predicate_name=predicate_name)

    # ----------------------------------------------------------
    #  Feedback messages (appended to messages as HumanMessage)
    # ----------------------------------------------------------
    
    def build_history_summary_message(self, older_records: list) -> str:
        """
        Compress earlier rounds into a single HumanMessage.

        Args:
            older_records: List[RoundRecord], excluding the latest round
        """
        if not older_records:
            return ""
        template = self.env.get_template("feedback/history_summary.jinja2")
        return template.render(older_records=older_records)
    
    def build_error_feedback_message(self, diagnosis) -> str:
        """
        Structured error feedback.

        Args:
            diagnosis: retry_policy.ErrorDiagnosis -- the raw CodeQL stderr mapped to
                       line numbers in the model's own code plus per-item API corrections.
        """
        template = self.env.get_template("feedback/error_feedback.jinja2")
        return template.render(
            diagnosis=diagnosis,
            stage_label="compile" if diagnosis.stage == "compile" else "run",
        )

    def build_empty_result_message(self) -> str:
        template = self.env.get_template("feedback/empty_result_feedback.jinja2")
        return template.render()

    def build_no_code_message(self) -> str:
        """The latest reply contained no extractable CodeQL code block."""
        template = self.env.get_template("feedback/no_code_feedback.jinja2")
        return template.render()

    def build_scope_abnormal_message(
        self,
        spec: SpecificationUnion,
        diagnostics: dict,
        retry_index: int,
        max_retries: int,
        project_api_call_count: int = 0,
    ) -> str:
        """
        Feedback for abnormal match scope (too many results / unconstrained
        disjunct variables in the predicate).

        Args:
            spec: current specification (its role tells the template which node
                  variable must be constrained)
            diagnostics: diagnostics dict from validator.ResultValidator.validate
            retry_index: which scope rewrite this is (1-based)
            max_retries: scope rewrite budget
            project_api_call_count: total API calls in the project, for scale reference only
        """
        template = self.env.get_template("feedback/scope_abnormal_feedback.jinja2")
        return template.render(
            spec=spec,
            diagnostics=diagnostics or {},
            retry_index=retry_index,
            max_retries=max_retries,
            project_api_call_count=project_api_call_count,
        )

    def build_gt_miss_message(
        self,
        expected_paths: List[str],
        matched_locations: List[str],
        matched_code_snippets: Optional[List[str]] = None,
    ) -> str:
        template = self.env.get_template("feedback/gt_miss_feedback.jinja2")
        return template.render(
            expected_paths=expected_paths,
            matched_locations=matched_locations,
            matched_code_snippets=matched_code_snippets or [],
        )