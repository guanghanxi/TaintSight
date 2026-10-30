"""
interaction_history.py
Per-specification interaction history.
- Latest round: raw AIMessage plus full feedback, inserted into messages directly
- Earlier rounds: code plus a compressed summary, shown in the compressed history
"""
from dataclasses import dataclass
from typing import List

from langchain_core.messages import AIMessage, message_to_dict


@dataclass
class RoundRecord:
    """One interaction round."""
    round_num: int
    raw_ai_message: AIMessage      # raw AIMessage (kept intact)
    feedback_text: str             # full feedback text (used directly in the latest round)
    error_summary: str             # compressed error summary (for historical display only)
    failure_type: str              # "compile_error" | "no_code" | "runtime_error" | "empty_result" | "gt_not_hit" | "scope_abnormal"


class InteractionHistory:
    """
    Full interaction history for one specification.

    Storage policy:
    - feedback_text: full detailed feedback (compiler errors, GT analysis, ...),
      used directly for the latest round
    - error_summary: one-line compressed summary, used only in the compressed history
    """

    def __init__(self):
        self.records: List[RoundRecord] = []

    def add_round(
        self,
        ai_message: AIMessage,
        feedback_text: str,
        failure_type: str,
        error_summary: str = "",
    ):
        """
        Record one failed round.

        Args:
            ai_message:    raw AIMessage returned by the LLM (kept intact)
            feedback_text: full detailed feedback (compiler errors, validation analysis, ...)
            failure_type:  failure type identifier
            error_summary: one-line summary. Structured feedback
                           (error_feedback.jinja2) passes a precise summary derived
                           from ErrorDiagnosis; empty falls back to generic compression.
        """
        self.records.append(RoundRecord(
            round_num=len(self.records) + 1,
            raw_ai_message=ai_message,
            feedback_text=feedback_text,
            error_summary=error_summary or self._compress_error(failure_type, feedback_text),
            failure_type=failure_type,
        ))

        return {
            "raw_response": message_to_dict(ai_message),
            "pass_validation": False,
            "failure_type": failure_type,
            "feedback_text": feedback_text,            
        }

    @property
    def total_rounds(self) -> int:
        return len(self.records)

    def build_compressed_summary(self) -> str:
        """
        Compress all rounds except the latest into plain text.
        Each round keeps only its code and a one-line error summary.
        """
        if len(self.records) <= 1:
            return ""

        older_records = self.records[:-1]
        lines: List[str] = []
        lines.append("## Previous attempts (avoid repeating these errors)")
        lines.append("")

        for r in older_records:
            lines.append(f"### Round {r.round_num}")
            code = self._extract_code_from_message(r.raw_ai_message)
            lines.append("```codeql")
            lines.append(code if code else r.raw_ai_message.content[:500])
            lines.append("```")
            lines.append(f"**Error type**: {r.failure_type}")
            lines.append(f"**Error summary**: {r.error_summary}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _extract_code_from_message(msg: AIMessage) -> str:
        """Extract the code block from an AIMessage (for compressed history)."""
        import re
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        pattern = r"```(?:codeql|ql)?\s*\n(.*?)```"
        match = re.search(pattern, content, re.DOTALL)
        if match:
            return match.group(1).strip()
        return content.strip()

    @staticmethod
    def _compress_error(failure_type: str, feedback_text: str) -> str:
        """
        Compress full feedback into one line.
        Used only for historical display; the latest round keeps full feedback.
        """
        if failure_type == "compile_error":
            for line in feedback_text.split("\n"):
                stripped = line.strip()
                if "ERROR" in stripped or "error" in stripped.lower():
                    return stripped[:150]
            return feedback_text[:150]

        elif failure_type == "no_code":
            return "No valid CodeQL code block was produced"

        elif failure_type == "runtime_error":
            return feedback_text[:150]

        elif failure_type == "empty_result":
            return "Query returned no results; no nodes matched"

        elif failure_type == "gt_not_hit":
            return "Query returned results but none matched the ground-truth file path"

        return feedback_text[:150]