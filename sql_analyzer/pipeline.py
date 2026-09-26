"""Single entry point: SQL summary + security analysis."""

from __future__ import annotations

from typing import Any, Dict

from sql_analyzer.security import analyze_security
from sql_analyzer.sql_extract import normalize_whitespace
from sql_analyzer.sql_summary import summarize


def analyze(source: str) -> Dict[str, Any]:
    """Analyze one SQL/code snippet. Formatting/whitespace does not change security class."""
    text = source if source is not None else ""
    security = analyze_security(text)
    try:
        summary = summarize(text)
    except Exception:
        summary = (
            "The SQL could not be parsed completely, so no extra operations were assumed. "
            "Security analysis below is still based on the original input."
        )
    return {
        "summary": summary,
        "normalized": normalize_whitespace(text),
        "security": security.as_dict(),
    }
