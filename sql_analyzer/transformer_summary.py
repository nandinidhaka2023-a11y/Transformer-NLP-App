"""Hugging Face Transformer layer for natural-language SQL explanations."""

from __future__ import annotations

from functools import lru_cache

from transformers import pipeline


@lru_cache(maxsize=1)
def _load_model():
    return pipeline(
        "text2text-generation",
        model="google/flan-t5-small",
    )


def generate_nlp_explanation(sql_summary: str) -> str:
    """Generate a natural-language explanation without changing SQL facts."""
    if not sql_summary.strip():
        return "No explanation available."

    prompt = (
        "Explain this database query description in simple language. "
        "Do not introduce any new facts, table names, column names, "
        "conditions, values, or operations. Keep it to one or two sentences.\n\n"
        f"Description: {sql_summary}"
    )

    try:
        result = _load_model()(
            prompt,
            max_new_tokens=80,
            do_sample=False,
        )

        if result:
            text = result[0].get("generated_text", "").strip()
            if text:
                return text

    except Exception:
        pass

    return "Transformer explanation unavailable. The parser-based SQL summary above remains the authoritative explanation."
