import html

import streamlit as st

from sql_analyzer.examples import EXAMPLES
from sql_analyzer.pipeline import analyze
from sql_analyzer.transformer_summary import generate_nlp_explanation

st.set_page_config(
    page_title="SQL Insight | Query & Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

LEVEL_META = {
    "SAFE": ("🟢", "safe", "#16a34a"),
    "LOW": ("🟡", "low", "#ca8a04"),
    "MEDIUM": ("🟠", "medium", "#ea580c"),
    "HIGH": ("🔴", "high", "#dc2626"),
    "CRITICAL": ("🔴", "critical", "#991b1b"),
}

st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'IBM Plex Sans', sans-serif;
    }

    .stApp {
        background:
            radial-gradient(1200px 500px at 10% -10%, #12315a 0%, transparent 55%),
            radial-gradient(900px 400px at 100% 0%, #0f3d3a 0%, transparent 50%),
            #0b1220;
        color: #e8eef7;
    }

    .block-container {
        padding-top: 1.4rem;
        max-width: 1180px;
    }

    .hero {
        border: 1px solid #1f3358;
        background: linear-gradient(180deg, rgba(18, 32, 58, 0.92), rgba(11, 18, 32, 0.92));
        border-radius: 18px;
        padding: 1.5rem 1.7rem 1.3rem;
        margin-bottom: 1.1rem;
        box-shadow: 0 12px 40px rgba(0, 0, 0, 0.25);
    }

    .kicker {
        color: #7dd3c7;
        letter-spacing: 0.16em;
        font-size: 0.72rem;
        font-weight: 700;
        margin-bottom: 0.35rem;
    }

    .hero h1 {
        margin: 0;
        font-size: 2rem;
        letter-spacing: -0.03em;
        color: #f8fbff;
    }

    .hero p {
        margin: 0.55rem 0 0;
        color: #b7c4d8;
        font-size: 1.02rem;
        line-height: 1.5;
        max-width: 52rem;
    }

    .chip-row {
        display: flex;
        flex-wrap: wrap;
        gap: 0.45rem;
        margin-top: 0.9rem;
    }

    .chip {
        border: 1px solid #2a4574;
        color: #c9d7ee;
        background: #13233f;
        border-radius: 999px;
        padding: 0.22rem 0.7rem;
        font-size: 0.78rem;
        font-weight: 500;
    }

    textarea {
        font-family: 'IBM Plex Mono', monospace !important;
        font-size: 0.92rem !important;
    }

    div[data-testid="stTextArea"] textarea {
        background: #0d1728 !important;
        color: #e6eefc !important;
        border: 1px solid #2a4574 !important;
        border-radius: 12px !important;
    }

    .stButton > button {
        border-radius: 11px;
        font-weight: 650;
        padding: 0.55rem 1.1rem;
        border: 0;
    }

    .stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #14b8a6, #0ea5e9);
        color: #04131a;
    }

    .card {
        border-radius: 16px;
        padding: 1.15rem 1.2rem 1.05rem;
        min-height: 210px;
        border: 1px solid #24375c;
        background: #101a2d;
        box-shadow: 0 10px 28px rgba(0, 0, 0, 0.18);
    }

    .card h3 {
        margin: 0 0 0.7rem;
        font-size: 1.05rem;
        color: #f3f7ff;
    }

    .muted {
        color: #93a4bd;
        font-size: 0.86rem;
        margin-bottom: 0.8rem;
    }

    .summary-body {
        color: #e8eef7;
        font-size: 1.02rem;
        line-height: 1.55;
    }

    .badge {
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
        border-radius: 999px;
        padding: 0.28rem 0.75rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        font-size: 0.82rem;
        margin-bottom: 0.85rem;
    }

    .meta-label {
        color: #86a0c4;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-top: 0.7rem;
        margin-bottom: 0.2rem;
    }

    .meta-value {
        color: #eef4ff;
        line-height: 1.5;
    }

    .footnote {
        color: #7f91ad;
        font-size: 0.8rem;
        margin-top: 1.2rem;
    }
</style>
""",
    unsafe_allow_html=True,
)

st.markdown(
    """
<div class="hero">
  <div class="kicker">SQL FIRST · STATIC SECURITY ANALYSIS</div>
  <h1>SQL Insight</h1>
  <p>
    Paste one SQL query or a code snippet that builds SQL. A single Analyze pass explains
    what the statement does and checks it for injection and related risks.
    Ordinary <code>SELECT</code> statements are not treated as vulnerabilities.
  </p>
  <div class="chip-row">
    <span class="chip">Parser-based SQL summary</span>
    <span class="chip">SQL injection detection</span>
    <span class="chip">Command / path / code injection</span>
    <span class="chip">Hardcoded secrets</span>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

if "sql_input" not in st.session_state:
    st.session_state.sql_input = EXAMPLES["Simple SELECT"]

st.markdown("#### SQL / code input")
example_name = st.selectbox("Load an example", ["(keep current input)"] + list(EXAMPLES.keys()))
c1, c2, _ = st.columns([1.2, 1.2, 3])
with c1:
    load_clicked = st.button("Load example", use_container_width=True)
with c2:
    clear_clicked = st.button("Clear", use_container_width=True)

if load_clicked and example_name in EXAMPLES:
    st.session_state.sql_input = EXAMPLES[example_name]
    st.rerun()
if clear_clicked:
    st.session_state.sql_input = ""
    st.rerun()

st.text_area(
    "Query editor",
    key="sql_input",
    height=260,
    placeholder="SELECT name, email FROM users WHERE age > 18 ORDER BY name;",
    label_visibility="collapsed",
)

analyze_clicked = st.button("🔍 Analyze", type="primary", use_container_width=True)

if analyze_clicked:
    source = st.session_state.sql_input or ""
    if not source.strip():
        st.warning("Enter a SQL query or code snippet first.")
    else:
        result = analyze(source)
        security = result["security"]
        level = security["level"]
        icon, _, color = LEVEL_META.get(level, ("⚪", "unknown", "#64748b"))
        summary_html = html.escape(result["summary"])
        transformer_explanation = html.escape(
            generate_nlp_explanation(result["summary"])
        )
        vuln = html.escape(security["vulnerability"])
        explanation = html.escape(security["explanation"])
        fix = html.escape(security["fix"])

        left, middle, right = st.columns(3, gap="medium")
        with left:
            st.markdown(
                f"""
                <div class="card">
                  <h3>📋 SQL summary</h3>
                  <div class="muted">What does this query do?</div>
                  <div class="summary-body">{summary_html}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with middle:
            st.markdown(
                f"""
                <div class="card">
                  <h3>🤖 Transformer NLP explanation</h3>
                  <div class="muted">Generated using Hugging Face FLAN-T5</div>
                  <div class="summary-body">{transformer_explanation}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with right:
            st.markdown(
                f"""
                <div class="card">
                  <h3>🛡️ Security analysis</h3>
                  <div class="badge" style="background:{color}22;color:{color};border:1px solid {color}66;">
                    {icon} {level}
                  </div>
                  <div class="meta-label">Detected vulnerability</div>
                  <div class="meta-value">{vuln}</div>
                  <div class="meta-label">Explanation</div>
                  <div class="meta-value">{explanation}</div>
                  <div class="meta-label">Recommended fix</div>
                  <div class="meta-value">{fix}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        extra = security.get("findings") or []
        if len(extra) > 1:
            with st.expander("All findings"):
                for finding in extra:
                    st.markdown(f"**{finding['level']} — {finding['vulnerability']}**  \n{finding['explanation']}")

st.markdown(
    '<p class="footnote">Static analysis only. A SAFE result means no matching rule fired — not that the code is fully secure.</p>',
    unsafe_allow_html=True,
)
