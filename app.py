import streamlit as st
from transformers import pipeline

# Page setup
st.set_page_config(page_title="Secure NLP App", layout="centered")

st.title("🧠 Transformer NLP App")
st.write("Performs summarization, sentiment analysis, and security detection.")

# Load lightweight models
@st.cache_resource
def load_models():
    summarizer = pipeline("summarization", model="sshleifer/distilbart-cnn-6-6")
    sentiment = pipeline("sentiment-analysis")
    return summarizer, sentiment

summarizer, sentiment_analyzer = load_models()

# ---------------- INPUT ----------------
text = st.text_area("✍️ Enter text or code:", height=200)

# ---------------- SUMMARIZATION ----------------
if st.button("✨ Summarize"):
    if text.strip():
        with st.spinner("Generating summary..."):
            try:
                result = summarizer(
                    "summarize: " + text,
                    max_length=40,
                    min_length=10,
                    do_sample=False
                )
                summary = result[0]['summary_text']
                st.subheader("📌 Summary:")
                st.success(summary)
            except:
                st.error("Error generating summary")
    else:
        st.warning("Please enter text!")

# ---------------- SENTIMENT ----------------
if st.button("😊 Sentiment Analysis"):
    if text.strip():
        result = sentiment_analyzer(text)
        label = result[0]['label']
        score = result[0]['score']

        st.subheader("💬 Sentiment:")
        if label == "POSITIVE":
            st.success(f"Positive 😊 (Confidence: {score:.2f})")
        else:
            st.error(f"Negative 😞 (Confidence: {score:.2f})")
    else:
        st.warning("Please enter text!")

# ---------------- SECURITY CHECK ----------------
def check_vulnerability(code):
    code = code.lower()

    if "select" in code and "+" in code:
        return "⚠️ SQL Injection Risk detected"
    elif "os.system" in code:
        return "⚠️ Command Injection Risk detected"
    elif "input(" in code and "+" in code:
        return "⚠️ Unsafe user input handling"
    else:
        return "✅ No major vulnerabilities detected"

if st.button("🔐 Check Security"):
    if text.strip():
        result = check_vulnerability(text)

        st.subheader("🔍 Security Analysis:")
        if "⚠️" in result:
            st.error(result)
        else:
            st.success(result)
    else:
        st.warning("Please enter text!")

# Footer
st.markdown("---")
st.markdown("Lightweight Transformer + Security Analysis")