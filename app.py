import streamlit as st
import pandas as pd
import joblib
import socket
import math
import os
import docx
import pptx
import io
import PyPDF2
from urllib.parse import urlparse

# --- 1. SET PAGE CONFIG (Must be first) ---
st.set_page_config(page_title="Cyber Guard Pro", layout="wide")

# --- 2. LOAD AI MODEL ---
@st.cache_resource
def load_model():
    if os.path.exists("intrusion_pipeline.pkl"):
        return joblib.load("intrusion_pipeline.pkl")
    return None

pipeline = load_model()

# --- 3. HELPER FUNCTIONS ---
def score_url(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        domain = urlparse(url).netloc
        socket.getaddrinfo(domain, None)
        dns = "✅ Active"
    except:
        dns = "❌ Failed"
        domain = url # Fallback
    
    # Simple Entropy calculation
    s = domain.replace(".", "")
    if len(s) == 0: return "Invalid", 0, "❌"
    freq = {c: s.count(c) for c in set(s)}
    ent = sum(-(v/len(s))*math.log2(v/len(s)) for v in freq.values())
    verdict = "Suspicious" if ent > 4 or dns == "❌ Failed" else "Safe"
    return verdict, round(ent, 2), dns

def scan_text_for_threats(text):
    keywords = ["password", "login", "bank", "verify", "urgent", "bitcoin", "click here"]
    found = [k for k in keywords if k in text.lower()]
    return found

# --- 4. THE UI ---
st.title("🚨 Network IDS & URL Safety Scanner")

tab1, tab2 = st.tabs(["📁 File Safety Scan", "🔍 URL Scanner"])

with tab1:
    st.header("Multi-File Threat Analysis")
    uploaded_file = st.file_uploader("Upload any file (CSV, PDF, Word, TXT)", type=None)

    if uploaded_file:
        file_ext = os.path.splitext(uploaded_file.name)[1].lower()
        text_content = ""

        try:
            # A. CSV Analysis (ML Logic)
            if file_ext == ".csv":
                df = pd.read_csv(uploaded_file)
                st.write("### Data Preview")
                st.dataframe(df.head())
                if pipeline:
                    # Clean data for model
                    test_df = df.drop(columns=["label", "difficulty", "attack"], errors='ignore')
                    preds = pipeline.predict(test_df)
                    df["Prediction"] = ["🚫 Attack" if p == 1 else "✅ Normal" for p in preds]
                    st.write("### Results")
                    st.dataframe(df)
                    st.write("Summary:", df["Prediction"].value_counts())
                else:
                    st.error("ML Model file missing. Run train_model.py!")

            # B. PDF / Word / Text Analysis
            elif file_ext == ".pdf":
                pdf_reader = PyPDF2.PdfReader(uploaded_file)
                text_content = "".join([page.extract_text() for page in pdf_reader.pages])
            elif file_ext == ".docx":
                doc = docx.Document(uploaded_file)
                text_content = "\n".join([p.text for p in doc.paragraphs])
            else:
                text_content = uploaded_file.read().decode(errors="ignore")

            # Threat Keyword Scan for non-CSV text
            if text_content:
                st.write("### Text Content Analysis")
                threats = scan_text_for_threats(text_content)
                if threats:
                    st.warning(f"⚠️ Suspicious keywords found: {', '.join(threats)}")
                else:
                    st.success("✅ No common phishing keywords detected in text.")
                st.text_area("File Content (Preview)", text_content[:1000])

        except Exception as e:
            st.error(f"Error reading file: {e}")

with tab2:
    st.header("URL Security Check")
    url_input = st.text_input("Paste a link here...")
    if st.button("Scan URL"):
        if url_input:
            verdict, ent, dns = score_url(url_input)
            col1, col2, col3 = st.columns(3)
            col1.metric("Verdict", verdict)
            col2.metric("Randomness (Entropy)", ent)
            col3.metric("DNS Status", dns)
            if verdict == "Safe": st.success("This URL looks safe.")
            else: st.error("Caution: This URL is suspicious!")