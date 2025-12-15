import streamlit as st
import pandas as pd
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import io
import os
import re
# === CONFIG ===
PAYLOAD_PATH = "9702payload.txt"  # originally .enc
UPDATES_PATH = "updates.json"
PDF_BASE_URL = "https://sialaichai.github.io/physics9702/"

# === DECRYPTION ===
def decrypt_payload(password: str, encrypted_b64: str) -> dict:
    try:
        encrypted_data = base64.b64decode(encrypted_b64)
        # Derive key/IV same way as CryptoJS (OpenSSL-compatible)
        password_bytes = password.encode('utf-8')
        key = password_bytes
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return json.loads(decrypted.decode('utf-8'))
    except Exception as e:
        st.error(f"Decryption failed: {str(e)}")
        return None

# === LOAD ENCRYPTED DATA ===
@st.cache_data
def load_encrypted_data():
    if not os.path.exists(PAYLOAD_PATH):
        st.error("❌ 9702payload.txt not found!")
        return None
    with open(PAYLOAD_PATH, 'r') as f:
        return f.read().strip()

# === LOAD UPDATES (optional) ===
def load_updates():
    if os.path.exists(UPDATES_PATH):
        with open(UPDATES_PATH, 'r') as f:
            return json.load(f)
    return []

# === MAIN APP ===
def main():
    st.set_page_config(page_title="9702 Physics Viewer", layout="wide")
    st.title("🔐 9702 Physics Past Paper Viewer")

    # Load encrypted payload once
    encrypted_text = load_encrypted_data()
    if not encrypted_text:
        return

    # Session state for authentication & data
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.data = None

    # === LOGIN SCREEN ===
    if not st.session_state.authenticated:
        with st.form("login"):
            password = st.text_input("Enter password", type="password")
            submitted = st.form_submit_button("Unlock")
            if submitted and password:
                bundle = decrypt_payload(password, encrypted_text)
                if bundle:
                    st.session_state.authenticated = True
                    main_data = bundle.get("data", [])
                    # Merge updates
                    updates = load_updates()
                    if updates:
                        main_data.extend(updates)
                    # Normalize and clean
                    normalized = []
                    for item in main_data:
                        q = str(item.get("question", "")).strip()
                        q = re.sub(r'^q0+(\d)', r'q\1', re.sub(r'\.pdf$', '', q, flags=re.IGNORECASE), flags=re.IGNORECASE)
                        normalized.append({
                            "filename": str(item.get("filename", "")).strip(),
                            "year": str(item.get("year", "")).strip(),
                            "paper": str(item.get("paper", "")).strip(),
                            "question": q,
                            "mainTopic": str(item.get("mainTopic", "")).strip(),
                            "otherTopics": [t.strip() for t in (item.get("otherTopics") or []) if t.strip()]
                        })
                    st.session_state.data = pd.DataFrame(normalized)
                    st.session_state.folder = bundle.get("secure_folder", "")
                    st.rerun()
                else:
                    st.error("Incorrect password")
        return

    # === MAIN INTERFACE ===
    df = st.session_state.data
    if df is None or df.empty:
        st.warning("No data loaded.")
        return

    # Sidebar filters
    st.sidebar.header("🔍 Filters")
    
    all_years = sorted(df["year"].dropna().unique(), reverse=True)
    selected_years = st.sidebar.multiselect("Year", options=all_years)

    all_papers = sorted(df["paper"].dropna().unique())
    selected_papers = st.sidebar.multiselect("Paper", options=all_papers)

    all_questions = sorted(df["question"].dropna().unique(), key=lambda x: [int(c) if c.isdigit() else c for c in x.split()])
    selected_questions = st.sidebar.multiselect("Question", options=all_questions)

    # Extract and split main topics (some entries have ";")
    def extract_main_topics(series):
        topics = set()
        for val in series.dropna():
            for t in val.split(";"):
                topics.add(t.strip())
        return sorted(topics)
    all_topics = extract_main_topics(df["mainTopic"])
    selected_topics = st.sidebar.multiselect("Main Topic", options=all_topics)

    # Apply filters
    filtered_df = df.copy()
    if selected_years:
        filtered_df = filtered_df[filtered_df["year"].isin(selected_years)]
    if selected_papers:
        filtered_df = filtered_df[filtered_df["paper"].isin(selected_papers)]
    if selected_questions:
        filtered_df = filtered_df[filtered_df["question"].isin(selected_questions)]
    if selected_topics:
        filtered_df = filtered_df[
            filtered_df["mainTopic"].apply(lambda x: any(t in x for t in selected_topics))
        ]

    st.subheader(f"📄 Results ({len(filtered_df)} files)")

    # Display table
    if not filtered_df.empty:
        # Make filename clickable to PDF
        def make_pdf_link(row):
            url = f"{PDF_BASE_URL}{st.session_state.folder}/{row['year']}/{row['filename']}"
            return f'<a href="{url}" target="_blank">{row["filename"]}</a>'
        display_df = filtered_df.copy()
        display_df["filename"] = display_df.apply(make_pdf_link, axis=1)
        display_df["otherTopics"] = display_df["otherTopics"].apply(lambda x: ", ".join(x))
        
        st.write(
            display_df[["filename", "year", "paper", "question", "mainTopic", "otherTopics"]]
            .to_html(escape=False, index=False),
            unsafe_allow_html=True
        )

        # === GENERATE HTML REPORT ===
        @st.experimental_fragment
        def generate_html_report():
            if len(filtered_df) > 100:
                if not st.checkbox("⚠️ Large report (>100 files). Proceed anyway?"):
                    return
            html_content = f"""<!DOCTYPE html>
<html><head><title>Physics Report</title>
<style>
body {{ font-family: sans-serif; margin: 20px; background: #f4f4f4; }}
h1 {{ text-align: center; }}
.pdf-section {{ margin-bottom: 40px; background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
.header-row {{ font-size: 1.2em; margin-bottom: 10px; border-bottom: 1px solid #eee; padding-bottom: 5px; }}
embed {{ width: 100%; height: 800px; border: 1px solid #ccc; }}
</style></head><body><h1>Filtered PDF Report</h1>"""
            for _, row in filtered_df.iterrows():
                url = f"{PDF_BASE_URL}{st.session_state.folder}/{row['year']}/{row['filename']}"
                html_content += f"""
                <div class='pdf-section'>
                    <div class='header-row'>
                        <b>{row['filename']}</b> 
                        <span style='color:#666; font-size:0.9em;'>({row['mainTopic']})</span>
                    </div>
                    <embed src='{url}' type='application/pdf' />
                </div>"""
            html_content += "</body></html>"

            b64 = base64.b64encode(html_content.encode()).decode()
            href = f'<a href="data:text/html;base64,{b64}" download="physics_report.html">📥 Download HTML Report</a>'
            st.markdown(href, unsafe_allow_html=True)

        st.divider()
        generate_html_report()
    else:
        st.info("No entries match the current filters.")

if __name__ == "__main__":
    main()
