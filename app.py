import streamlit as st
import pandas as pd
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import io
import os
import re
import hashlib

# === CONFIG ===
PAYLOAD_PATH = "9702payload.enc"  # originally .enc
UPDATES_PATH = "updates.json"
PDF_BASE_URL = "https://sialaichai.github.io/physics9702/"

# ====================================================================
# === KEY DERIVATION FUNCTION (MIMICS OpenSSL/CryptoJS) ===
# ====================================================================

def derive_key_and_iv(password, salt, key_len, iv_len, hash_algo=hashlib.md5):
    """
    Derives AES Key and IV from password and salt using the specified hash function.
    hash_algo can be hashlib.md5 or hashlib.sha256.
    """
    d = b''
    last_hash = b''
    password = password.encode('utf-8')
    while len(d) < key_len + iv_len:
        last_hash = hash_algo(last_hash + password + salt).digest()
        d += last_hash
    return d[:key_len], d[key_len:key_len + iv_len]

# ====================================================================
# === DECRYPTION (CORRECTED WITH KDF AND KEY SIZE TESTING) ===
# ====================================================================

@st.cache_data
def decrypt_payload(password: str, encrypted_b64: str) -> dict | None:
    # Key sizes to test: AES-128 (16), AES-192 (24), AES-256 (32)
    KEY_SIZES = [16, 24, 32]
    IV_SIZE = 16
    HASH_ALGOS = {"MD5": hashlib.md5, "SHA256": hashlib.sha256}
    
    try:
        decoded_data = base64.b64decode(encrypted_b64)
    
        if decoded_data[:8] != b'Salted__':
            st.error("Decryption failed: Data format error - missing 'Salted__' header.")
            return None
    
        salt = decoded_data[8:16]
        ciphertext = decoded_data[16:]
        
        last_error = None
        
        # 3. Iterate through possible hash algorithms and key sizes
        for algo_name, hash_func in HASH_ALGOS.items():
            for key_size in KEY_SIZES:
                try:
                    # Derive Key and IV using the current hash function
                    key, iv = derive_key_and_iv(password, salt, key_size, IV_SIZE, hash_func)
                
                    # Decrypt using CBC mode
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted_padded = cipher.decrypt(ciphertext)
                    
                    # Unpad and decode JSON (raises ValueError on wrong key/IV)
                    decrypted_bytes = unpad(decrypted_padded, AES.block_size)
                    
                    # Success! Parse JSON result
                    decrypted_bundle = json.loads(decrypted_bytes.decode('utf-8'))
                    
                    if 'data' not in decrypted_bundle:
                        raise ValueError("Decrypted JSON is incomplete.")
                        
                    st.success(f"Decryption successful! Using {algo_name}/AES-{key_size*8}.")
                    return decrypted_bundle
                    
                except ValueError as e:
                    # Catches bad padding/wrong key/IV (ValueError from unpad) or bad JSON
                    last_error = f"{algo_name}/AES-{key_size*8} failed (Bad Key/IV/Padding): {str(e)}"
                    continue # Try next combination
                except Exception as e:
                    # Catch any other system errors (e.g., unexpected encoding)
                    last_error = f"{algo_name}/AES-{key_size*8} system failure: {type(e).__name__} {str(e)}"
                    continue

        # If the entire loop finishes without success
        st.error(f"Login Failed. All KDF/AES combinations failed. Last attempt error: {last_error}")
        return None
        
    except Exception as e:
        # Catch errors outside the loop (e.g., Base64 decoding failure)
        st.error(f"A fatal error occurred during initialization: {type(e).__name__}: {str(e)}")
        return None
# === LOAD ENCRYPTED DATA ===
@st.cache_data
def load_encrypted_data():
    if not os.path.exists(PAYLOAD_PATH):
        st.error("❌ 9702payload.enc not found!")
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
