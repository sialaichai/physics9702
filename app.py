import streamlit as st
import pandas as pd
import base64
import json
#from Cryptodome.Cipher import AES # <-- FIXED: Changed from 'Crypto' to 'Cryptodome'
from Crypto.Cipher import AES
from Cryptodome.Util.Padding import unpad # <-- FIXED: Changed from 'Crypto' to 'Cryptodome'
import io
import os
import re
import hashlib
import plotly.express as px # <-- NEW: Import Plotly for graphing

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

# === ANALYTICS DISPLAY FUNCTION (NEW) ===
def display_analytics(df: pd.DataFrame):
    st.header("📊 Question Analytics")
    st.info("These graphs reflect the data currently shown in the table (i.e., they respect the filters you set).")

    if df.empty:
        st.warning("No data to display in the charts based on current filters.")
        return

    # --- 1. Total Questions Per Year (Bar Chart) ---
    year_counts = df['year'].value_counts().sort_index(ascending=False).reset_index()
    year_counts.columns = ['Year', 'Count']
    fig_year = px.bar(
        year_counts,
        x='Year',
        y='Count',
        title='Total Questions by Year',
        labels={'Count': 'Number of Questions'},
        color='Year'
    )
    st.plotly_chart(fig_year, use_container_width=True)

    st.markdown("---")

    # --- 2. Top Main Topics (Horizontal Bar Chart) ---
    topic_list = df['mainTopic'].str.split(';').explode().str.strip()
    topic_counts = topic_list.value_counts().nlargest(10).reset_index()
    topic_counts.columns = ['Main Topic', 'Count']
    
    fig_topic = px.bar(
        topic_counts.sort_values('Count', ascending=True),
        x='Count',
        y='Main Topic',
        orientation='h',
        title='Top 10 Main Topics by Question Count',
        labels={'Count': 'Number of Questions'},
        color='Main Topic'
    )
    st.plotly_chart(fig_topic, use_container_width=True)

    st.markdown("---")

    # --- 3. Paper Type Distribution (Pie Chart) ---
    df['Paper Type'] = df['paper'].str[0].apply(
        lambda x: f"P{x} ({'MCQ' if x=='1' else 'Structured' if x=='2' else 'Practical/Adv'})"
    )
    paper_counts = df['Paper Type'].value_counts().reset_index()
    paper_counts.columns = ['Paper Type', 'Count']
    
    fig_paper = px.pie(
        paper_counts,
        values='Count',
        names='Paper Type',
        title='Distribution of Questions by Paper Type',
    )
    st.plotly_chart(fig_paper, use_container_width=False)


# === MAIN APP ===
def main():
    st.set_page_config(page_title="9702 Physics Viewer", layout="wide")
    st.title("🔐 9702 Physics Past Paper Viewer")

    # Load encrypted payload once
    encrypted_text = load_encrypted_data()
    if not encrypted_text:
        return

    # Session state initialization remains the same
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.data = None
        st.session_state.folder = ""

    # === LOGIN SCREEN ===
    if not st.session_state.authenticated:
        # Login logic remains the same (omitted here for brevity)
        with st.form("login"):
            password = st.text_input("Enter password", type="password")
            submitted = st.form_submit_button("Unlock")
            if submitted and password:
                bundle = decrypt_payload(password, encrypted_text)
                if bundle:
                    st.session_state.authenticated = True
                    st.session_state.folder = bundle.get("secure_folder", "")
                    main_data = bundle.get("data", [])
                    updates = load_updates()
                    if updates:
                        main_data.extend(updates)
                    
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
                    st.rerun()
                else:
                    st.error("Incorrect password (or decryption failed, see error above).")
        return

    # === MAIN INTERFACE ===
    df = st.session_state.data
    if df is None or df.empty:
        st.warning("No data loaded.")
        if st.button("Logout"):
            st.session_state.authenticated = False
            st.rerun()
        return

    # --- 1. FILTERS (Custom Width Columns) ---
    st.header("🔍 Filter Questions")
    
    # Define custom column widths: [Year, Paper, Question, Main Topic]
    # Ratio: [1, 1, 1.5, 3.5] (Total units = 7)
    col1, col2, col_q, col3 = st.columns([1, 1, 1.5, 3.5])
    
    # 1. Year Filter (Small)
    with col1:
        all_years = sorted(df["year"].dropna().unique(), reverse=True)
        selected_years = st.multiselect("Year", options=all_years, key="filter_year")
    
    # 2. Paper Filter (Small)
    with col2:
        all_papers = sorted(df["paper"].dropna().unique())
        selected_papers = st.multiselect("Paper", options=all_papers, key="filter_paper")
        
    # 3. Question Number Filter (Medium-Small)
    with col_q:
        all_questions = sorted(df["question"].dropna().unique(), key=lambda x: [int(c) if c.isdigit() else c for c in x.split()])
        # Moved the multiselect definition here
        selected_questions = st.multiselect("Q#", options=all_questions, key="filter_question")
        
    # 4. Main Topic Filter (Widest)
    with col3:
        # NOTE: The extract_main_topics function needs to be defined within main() scope
        def extract_main_topics(series):
            topics = set()
            for val in series.dropna():
                for t in val.split(";"):
                    topics.add(t.strip())
            return sorted(topics)
        
        all_topics = extract_main_topics(df["mainTopic"])
        selected_topics = st.multiselect("Main Topic", options=all_topics, key="filter_topic")

    st.markdown("---") # Visual separator

    # --- 2. APPLY FILTERS ---
    filtered_df = df.copy()
    
    # Apply filters based on the selections made above
    if selected_years:
        filtered_df = filtered_df[filtered_df["year"].isin(selected_years)]
    if selected_papers:
        filtered_df = filtered_df[filtered_df["paper"].isin(selected_papers)]
    if selected_questions:
        filtered_df = filtered_df[filtered_df["question"].isin(selected_questions)]
    if selected_topics:
        filtered_df = filtered_df[
            filtered_df["mainTopic"].apply(lambda x: any(t in x.split(';') for t in selected_topics))
        ]
    # --- 3. DOWNLOAD BUTTON (Moved to the Top) ---
    
    # Place download link in an expander for better organization above the results
    with st.expander(f"📥 Generate & Download Report ({len(filtered_df)} files match filters)", expanded=False):
        
        # Define the content generation function inline
        def generate_html_report_content(filtered_df, folder):
            
            if len(filtered_df) > 100:
                # Use a unique key for the checkbox
                if not st.checkbox("⚠️ Large report (>100 files). Proceed anyway?", key="report_check"):
                    return None
            
            # --- HTML GENERATION LOGIC ---
            html_content = f"""<!DOCTYPE html>
<html><head><title>Physics Report</title>
<style>
/* ... (CSS styles remain the same) ... */
body {{ font-family: sans-serif; margin: 20px; background: #f4f4f4; }}
h1 {{ text-align: center; }}
.pdf-section {{ margin-bottom: 40px; background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
.header-row {{ font-size: 1.2em; margin-bottom: 10px; border-bottom: 1px solid #eee; padding-bottom: 5px; }}
embed {{ width: 100%; height: 800px; border: 1px solid #ccc; }}
</style></head><body><h1>Filtered PDF Report</h1>"""
            
            for _, row in filtered_df.iterrows():
                url = f"{PDF_BASE_URL}{folder}/{row['year']}/{row['filename']}"
                html_content += f"""
                <div class='pdf-section'>
                    <div class='header-row'>
                        <b>{row['filename']}</b> 
                        <span style='color:#666; font-size:0.9em;'>({row['mainTopic']})</span>
                    </div>
                    <embed src='{url}' type='application/pdf' />
                </div>"""
            
            html_content += "</body></html>"
            return html_content

        # Call the function and generate the download link
        html_result = generate_html_report_content(filtered_df, st.session_state.folder)
        
        if html_result:
            b64 = base64.b64encode(html_result.encode()).decode()
            href = f'<a href="data:text/html;base64,{b64}" download="physics_report.html">📥 Download HTML Report ({len(filtered_df)} files)</a>'
            st.markdown(href, unsafe_allow_html=True)
            
    st.markdown("---") # Visual separator before the table

    # --- 4. DISPLAY RESULTS TABLE ---
    st.subheader(f"📄 Results Table ({len(filtered_df)} files)")

    if not filtered_df.empty:
        # Make filename clickable to PDF
        def make_pdf_link(row):
            url = f"{PDF_BASE_URL}{st.session_state.folder}/{row['year']}/{row['filename']}"
            return f'<a href="{url}" target="_blank">{row["filename"]}</a>'
        
        display_df = filtered_df.copy()
        display_df["Link"] = display_df.apply(make_pdf_link, axis=1)
        display_df["otherTopics"] = display_df["otherTopics"].apply(lambda x: ", ".join(x))
        
        # Select and rename columns for display
        display_cols = ["Link", "year", "paper", "question", "mainTopic", "otherTopics"]
        display_df = display_df[display_cols].rename(columns={
            "year": "Year", 
            "paper": "Paper", 
            "question": "Q#", 
            "mainTopic": "Main Topic", 
            "otherTopics": "Other Topics",
            "Link": "Filename"
        })
        
        st.write(
            display_df
            .to_html(escape=False, index=False),
            unsafe_allow_html=True
        )

    else:
        st.info("No entries match the current filters.")
        
    # --- 5. CALL ANALYTICS FUNCTION (NEW) ---
    st.markdown("---")
    display_analytics(filtered_df) # <-- NEW CALL TO THE ANALYTICS FUNCTION

if __name__ == "__main__":
    main()
