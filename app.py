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
import plotly.express as px
import yaml
from yaml.loader import SafeLoader
import streamlit_authenticator as stauth

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
# === DECRYPTION ===
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
        
        for algo_name, hash_func in HASH_ALGOS.items():
            for key_size in KEY_SIZES:
                try:
                    key, iv = derive_key_and_iv(password, salt, key_size, IV_SIZE, hash_func)
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted_padded = cipher.decrypt(ciphertext)
                    decrypted_bytes = unpad(decrypted_padded, AES.block_size)
                    decrypted_bundle = json.loads(decrypted_bytes.decode('utf-8'))
                    
                    if 'data' not in decrypted_bundle:
                        raise ValueError("Decrypted JSON is incomplete.")
                        
                    st.success(f"Decryption successful! Using {algo_name}/AES-{key_size*8}.")
                    return decrypted_bundle
                    
                except ValueError as e:
                    last_error = f"{algo_name}/AES-{key_size*8} failed (Bad Key/IV/Padding): {str(e)}"
                    continue
                except Exception as e:
                    last_error = f"{algo_name}/AES-{key_size*8} system failure: {type(e).__name__} {str(e)}"
                    continue

        st.error(f"Login Failed. All KDF/AES combinations failed. Last attempt error: {last_error}")
        return None
        
    except Exception as e:
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

# ====================================================================
# === NEW DATA NORMALIZATION FUNCTION ===
# ====================================================================

@st.cache_data
def normalize_data(data_list):
    """Splits raw year ('m24') into year_numeric (2024) and session ('m')."""
    normalized = []
    for item in data_list:
        raw_year = str(item.get("year", "")).strip()
        
        # Logic to split 'm24', 's24', 'w24'
        match = re.match(r'([msw])(\d{2})', raw_year, re.IGNORECASE)
        if match:
            session_code = match.group(1).upper() # M, S, or W
            # Assuming current century (20xx)
            year_code = '20' + match.group(2) 
        else:
            # Handle standard numeric years or unparsed data
            session_code = 'OTHER' 
            year_code = raw_year
            
        try:
            year_numeric = int(year_code)
        except ValueError:
            year_numeric = None # Set to None if year conversion fails (will be ignored by filters/plots)

        q = str(item.get("question", "")).strip()
        q = re.sub(r'^q0+(\d)', r'q\1', re.sub(r'\.pdf$', '', q, flags=re.IGNORECASE), flags=re.IGNORECASE)
        
        normalized.append({
            "filename": str(item.get("filename", "")).strip(),
            "raw_year": raw_year, # Kept for reference
            "year_numeric": year_numeric, # NEW: Year (e.g., 2024)
            "session": session_code, # NEW: Session (e.g., 'M')
            "paper": str(item.get("paper", "")).strip(),
            "question": q,
            "mainTopic": str(item.get("mainTopic", "")).strip(),
            "otherTopics": [t.strip() for t in (item.get("otherTopics") or []) if t.strip()]
        })
    df = pd.DataFrame(normalized)
    # Ensure year_numeric is integer type where possible
    df['year_numeric'] = pd.to_numeric(df['year_numeric'], errors='coerce', downcast='integer')
    return df


# === ANALYTICS DISPLAY FUNCTION (Updated to use year_numeric and include Session chart) ===

def display_analytics(df: pd.DataFrame):
    st.header("📊 Question Analytics")
    st.info("These graphs reflect the data currently shown in the table (i.e., they respect the filters you set).")

    if df.empty:
        st.warning("No data to display in the charts based on current filters.")
        return

    # --- 1. Total Questions Per Year (Bar Chart) ---
    st.subheader("Total Questions by Year")
    
    # Use the new 'year_numeric' column
    year_counts = df['year_numeric'].value_counts().sort_index(ascending=False).reset_index()
    year_counts.columns = ['Year', 'Count']
    
    # Robustness Check 1: Drop invalid years
    year_counts = year_counts.dropna(subset=['Year'])
    
    if year_counts.empty:
        st.warning("No valid year data found to generate the Year Count chart.")
    else:
        fig_year = px.bar(
            year_counts,
            x='Year',
            y='Count',
            title='Total Questions by Year',
            labels={'Count': 'Number of Questions'},
            color='Year'
        )
        fig_year.update_layout(xaxis=dict(tickmode='linear', dtick=1))
        st.plotly_chart(fig_year, use_container_width=True)

    st.markdown("---")
    
    # --- 1b. Session Breakdown (New Chart) ---
    st.subheader("Distribution by Exam Session (M/S/W)")
    
    session_counts = df['session'].value_counts().reset_index()
    session_counts.columns = ['Session', 'Count']
    
    # Exclude the 'OTHER' category from the pie chart
    session_counts = session_counts[session_counts['Session'] != 'OTHER']
    
    if session_counts.empty:
        st.warning("No valid session data (M, S, W) found to generate the Session chart.")
    else:
        fig_session = px.pie(
            session_counts,
            values='Count',
            names='Session',
            title='Distribution by Exam Session',
        )
        st.plotly_chart(fig_session, use_container_width=False)
        
    st.markdown("---")

    # --- 2. Main Topic Trends Over Years (Up to 20 Line Charts) ---
    st.header("📈 Main Topic Trends Over Years")

    # 1. Explode topics and get the top 20 list based on current filters
    topic_list_exploded = df['mainTopic'].str.split(';').explode().str.strip().dropna()
    top_20_topics = topic_list_exploded.value_counts().nlargest(20).index.tolist()
    
    if not top_20_topics:
        st.info("No main topics found in the filtered data to show trends.")
    else:
        # 2. Create a long DataFrame for trending analysis
        # Use the already cleaned 'year_numeric' column
        topic_df = df[['year_numeric', 'mainTopic']].copy()
        topic_df = topic_df.rename(columns={'year_numeric': 'year'}) # Rename for generic plotting
        
        # Drop rows where year is None/NaN (which happens for invalid raw years)
        topic_df = topic_df.dropna(subset=['year']) 
        
        if topic_df.empty:
            st.warning("Valid year data is required for trend charts, but none was found.")
        else:
            topic_df['topic'] = topic_df['mainTopic'].str.split(';')
            topic_df_long = topic_df.explode('topic')
            topic_df_long['topic'] = topic_df_long['topic'].str.strip()
            topic_df_long = topic_df_long.dropna(subset=['topic'])

            trending_df = topic_df_long[topic_df_long['topic'].isin(top_20_topics)]
            
            # 3. Group by Year and Topic and count the frequency
            topic_year_counts = trending_df.groupby(['year', 'topic']).size().reset_index(name='Count')
            topic_year_counts = topic_year_counts.sort_values('year')

            # 4. Iterate and Chart for each topic in a 2-column layout
            st.subheader(f"Showing Trends for Top {len(top_20_topics)} Topics:")
            cols = st.columns(2)
            col_index = 0
            
            for topic in top_20_topics:
                topic_data = topic_year_counts[topic_year_counts['topic'] == topic]
                
                if topic_data.empty:
                    continue
                    
                with cols[col_index % 2]:
                    fig = px.line(
                        topic_data,
                        x='year',
                        y='Count',
                        title=f'{topic}',
                        markers=True,
                        labels={'year': 'Year', 'Count': 'Frequency'},
                    )
                    fig.update_layout(
                        xaxis=dict(tickmode='linear', dtick=1), 
                        yaxis=dict(rangemode='tozero')
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                col_index += 1
            
    st.markdown("---")

    # --- 3. Paper Type Distribution (Pie Chart) ---
    
    # 3a. Define the custom mapping function for P1, P2, P4
    def map_paper_to_group(paper_code):
        paper_code = str(paper_code) 
        
        P1_codes = ['1', '11', '12', '13', '14']
        P2_codes = ['2', '21', '22', '23', '24']
        P4_codes = ['4', '41', '42', '43', '44'] 
        
        if paper_code in P1_codes:
            return "P1 (MCQ/Core)"
        elif paper_code in P2_codes:
            return "P2 (Structured/Core)"
        elif paper_code in P4_codes:
            return "P4 (Advanced Theory)"
        return None 

    # 3b. Apply the mapping to create the new column
    df['Paper Group'] = df['paper'].apply(map_paper_to_group)
    
    paper_counts = df['Paper Group'].value_counts().reset_index()
    paper_counts.columns = ['Paper Group', 'Count']
    
    if paper_counts.empty:
        st.subheader("Distribution of Questions by Custom Paper Groups")
        st.warning("No P1, P2, or P4 data found under current filters.")
        return

    # Create the Pie Chart using the new grouping
    fig_paper = px.pie(
        paper_counts,
        values='Count',
        names='Paper Group', 
        title='Distribution of Questions by Custom Paper Groups',
    )
    st.plotly_chart(fig_paper, use_container_width=False)


def main():
    st.set_page_config(page_title="9702 Physics Viewer", layout="wide")
    st.title("🔐 9702 Physics Past Paper Viewer")

    encrypted_text = load_encrypted_data()
    if not encrypted_text:
        return

    # --- 1. Authenticator Setup ---
    # Load configuration
    with open('./config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    # Initialize Authenticator
    authenticator = stauth.Authenticate(
        config['credentials'],
        config['cookie']['name'],
        config['cookie']['key'],
        config['cookie']['expiry_days'],
        config['preauthorized']
    )

    # --- 2. Render Login/Handle Status ---
    # The name of the user, the authentication status (True/False/None), and the username
    name, authentication_status, username = authenticator.login(
        form_name='Login', 
        location='main'
    )
    # Status check and core logic starts here
    if st.session_state["authentication_status"]:
        # User is logged in
        
        # --- 2a. Decrypt Data (Use the same logic as before, but ensure it's triggered once) ---
        if st.session_state.data is None:
            # For simplicity, we assume your decryption password is hardcoded 
            # if you are using the same key for everyone.
            # If the user's login password IS the decryption key, you need to save it during login.
            DECRYPTION_PASSWORD = "Your_Hardcoded_Decryption_Password_Here" # <-- CHANGE THIS

            bundle = decrypt_payload(DECRYPTION_PASSWORD, encrypted_text)
            if bundle:
                st.session_state.folder = bundle.get("secure_folder", "")
                main_data = bundle.get("data", [])
                updates = load_updates()
                if updates:
                    main_data.extend(updates)
                st.session_state.data = normalize_data(main_data)
            else:
                # If decryption fails for any reason, log the user out
                st.session_state["authentication_status"] = None
                st.error("Decryption failed after successful login. Data is unavailable.")
                st.rerun()
        # --- 2b. Display App Header and Logout Button ---
        st.sidebar.title(f'Welcome {name}')
        authenticator.logout('Logout', 'sidebar')
       
        st.header("🔍 Filter Questions")
            
        # === MAIN INTERFACE ===
        df = st.session_state.data
        if df is None or df.empty:
            st.warning("No data loaded.")
            #if st.button("Logout"):
            st.session_state.authenticated = False
            st.rerun()
            return
    
        # --- 1. FILTERS (Custom Width Columns) ---
        st.header("🔍 Filter Questions")
        
        # Define custom column widths: [Year, Session, Paper, Question, Main Topic]
        col_yr, col_sess, col2, col_q, col3 = st.columns([1, 1, 1, 1, 3.4])
        
        # 1a. Year Filter (NEW)
        with col_yr:
            # Use the new year_numeric column for filtering
            all_years = sorted(df["year_numeric"].dropna().unique(), reverse=True)
            # Convert to int for display (as pandas returns float for unique values if NaN is present)
            all_years_display = [int(y) for y in all_years]
            selected_years = st.multiselect("Year", options=all_years_display, key="filter_year")
    
        # 1b. Session Filter (NEW)
        with col_sess:
            # Use the new session column for filtering
            all_sessions = sorted(df["session"].dropna().unique())
            all_sessions = [s for s in all_sessions if s in ['M', 'S', 'W']] # Only show M, S, W options
            selected_sessions = st.multiselect("Session", options=all_sessions, key="filter_session")
            
        # 2. Paper Filter (Small)
        with col2:
            all_papers = sorted(df["paper"].dropna().unique())
            selected_papers = st.multiselect("Paper", options=all_papers, key="filter_paper")
            
        # 3. Question Number Filter (Medium-Small)
        with col_q:
            all_questions = sorted(df["question"].dropna().unique(), key=lambda x: [int(c) if c.isdigit() else c for c in x.split()])
            selected_questions = st.multiselect("Q#", options=all_questions, key="filter_question")
            
        # 4. Main Topic Filter (Widest)
        with col3:
            def extract_main_topics(series):
                topics = set()
                for val in series.dropna():
                    for t in val.split(";"):
                        topics.add(t.strip())
                return sorted(topics)
            
            all_topics = extract_main_topics(df["mainTopic"])
            selected_topics = st.multiselect("Main Topic", options=all_topics, key="filter_topic")
    
        st.markdown("---") 
    
        # --- 2. APPLY FILTERS ---
        filtered_df = df.copy()
        
        # Apply filters based on the selections made above
        if selected_years:
            # Filter based on the new 'year_numeric' column
            filtered_df = filtered_df[filtered_df["year_numeric"].isin(selected_years)]
        if selected_sessions:
            # Filter based on the new 'session' column
            filtered_df = filtered_df[filtered_df["session"].isin(selected_sessions)]
        if selected_papers:
            filtered_df = filtered_df[filtered_df["paper"].isin(selected_papers)]
        if selected_questions:
            filtered_df = filtered_df[filtered_df["question"].isin(selected_questions)]
        if selected_topics:
            filtered_df = filtered_df[
                filtered_df["mainTopic"].apply(lambda x: any(t in x.split(';') for t in selected_topics))
            ]
    
        # === 3. TAB CREATION AND CONTENT ===
        tab1, tab2 = st.tabs(["📄 Data Table", "📊 Analytics"])
    
        with tab1:
            # --- Download Button expander remains the same ---
            with st.expander(f"📥 Generate & Download Report ({len(filtered_df)} files match filters)", expanded=False):
                
                def generate_html_report_content(filtered_df, folder):
                    # ... (Content generation logic remains here) ...
                    if len(filtered_df) > 100:
                        if not st.checkbox("⚠️ Large report (>100 files). Proceed anyway?", key="report_check"):
                            return None
                    
                    # ... (rest of HTML generation) ...
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
                        url = f"{PDF_BASE_URL}{folder}/{row['raw_year']}/{row['filename']}" # USE RAW_YEAR FOR FOLDER PATH
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
    
                html_result = generate_html_report_content(filtered_df, st.session_state.folder)
                
                if html_result and not html_result.startswith('<!'): # Simple check to skip if checkbox was hit but content wasn't generated
                    pass 
                elif html_result:
                    b64 = base64.b64encode(html_result.encode()).decode()
                    href = f'<a href="data:text/html;base64,{b64}" download="physics_report.html">📥 Download HTML Report ({len(filtered_df)} files)</a>'
                    st.markdown(href, unsafe_allow_html=True)
            
            st.markdown("---")
    
            # --- 4. DISPLAY PAGINATED RESULTS TABLE ---
            st.subheader(f"📄 Results Table ({len(filtered_df)} files)")
            
            TOTAL_ROWS = len(filtered_df)
            ROWS_PER_PAGE = 50
            
            if TOTAL_ROWS == 0:
                st.info("No entries match the current filters.")
                # Use return instead of break here
                return 
            
            total_pages = (TOTAL_ROWS + ROWS_PER_PAGE - 1) // ROWS_PER_PAGE
            
            if st.session_state.page_number > total_pages:
                st.session_state.page_number = 1
                
            st.markdown(f"**Viewing Page {st.session_state.page_number} of {total_pages}**")
    
            nav_col1, nav_col2, nav_col3 = st.columns([1, 1, 1])
            
            with nav_col1:
                if st.button("⬅️ Previous", key="prev_page", 
                             disabled=(st.session_state.page_number == 1)):
                    st.session_state.page_number -= 1
                    st.rerun()
                    
            with nav_col2:
                if st.button("Next ➡️", key="next_page", 
                             disabled=(st.session_state.page_number == total_pages)):
                    st.session_state.page_number += 1
                    st.rerun()
    
            st.markdown("---")
            
            start_row = (st.session_state.page_number - 1) * ROWS_PER_PAGE
            end_row = start_row + ROWS_PER_PAGE
            
            paginated_df = filtered_df.iloc[start_row:end_row]
    
            if not paginated_df.empty:
                def make_pdf_link(row):
                    # Use raw_year for the link generation, as the folder structure likely uses it
                    url = f"{PDF_BASE_URL}{st.session_state.folder}/{row['raw_year']}/{row['filename']}" 
                    return f'<a href="{url}" target="_blank">{row["filename"]}</a>'
                
                display_df = paginated_df.copy()
                display_df["Link"] = display_df.apply(make_pdf_link, axis=1)
                display_df["otherTopics"] = display_df["otherTopics"].apply(lambda x: ", ".join(x))
                
                # 💥 UPDATED DISPLAY COLUMNS
                display_cols = ["Link", "year_numeric", "session", "paper", "question", "mainTopic", "otherTopics"]
                display_df = display_df[display_cols].rename(columns={
                    "year_numeric": "Year", # Uses the numeric year
                    "session": "Session", # NEW Session column
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
                st.info("No entries match the current filters.") # This will be hit only if paginated_df is empty when filtered_df is not (unlikely with fixed logic)
    
        with tab2:
            # --- Analytics View ---
            display_analytics(filtered_df) 
    

    elif st.session_state["authentication_status"] == False:
        st.error('Username/password is incorrect')
        st.session_state.data = None
    
    elif st.session_state["authentication_status"] == None:
        st.warning('Please enter your credentials to access the data.')
        st.session_state.data = None

if __name__ == "__main__":
    main()
