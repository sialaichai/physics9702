import streamlit as st
import pandas as pd
import json
import io
import requests
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import base64
import altair as alt # Optional: for simpler charts
import hashlib
import base64


# --- CONFIGURATION ---
# These filenames refer to the files you uploaded
PAYLOAD_FILE = '9702payload.enc'
UPDATES_FILE = 'updates.json' 
# Base URL for the GitHub Pages repository where your PDFs are hosted
BASE_PDF_URL = 'https://sialaichai.github.io/physics9702/' 

# Set Streamlit page config for an elegant, wide layout
st.set_page_config(
    page_title="9702 Physics Viewer",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- HELPER FUNCTIONS (REPLACING JAVASCRIPT LOGIC) ---

@st.cache_data
def fetch_and_load_data(password):
    """
    Fetches encrypted payload and updates file, then decrypts and normalizes data.
    NOTE: The decryption logic here is a placeholder. You must update the key
    and IV derivation to match how your original JavaScript/CryptoJS encrypts data.
    """
    st.info("Loading files and attempting decryption. This is a one-time process until the password changes.")
    
    try:
        # 1. Load Encrypted Payload (9702payload.enc)
        with open(PAYLOAD_FILE, 'r') as f:
            encrypted_data = f.read().strip()
        except FileNotFoundError:
            st.error(f"FATAL ERROR: Could not find data file '{PAYLOAD_FILE}'. Ensure it's in the same folder as app.py in your GitHub repo.")
            return None
        
    # 1. Decode the Base64 Encrypted Data
    try:
        decoded_data = base64.b64decode(encrypted_data)
    except Exception:
        raise ValueError("Encrypted payload is not valid Base64.")
    
    # 2. Check for the "Salted__" prefix (8 bytes)
    if decoded_data[:8] != b'Salted__':
        raise ValueError("Encrypted data does not have the expected 'Salted__' header. Check encryption method.")
    
    # 3. Extract Salt (8 bytes) and Ciphertext
    salt = decoded_data[8:16]
    ciphertext_with_iv = decoded_data[16:] # The rest is the ciphertext (since IV is part of the derivation)
    key_size = 32  # AES-256 (32 bytes)
    iv_size = 16   # AES-256 uses a 16-byte IV
    
    # 4. Derive Key and IV using MD5 (the EVP_BytesToKey equivalent)
    def derive_key_and_iv(password, salt, key_len, iv_len):
        d = b''
        last_hash = b''
        password = password.encode('utf-8')
        while len(d) < key_len + iv_len:
            last_hash = hashlib.md5(last_hash + password + salt).digest()
            d += last_hash
        return d[:key_len], d[key_len:key_len + iv_len]
    
    key, iv = derive_key_and_iv(password, salt, key_size, iv_size)
    
    # 5. Decrypt
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # The ciphertext for PyCryptodome is the part AFTER the Salt
        decrypted_padded = cipher.decrypt(ciphertext_with_iv)
        decrypted_bytes = unpad(decrypted_padded, AES.block_size)
        
        # 6. Parse JSON result
        decrypted_bundle = json.loads(decrypted_bytes.decode('utf-8'))
        
        # Check if the result is valid
        if 'data' not in decrypted_bundle or 'secure_folder' not in decrypted_bundle:
            raise ValueError("Decrypted content is missing 'data' or 'secure_folder' keys.")
            
        main_data = decrypted_bundle['data']
        pdf_folder = decrypted_bundle['secure_folder']
        st.session_state.pdf_folder = pdf_folder
        
    except ValueError as e:
        # This catches incorrect padding or bad JSON (usually means wrong password)
        raise ValueError(f"Decryption failed, likely due to incorrect password or bad data format: {e}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred during decryption or JSON parsing: {e}")
    
    # --- END OF REPLACEMENT DECRYPTION LOGIC ---

        # 3. Load and Merge Updates (updates.json)
     #   with open(UPDATES_FILE, 'r') as f:
    #        update_data = json.load(f)

    # 3. Load and Merge Updates (updates.json)
    try:
        with open(UPDATES_FILE, 'r') as f:
            update_data = json.load(f)
    except FileNotFoundError:
        st.warning(f"Warning: Could not find updates file '{UPDATES_FILE}'. Proceeding with main data only.")
        update_data = []
    except Exception as e:
        st.warning(f"Warning: Failed to load updates.json: {e}")
        update_data = []

    
        if update_data:
            main_data.extend(update_data)
        
        # 4. Normalize and Convert to DataFrame
        df = pd.DataFrame(main_data)
        df['question'] = df['question'].str.replace(r'(\.pdf$|^q0+)', r'\1', regex=True).str.strip()
        df['mainTopic'] = df['mainTopic'].str.strip()
        df['otherTopics'] = df['otherTopics'].apply(lambda x: ', '.join(x) if isinstance(x, list) else str(x))
        
        return df

    except ValueError as e:
        st.error(f"Login failed: {e}. Please check your password.")
        return None
    except Exception as e:
        st.error(f"System Error: Could not load or decrypt data files. {e}")
        return None

# --- STREAMLIT APP LAYOUT & LOGIC ---

def login_screen():
    """Displays the password input screen."""
    st.empty() # Clear the main area
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.title("🔐 9702 Physics Viewer")
        st.subheader("Restricted Access")
        
        password = st.text_input("Enter Password to Unlock Data", type="password")
        
        if st.button("Login"):
            if password:
                # Store password in session state, which will trigger data loading
                st.session_state.password = password
                st.session_state.data_loaded = False
                st.rerun()
            else:
                st.warning("Please enter a password.")

def display_main_app(df):
    """Displays the main application dashboard."""
    
    st.sidebar.title("Data Filters")

    # --- 1. SIDEBAR FILTERS (Elegant Display) ---
    
    # Extract unique filter options
    years = sorted(df['year'].unique(), reverse=True)
    papers = sorted(df['paper'].unique())
    topics = sorted(df['mainTopic'].str.split(',\s*').explode().unique().dropna())

    # Create Multiselect Widgets in the Sidebar
    selected_years = st.sidebar.multiselect("Select Year(s)", years)
    selected_papers = st.sidebar.multiselect("Select Paper(s)", papers)
    selected_topics = st.sidebar.multiselect("Select Main Topic(s)", topics)

    # Search Bar (Replaces Question Filter Dropdown)
    search_term = st.sidebar.text_input("Search Filename or Topic:", "").lower()
    
    # Apply Filters
    df_filtered = df.copy()
    
    if selected_years:
        df_filtered = df_filtered[df_filtered['year'].isin(selected_years)]
    if selected_papers:
        df_filtered = df_filtered[df_filtered['paper'].isin(selected_papers)]
    if selected_topics:
        # Filter where the 'mainTopic' column contains ANY of the selected topics
        df_filtered = df_filtered[df_filtered['mainTopic'].apply(
            lambda x: any(t in x.split(', ') for t in selected_topics)
        )]
    if search_term:
        df_filtered = df_filtered[
            df_filtered.apply(
                lambda row: search_term in row['filename'].lower() or 
                            search_term in row['mainTopic'].lower() or
                            search_term in row['otherTopics'].lower(), 
                axis=1
            )
        ]

    st.header(f"Data Dashboard ({len(df_filtered)} files selected)")
    
    # --- 2. CHARTS (New Feature for Data Insights) ---

    chart_tab, data_tab = st.tabs(["📊 Data Visualizations", "📄 Filtered Question List"])
    
    with chart_tab:
        
        # Use st.columns for elegant side-by-side display
        chart_col1, chart_col2 = st.columns(2)
        
        with chart_col1:
            st.subheader("Topic Frequency Analysis")
            # Explode the main topics and count them
            topic_counts = df_filtered['mainTopic'].str.split(',\s*').explode().value_counts().reset_index()
            topic_counts.columns = ['Topic', 'Count']
            
            # Plotly Bar Chart (Highly Interactive)
            fig_topic = px.bar(
                topic_counts.head(10), # Show top 10 topics
                x='Count', 
                y='Topic', 
                orientation='h', 
                title='Top 10 Most Frequent Topics in Selection',
                color_discrete_sequence=['#007bff']
            )
            fig_topic.update_yaxes(categoryorder='total ascending')
            st.plotly_chart(fig_topic, use_container_width=True)

        with chart_col2:
            st.subheader("File Distribution by Year")
            year_counts = df_filtered['year'].value_counts().sort_index().reset_index()
            year_counts.columns = ['Year', 'Count']
            
            # Altair Line Chart (Good for trends)
            chart_year = alt.Chart(year_counts).mark_line(point=True).encode(
                x=alt.X('Year:O', sort='descending'),
                y='Count:Q',
                tooltip=['Year', 'Count']
            ).properties(
                title="Number of Files per Year"
            )
            st.altair_chart(chart_year, use_container_width=True)

    # --- 3. DATA TABLE AND PDF VIEWER (Main Content) ---
    
    with data_tab:
        
        # Display the Filtered Data Table
        st.subheader("Click a Row to View PDF")
        
        # Streamlit's st.dataframe is a much more elegant, interactive table
        # than the custom HTML table (sortable, searchable)
        st.dataframe(
            df_filtered[['filename', 'year', 'paper', 'question', 'mainTopic', 'otherTopics']].rename(
                columns={'mainTopic': 'Main Topic', 'otherTopics': 'Other Topics'}
            ),
            use_container_width=True,
            height=300, # Control table height
            hide_index=True
        )
        
        # --- PDF Viewer ---
        
        # Get the selected row from the dataframe (by user click)
        # Note: Streamlit's DataFrame does not natively support single-click row selection
        # so we will use a workaround, or simplify to direct viewing.
        
        # For a simpler approach, we'll use a Selectbox for viewing
        selected_file = st.selectbox(
            "Select file to view PDF:", 
            options=df_filtered['filename'].unique(),
            index=None
        )

        if selected_file:
            row = df_filtered[df_filtered['filename'] == selected_file].iloc[0]
            year = row['year']
            
            # Construct the PDF URL based on the pattern in your JS code
            # e.g., https://sialaichai.github.io/physics9702/Q_Papers/w19/9702_w19_qp_11.pdf
            pdf_url = f"{BASE_PDF_URL}{st.session_state.pdf_folder}/{year}/{selected_file}"
            
            st.subheader(f"Viewing: {selected_file}")
            
            # Embed the PDF using an iframe via st.markdown
            st.markdown(
                f'<iframe src="{pdf_url}" width="100%" height="600" style="border: none;"></iframe>',
                unsafe_allow_html=True
            )
        else:
            st.info("Select a file from the list above to view its PDF.")
            
# --- MAIN APPLICATION ENTRY POINT ---

# Initialize session state variables
if 'password' not in st.session_state:
    st.session_state.password = None
if 'data_loaded' not in st.session_state:
    st.session_state.data_loaded = False
if 'pdf_folder' not in st.session_state:
    st.session_state.pdf_folder = None
    
# Import charting libraries after st.set_page_config
import plotly.express as px

if st.session_state.password:
    # Attempt to load and decrypt data
    if not st.session_state.data_loaded:
        df = fetch_and_load_data(st.session_state.password)
        if df is not None:
            st.session_state.df = df
            st.session_state.data_loaded = True
            st.rerun() # Rerun to switch from loading screen to main app
        else:
            # If decryption fails, clear password state to show login screen again
            st.session_state.password = None
            st.rerun()
    
    if st.session_state.data_loaded:
        display_main_app(st.session_state.df)

else:
    # No password entered, show login screen
    login_screen()

st.sidebar.markdown("---")
st.sidebar.markdown(f"[Prelim]({BASE_PDF_URL}physicsprelim/)")
st.sidebar.markdown(f"[SEAB]({BASE_PDF_URL}physicsseab/)")
