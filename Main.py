import streamlit as st
import pandas as pd
import requests
import time
from io import BytesIO

# ---------------- Background & Styling ----------------
st.set_page_config(page_title="IOC Validator Pro", layout="wide")

# Professional cybersecurity/hacking background (no dark overlay)
st.markdown(
    """
    <style>
    .stApp {
        background-image: url("https://images.unsplash.com/photo-1581090700227-3a7c7bdb3d72?ixlib=rb-4.0.3&auto=format&fit=crop&w=1950&q=80");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        color: #ffffff;
    }
    .css-1v3fvcr { color: #ffffff; } /* headings */
    .stButton>button { background-color: #1f2937; color: #ffffff; } /* buttons */
    .stFileUploader>div { color: #ffffff; } /* file uploader text */
    .stTextArea>div { color: #ffffff; } /* textarea text */
    </style>
    """,
    unsafe_allow_html=True
)

st.title("🔍 IOC Validator with VirusTotal (By Saurabh Kadasare 😎)")
st.markdown(
    "Upload a TXT/Excel file or enter hashes manually. Free-tier limits are enforced automatically."
)

# ---------------- API Key ----------------
try:
    API_KEY = st.secrets["virustotal_api_key"]
except KeyError:
    API_KEY = "58d4205b4e34c92a90e825132af5d64b3c0d4b096c6ff8cf18cc1ad2534e6abb"  # replace with your key for testing

headers = {"x-apikey": API_KEY}

# ---------------- Helper Functions ----------------
def valid_hash(h):
    h = h.strip()
    return len(h) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in h)

def check_ioc(original_hash):
    url = f"https://www.virustotal.com/api/v3/files/{original_hash}"
    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            sha256 = data.get("sha256", "Not Found in VT")
            score = data.get("last_analysis_stats", {}).get("malicious", "Not Found in VT")
            ms = data.get("last_analysis_results", {}).get("Microsoft")
            verdict = f"Detected ({ms.get('result')})" if ms and ms.get("category") == "malicious" else "Undetected"
            return {"Original Hash": original_hash, "SHA256 Hash": sha256, "VirusTotal Score": score, "Microsoft Detection": verdict}
        elif response.status_code == 404:
            return {"Original Hash": original_hash, "SHA256 Hash": "Not Found in VT", "VirusTotal Score": "Not Found in VT", "Microsoft Detection": "Not Found in VT"}
        elif response.status_code == 401:
            return {"Original Hash": original_hash, "SHA256 Hash": "Invalid API Key", "VirusTotal Score": "Invalid API Key", "Microsoft Detection": "Invalid API Key"}
        elif response.status_code == 429:
            return {"Original Hash": original_hash, "SHA256 Hash": "Rate Limited", "VirusTotal Score": "Rate Limited", "Microsoft Detection": "Rate Limited"}
        else:
            return {"Original Hash": original_hash, "SHA256 Hash": f"HTTP {response.status_code}", "VirusTotal Score": f"HTTP {response.status_code}", "Microsoft Detection": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"Original Hash": original_hash, "SHA256 Hash": f"Error: {str(e)}", "VirusTotal Score": f"Error: {str(e)}", "Microsoft Detection": f"Error: {str(e)}"}

# ---------------- Input Options ----------------
st.subheader("📂 Upload File")
uploaded_file = st.file_uploader("Upload TXT or Excel file", type=["txt", "xlsx"])

st.subheader("⌨️ Or Enter Hashes Manually")
manual_input = st.text_area("Enter one hash per line")

# ---------------- Collect Hashes ----------------
iocs = []

if uploaded_file:
    if uploaded_file.name.endswith(".txt"):
        content = uploaded_file.read().decode("utf-8").splitlines()
        iocs.extend([line.strip() for line in content if valid_hash(line.strip())])
    elif uploaded_file.name.endswith(".xlsx"):
        df = pd.read_excel(uploaded_file)
        column = st.selectbox("Select the column containing hashes", df.columns)
        iocs.extend(df[column].dropna().astype(str).tolist())
        iocs = [h for h in iocs if valid_hash(h)]

if manual_input.strip():
    pasted_hashes = manual_input.splitlines()
    iocs.extend([h.strip() for h in pasted_hashes if valid_hash(h.strip())])

# ---------------- Main Logic ----------------
if iocs:
    st.info(f"🔎 Processing {len(iocs)} hashes (Free-tier delay enforced)...")
    results = []
    progress_bar = st.progress(0)
    status_text = st.empty()

    for i, ioc in enumerate(iocs):
        result = check_ioc(ioc)
        results.append(result)
        progress = int((i + 1) / len(iocs) * 100)
        progress_bar.progress(progress)
        status_text.text(f"Processing {i+1}/{len(iocs)} ...")
        if i < len(iocs) - 1:
            time.sleep(15)  # Free-tier VT delay

    progress_bar.empty()
    status_text.empty()

    result_df = pd.DataFrame(results)
    st.success("✅ Validation Complete!")
    st.dataframe(result_df, use_container_width=True)

    # ---------------- Download Options ----------------
    csv_data = result_df.to_csv(index=False).encode("utf-8")
    st.download_button("💾 Download as CSV", csv_data, "ioc_results.csv", "text/csv")

    excel_buffer = BytesIO()
    result_df.to_excel(excel_buffer, index=False, engine='openpyxl')
    st.download_button(
        "💾 Download as Excel",
        excel_buffer,
        "ioc_results.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
else:
    st.warning("⚠️ Please upload a file or enter valid hashes manually.")
