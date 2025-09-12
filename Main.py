import streamlit as st
import pandas as pd
import requests
import time
from io import BytesIO

# ---------------- Streamlit UI ----------------
st.set_page_config(page_title="IOC Validator Pro", layout="wide")

# Title and subtitle
st.markdown(
    """
    <h1 style='text-align: center; color: green;'>🔍 IOC Validation with VirusTotal</h1>
    <h3 style='text-align: center; color: black;'>(By Saurabh Kadasare 😎)</h3>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    "<p style='text-align:center; font-size:18px;'>Check file hashes against VirusTotal with Microsoft Detection Highlight ⚡</p>",
    unsafe_allow_html=True,
)
st.markdown("---")

# ---------------- API Key ----------------
API_KEY = "5ff1d3fe0662f3508a64efeb0226837bc7b22d4e4e9cd149c01e8a6b610095ec"
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
            if ms and ms.get("category") == "malicious":
                verdict = f"Detected ({ms.get('result')})"
            else:
                verdict = "Undetected"
            return {
                "Original Hash": original_hash,
                "SHA256 Hash": sha256,
                "VirusTotal Score": score,
                "Microsoft Detection": verdict
            }
        elif response.status_code == 404:
            return {k: "Not Found in VT" for k in 
                    ["Original Hash", "SHA256 Hash", "VirusTotal Score", "Microsoft Detection"]}
        elif response.status_code == 401:
            return {k: "Invalid API Key" for k in 
                    ["Original Hash", "SHA256 Hash", "VirusTotal Score", "Microsoft Detection"]}
        elif response.status_code == 429:
            return {k: "Rate Limited" for k in 
                    ["Original Hash", "SHA256 Hash", "VirusTotal Score", "Microsoft Detection"]}
        else:
            return {k: f"HTTP {response.status_code}" for k in 
                    ["Original Hash", "SHA256 Hash", "VirusTotal Score", "Microsoft Detection"]}
    except Exception as e:
        return {k: f"Error: {str(e)}" for k in 
                ["Original Hash", "SHA256 Hash", "VirusTotal Score", "Microsoft Detection"]}

# ---------------- Input Options ----------------
with st.expander("📂 Upload File (TXT/Excel)", expanded=True):
    uploaded_file = st.file_uploader("Upload your file here", type=["txt", "xlsx"])

with st.expander("⌨️ Enter Hashes Manually", expanded=True):
    manual_input = st.text_area(
        "Enter one hash per line",
        height=150,
        placeholder="Put your hashes here (one per line)..."
    )

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
    st.info(f"🔎 Processing {len(iocs)} hashes...")
    results = []
    progress_bar = st.progress(0)
    status_text = st.empty()
    scanner_text = st.empty()  # Animated scanner

    for i, ioc in enumerate(iocs):
        # Animated live scanner
        for dot in range(4):
            scanner_text.markdown(f"<p style='color:#00C9FF; font-weight:bold;'>Scanning IOC: {ioc} {'•'*dot}</p>", unsafe_allow_html=True)
            time.sleep(0.5)

        result = check_ioc(ioc)
        results.append(result)
        progress = int((i + 1) / len(iocs) * 100)
        progress_bar.progress(progress)
        status_text.text(f"Processed {i+1}/{len(iocs)} hashes")

        # Free-tier delay
        if i < len(iocs) - 1:
            time.sleep(10)

    progress_bar.empty()
    status_text.empty()
    scanner_text.empty()

    result_df = pd.DataFrame(results)

    # Conditional formatting
    def highlight_detection(val):
        if isinstance(val, str) and val.startswith("Detected"):
            return "background-color: red; color: white; font-weight:bold;"
        elif val == "Undetected":
            return "background-color: lightgreen; color: black; font-weight:bold;"
        return ""

    table_styles = [
        {"selector": "th", "props": [("text-align", "center"), ("font-size", "14px")]},
        {"selector": "td", "props": [("text-align", "center"), ("font-size", "13px")]}
    ]

    st.success("✅ Validation Complete!")
    st.dataframe(
        result_df.style.applymap(highlight_detection, subset=["Microsoft Detection"])
                      .set_table_styles(table_styles),
        use_container_width=True
    )

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
