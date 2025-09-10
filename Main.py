import streamlit as st
import pandas as pd
import requests
import time

# ---------------- Streamlit UI ----------------
st.set_page_config(page_title="IOC Validator Pro", layout="wide")
st.title("🔍 Advanced IOC Validator with VirusTotal")
st.markdown(
    "Provide IOCs (MD5/SHA1/SHA256) either by **uploading a file** "
    "or by **pasting hashes directly**."
)

# ---------------- API Key ----------------
# Option 1: Use Streamlit secrets (recommended)
try:
    API_KEY = st.secrets["virustotal_api_key"]
except KeyError:
    # Option 2: fallback to hardcoded key (for testing only)
    API_KEY = "5ff1d3fe0662f3508a64efeb0226837bc7b22d4e4e9cd149c01e8a6b610095ec"

headers = {"x-apikey": API_KEY}

# ---------------- Helper Functions ----------------
def valid_hash(h):
    """Validate if the input string is MD5, SHA1, or SHA256."""
    h = h.strip()
    return (
        len(h) in [32, 40, 64]
        and all(c in "0123456789abcdefABCDEF" for c in h)
    )

def check_ioc(original_hash):
    """Check IOC in VirusTotal using the file endpoint with robust error handling."""
    url = f"https://www.virustotal.com/api/v3/files/{original_hash}"
    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})

            sha256 = data.get("sha256", "Not Found in VirusTotal")
            score = data.get("last_analysis_stats", {}).get("malicious", "Not Found in VirusTotal")

            ms = data.get("last_analysis_results", {}).get("Microsoft")
            if ms:
                verdict = ms.get("result") if ms.get("category") == "malicious" else "Undetected"
            else:
                verdict = "Undetected"

            return {
                "Original Hash": original_hash,
                "SHA256 Hash": sha256,
                "Malicious Score": score,
                "Microsoft Detection Status": verdict
            }

        elif response.status_code == 404:
            return {
                "Original Hash": original_hash,
                "SHA256 Hash": "Not Found in VirusTotal",
                "Malicious Score": "Not Found in VirusTotal",
                "Microsoft Detection Status": "Not Found in VirusTotal"
            }
        elif response.status_code == 401:
            return {
                "Original Hash": original_hash,
                "SHA256 Hash": "Invalid API Key",
                "Malicious Score": "Invalid API Key",
                "Microsoft Detection Status": "Invalid API Key"
            }
        elif response.status_code == 429:
            return {
                "Original Hash": original_hash,
                "SHA256 Hash": "Rate Limited",
                "Malicious Score": "Rate Limited",
                "Microsoft Detection Status": "Rate Limited"
            }
        else:
            return {
                "Original Hash": original_hash,
                "SHA256 Hash": f"HTTP {response.status_code}",
                "Malicious Score": f"HTTP {response.status_code}",
                "Microsoft Detection Status": f"HTTP {response.status_code}"
            }

    except Exception as e:
        return {
            "Original Hash": original_hash,
            "SHA256 Hash": f"Error: {str(e)}",
            "Malicious Score": f"Error: {str(e)}",
            "Microsoft Detection Status": f"Error: {str(e)}"
        }

# ---------------- Input Options ----------------
st.subheader("📂 Upload File (TXT or Excel)")
uploaded_file = st.file_uploader("Upload TXT or Excel file", type=["txt", "xlsx"])

st.subheader("⌨️ Or Paste Hashes Manually")
manual_input = st.text_area("Enter one hash per line")

# Collect IOCs
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
    st.info(f"🔎 Processing {len(iocs)} IOCs...")

    results = []
    progress_bar = st.progress(0)
    status_text = st.empty()

    for i, ioc in enumerate(iocs):
        result = check_ioc(ioc)
        results.append(result)

        # update UI progress
        progress = int((i + 1) / len(iocs) * 100)
        progress_bar.progress(progress)
        status_text.text(f"Processing {i+1}/{len(iocs)} ...")

        time.sleep(1)  # avoid hitting API too fast (free tier)

    progress_bar.empty()
    status_text.empty()

    result_df = pd.DataFrame(results)

    st.success("✅ Validation Complete!")

    # Conditional formatting for Microsoft Detection
    def highlight_malicious(val):
        color = "red" if val not in ["Undetected", "Not Found in VirusTotal"] else "green"
        return f"background-color: {color}"

    st.dataframe(result_df.style.applymap(highlight_malicious, subset=["Microsoft Detection Status"]), use_container_width=True)

    csv = result_df.to_csv(index=False).encode("utf-8")
    st.download_button("💾 Download Results as CSV", csv, "ioc_results.csv", "text/csv")
else:
    st.warning("⚠️ Please upload a file or paste valid hashes above to begin.")
