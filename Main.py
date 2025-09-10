import streamlit as st
import pandas as pd
import requests
import hashlib
import time

# ---------------- Streamlit UI ----------------
st.set_page_config(page_title="IOC Validator Pro", layout="wide")
st.title("🔍 Advanced IOC Validator with VirusTotal")
st.markdown("Upload a **CSV file** containing hashes (MD5/SHA1/SHA256). "
            "The app will auto-convert MD5 → SHA256, query VirusTotal, and display results.")

uploaded_file = st.file_uploader("📂 Upload IOC CSV", type=["csv"])

# Get API key securely
API_KEY = st.secrets["VT_API_KEY"] if "VT_API_KEY" in st.secrets else "YOUR_VIRUSTOTAL_API_KEY"
headers = {"x-apikey": API_KEY}

# ---------------- Helper Functions ----------------
def convert_to_sha256(hash_value: str) -> str:
    """Convert MD5 to SHA256. If already SHA1/SHA256, just normalize."""
    hash_value = hash_value.strip().lower()
    if len(hash_value) == 32:  # MD5
        return hashlib.sha256(bytes.fromhex(hash_value)).hexdigest()
    elif len(hash_value) == 40:  # SHA1
        return hashlib.sha256(bytes.fromhex(hash_value)).hexdigest()
    elif len(hash_value) == 64:  # SHA256
        return hash_value
    else:
        return None  # Invalid format

def check_ioc(original_hash, sha256_hash):
    """Check IOC in VirusTotal and return results."""
    if not sha256_hash:
        return {
            "Original Hash": original_hash,
            "SHA256 Hash": "Invalid Hash",
            "Score": "Not Found in VirusTotal",
            "Microsoft": "Not Found in VirusTotal"
        }

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        if "data" in data:
            attr = data["data"]["attributes"]
            score = attr["last_analysis_stats"]["malicious"]
            ms = attr["last_analysis_results"].get("Microsoft", {})
            verdict = ms.get("category", "Undetected")
            return {
                "Original Hash": original_hash,
                "SHA256 Hash": sha256_hash,
                "Score": score,
                "Microsoft": verdict
            }
        else:
            return {
                "Original Hash": original_hash,
                "SHA256 Hash": sha256_hash,
                "Score": "Not Found in VirusTotal",
                "Microsoft": "Not Found in VirusTotal"
            }
    else:
        return {
            "Original Hash": original_hash,
            "SHA256 Hash": sha256_hash,
            "Score": "Not Found in VirusTotal",
            "Microsoft": "Not Found in VirusTotal"
        }

# ---------------- Main Logic ----------------
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    if df.shape[1] > 1:
        st.warning("⚠️ Only the first column will be used as IOC input.")

    iocs = df.iloc[:, 0].dropna().tolist()
    results = []

    progress_bar = st.progress(0)
    status_text = st.empty()

    for i, ioc in enumerate(iocs):
        sha256_hash = convert_to_sha256(ioc)
        result = check_ioc(ioc, sha256_hash)
        results.append(result)

        # update UI progress
        progress = int((i + 1) / len(iocs) * 100)
        progress_bar.progress(progress)
        status_text.text(f"Processing {i+1}/{len(iocs)} ...")

        # small delay (avoid API ban; real production can use retry/backoff logic)
        time.sleep(1)

    progress_bar.empty()
    status_text.empty()

    result_df = pd.DataFrame(results)

    st.success("✅ Validation Complete!")
    st.dataframe(result_df, use_container_width=True)

    csv = result_df.to_csv(index=False).encode("utf-8")
    st.download_button("💾 Download Results as CSV", csv, "ioc_results.csv", "text/csv")
