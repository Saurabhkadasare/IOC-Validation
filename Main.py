import streamlit as st
import pandas as pd
import requests
import time

# ---------------- Streamlit UI ----------------
st.set_page_config(page_title="IOC Validator Pro", layout="wide")
st.title("🔍 Advanced IOC Validator with VirusTotal")
st.markdown("Upload a **TXT file** containing hashes (MD5/SHA1/SHA256). "
            "The app will query VirusTotal and display results.")

uploaded_file = st.file_uploader("📂 Upload IOC TXT", type=["txt"])

# Get API key securely
API_KEY = st.secrets["VT_API_KEY"] if "VT_API_KEY" in st.secrets else "5ff1d3fe0662f3508a64efeb0226837bc7b22d4e4e9cd149c01e8a6b610095ec"
headers = {"x-apikey": API_KEY}

# ---------------- Helper Functions ----------------
def normalize_hash(hash_value: str) -> str:
    """Ensure the hash is in lowercase, valid length."""
    hv = hash_value.strip().lower()
    if len(hv) in [32, 40, 64]:  # MD5 / SHA1 / SHA256
        return hv
    else:
        return None

def check_ioc(original_hash, norm_hash):
    """Check IOC in VirusTotal and return results."""
    if not norm_hash:
        return {
            "Original Hash": original_hash,
            "SHA256 Hash": "Invalid Hash",
            "Score": "Not Found in VirusTotal",
            "Microsoft": "Not Found in VirusTotal"
        }

    url = f"https://www.virustotal.com/api/v3/files/{norm_hash}"
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
                "SHA256 Hash": attr.get("sha256", norm_hash),
                "Score": score,
                "Microsoft": verdict
            }
        else:
            return {
                "Original Hash": original_hash,
                "SHA256 Hash": norm_hash,
                "Score": "Not Found in VirusTotal",
                "Microsoft": "Not Found in VirusTotal"
            }
    else:
        return {
            "Original Hash": original_hash,
            "SHA256 Hash": norm_hash,
            "Score": "Not Found in VirusTotal",
            "Microsoft": "Not Found in VirusTotal"
        }

# ---------------- Main Logic ----------------
if uploaded_file:
    # Read TXT file → one hash per line
    content = uploaded_file.read().decode("utf-8").splitlines()
    iocs = [line.strip() for line in content if line.strip()]

    results = []

    progress_bar = st.progress(0)
    status_text = st.empty()

    for i, ioc in enumerate(iocs):
        norm_hash = normalize_hash(ioc)
        result = check_ioc(ioc, norm_hash)
        results.append(result)

        # update UI progress
        progress = int((i + 1) / len(iocs) * 100)
        progress_bar.progress(progress)
        status_text.text(f"Processing {i+1}/{len(iocs)} ...")

        time.sleep(1)  # avoid hitting API too fast

    progress_bar.empty()
    status_text.empty()

    result_df = pd.DataFrame(results)

    st.success("✅ Validation Complete!")
    st.dataframe(result_df, use_container_width=True)

    csv = result_df.to_csv(index=False).encode("utf-8")
    st.download_button("💾 Download Results as CSV", csv, "ioc_results.csv", "text/csv")
