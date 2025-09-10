import streamlit as st
import pandas as pd
import requests
import time

# ---------------- Streamlit UI ----------------
st.set_page_config(page_title="IOC Validator Pro", layout="wide")
st.title("🔍 Advanced IOC Validator with VirusTotal")
st.markdown("""
Upload a **TXT file** containing hashes (MD5/SHA1/SHA256)  
**OR** paste hashes directly in the text area below.  
The app will query VirusTotal and display results.
""")

uploaded_file = st.file_uploader("📂 Upload IOC TXT", type=["txt"])

# Manual input
manual_input = st.text_area("✍️ Or paste hashes here (one per line):")

# ---------------- API Key ----------------
# 🔑 Replace with your VirusTotal API key
API_KEY = "5ff1d3fe0662f3508a64efeb0226837bc7b22d4e4e9cd149c01e8a6b610095ec"
headers = {"x-apikey": API_KEY}

# ---------------- Helper Function ----------------
def check_ioc(original_hash):
    """Check IOC in VirusTotal using search endpoint and return results."""
    url = f"https://www.virustotal.com/api/v3/search?query={original_hash}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        if data.get("data"):
            attr = data["data"][0]["attributes"]
            sha256 = attr.get("sha256", "Not Found in VirusTotal")
            score = attr["last_analysis_stats"]["malicious"]
            ms = attr["last_analysis_results"].get("Microsoft", {})
            verdict = ms.get("category", "Undetected")
            return {
                "Original Hash": original_hash,
                "SHA256 Hash": sha256,
                "Score": score,
                "Microsoft": verdict
            }
        else:
            return {
                "Original Hash": original_hash,
                "SHA256 Hash": "Not Found in VirusTotal",
                "Score": "Not Found in VirusTotal",
                "Microsoft": "Not Found in VirusTotal"
            }
    else:
        return {
            "Original Hash": original_hash,
            "SHA256 Hash": "Not Found in VirusTotal",
            "Score": "Not Found in VirusTotal",
            "Microsoft": "Not Found in VirusTotal"
        }

# ---------------- Main Logic ----------------
iocs = []

if uploaded_file:
    # Read TXT file → one hash per line
    content = uploaded_file.read().decode("utf-8").splitlines()
    iocs = [line.strip() for line in content if line.strip()]

elif manual_input.strip():
    # Read hashes from textarea
    iocs = [line.strip() for line in manual_input.splitlines() if line.strip()]

if iocs:
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

        time.sleep(1)  # avoid hitting API too fast on free tier

    progress_bar.empty()
    status_text.empty()

    result_df = pd.DataFrame(results)

    st.success("✅ Validation Complete!")
    st.dataframe(result_df, use_container_width=True)

    csv = result_df.to_csv(index=False).encode("utf-8")
    st.download_button("💾 Download Results as CSV", csv, "ioc_results.csv", "text/csv")
