import streamlit as st
import pandas as pd
import requests

# Streamlit UI
st.set_page_config(page_title="IOC Validator", layout="centered")
st.title("🔍 IOC Validator with VirusTotal")
st.write("Upload a CSV file with one column of IOCs (hashes, URLs, etc).")

uploaded_file = st.file_uploader("Upload IOC CSV", type=["csv"])

API_KEY = st.secrets["VT_API_KEY"] if "VT_API_KEY" in st.secrets else "YOUR_VIRUSTOTAL_API_KEY"
headers = {"x-apikey": API_KEY}

def check_ioc(ioc):
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if data.get("data"):
            attr = data["data"][0]["attributes"]
            score = attr["last_analysis_stats"]["malicious"]
            ms = attr["last_analysis_results"].get("Microsoft", {})
            verdict = ms.get("category", "Undetected")
            return score, verdict
        else:
            return "-", "Not Found"
    else:
        return "-", "Not Found"

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    if df.shape[1] > 1:
        st.warning("Only the first column will be used.")
    iocs = df.iloc[:, 0].dropna().tolist()

    results = []
    with st.spinner("Validating IOCs..."):
        for ioc in iocs:
            score, verdict = check_ioc(ioc)
            results.append({"IOC": ioc, "Score": score, "Microsoft": verdict})

    result_df = pd.DataFrame(results)
    st.success("✅ Validation Complete!")
    st.dataframe(result_df)

    csv = result_df.to_csv(index=False).encode("utf-8")
    st.download_button("Download Result CSV", csv, "ioc_results.csv", "text/csv")
