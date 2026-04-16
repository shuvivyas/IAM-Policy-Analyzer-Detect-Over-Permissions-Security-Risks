import streamlit as st
import requests

st.set_page_config(page_title="IAM Policy Analyzer", layout="wide")

st.title("🔐 IAM Policy Analyzer")
st.caption("Detect over-permissions and security risks in AWS IAM policies")

uploaded_file = st.file_uploader("Upload IAM Policy JSON", type=["json"])

if uploaded_file is not None:

    files = {"file": uploaded_file.getvalue()}

    # 🔄 Loading spinner
    with st.spinner("Analyzing IAM policy..."):
        try:
            response = requests.post(
                "http://127.0.0.1:8000/upload",
                files=files
            )
        except:
            st.error("❌ Backend not running or connection failed")
            st.stop()

    # ✅ Success case
    if response.status_code == 200:
        result = response.json()

        st.divider()

        # 🔥 Top dashboard (2 columns)
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Overall Risk")

            if result["overall_risk"] == "Critical":
                st.error("🔴 Critical")
            elif result["overall_risk"] == "High":
                st.warning("🟠 High")
            else:
                st.success("🟢 Low")

        with col2:
            st.subheader("Score")
            st.metric("Risk Score", result["total_score"])

        st.divider()

        # ✅ No issues case
        if not result["findings"]:
            st.markdown("### ✅ Secure Policy")
            st.success("No major security issues found")

        # 🔍 Findings section
        st.subheader("🔍 Findings")

        for f in result["findings"]:
            risk = f["risk"]

            if risk == "Critical":
                color = "#ff4b4b"
                icon = "🔴"
            elif risk == "High":
                color = "#ffa500"
                icon = "🟠"
            else:
                color = "#ffd700"
                icon = "🟡"

            st.markdown(f"""
            <div style="
                border-left: 6px solid {color};
                padding: 15px;
                margin-bottom: 15px;
                background-color: #111;
                border-radius: 10px;
            ">
                <h4>{icon} {f['issue']}</h4>
                <p><b>Risk:</b> {f['risk']}</p>
                <p><b>Fix:</b> {f['fix']}</p>
            </div>
            """, unsafe_allow_html=True)

    # ❌ API failed
    else:
        st.error("❌ API call failed. Check backend.")