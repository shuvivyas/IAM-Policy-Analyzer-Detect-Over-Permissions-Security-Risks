import streamlit as st
import requests
import json

st.set_page_config(page_title="IAM Policy Analyzer", layout="wide")

st.title("🔐 IAM Policy Analyzer")
st.caption("Detect over-permissions and security risks in AWS IAM policies")

uploaded_file = st.file_uploader("Upload IAM Policy JSON", type=["json"])

if uploaded_file is not None:

    files = {"file": uploaded_file.getvalue()}

    with st.spinner("Analyzing IAM policy..."):
        try:
            response = requests.post(
                "https://iam-policy-analyzer-detect-over.onrender.com/upload",
                files=files
            )
        except:
            st.error("❌ Backend connection failed")
            st.stop()

    if response.status_code == 200:
        result = response.json()

        st.divider()

        # 🔥 Dashboard
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

        # 🧠 Policy Type
        st.subheader("Policy Type")
        st.info(result.get("policy_type", "Unknown"))

        st.divider()

        # ✅ Secure case
        if not result.get("findings"):
            st.markdown("### ✅ Secure Policy")
            st.success("No major security issues found")

        # 🔍 Findings
        st.subheader("🔍 Findings")

        for f in result.get("findings", []):
            risk = f.get("risk", "Low")

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
                <h4>{icon} {f.get('issue')}</h4>
                <p><b>Risk:</b> {f.get('risk')}</p>
                <p><b>Attack:</b> {f.get('attack', 'N/A')}</p>
                <p><b>Fix:</b> {f.get('fix')}</p>
            </div>
            """, unsafe_allow_html=True)

        # 📄 Download Report
        st.divider()
        report = json.dumps(result, indent=4)

        st.download_button(
            label="📄 Download Report",
            data=report,
            file_name="iam_analysis_report.json",
            mime="application/json"
        )

    else:
        st.error("❌ API call failed")
