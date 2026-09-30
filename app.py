import streamlit as st

from src.parser import load_logs
from src.detector import (
    detect_brute_force,
    detect_success_after_failures
)
from src.ioc_extractor import extract_iocs_from_alert
from src.threat_intel import check_ip_reputation
from src.ai_analyzer import analyze_alert


LOG_FILE = "data/sample_logs.csv"


st.set_page_config(
    page_title="AI SOC Alert Triage",
    page_icon="🛡️",
    layout="wide"
)


st.title("🛡️ AI SOC Alert Triage System")
st.caption(
    "AI-assisted security alert investigation and threat intelligence enrichment"
)


@st.cache_data
def load_and_detect():
    df = load_logs(LOG_FILE)

    brute_force_alerts = detect_brute_force(df)
    compromise_alerts = detect_success_after_failures(df)

    return df, brute_force_alerts + compromise_alerts


df, alerts = load_and_detect()


# --------------------------------------------------
# Dashboard metrics
# --------------------------------------------------

st.subheader("Security Operations Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Security Events", len(df))

with col2:
    st.metric("Total Alerts", len(alerts))

with col3:
    high_alerts = sum(
        alert["severity"] == "HIGH"
        for alert in alerts
    )
    st.metric("High Severity", high_alerts)

with col4:
    critical_alerts = sum(
        alert["severity"] == "CRITICAL"
        for alert in alerts
    )
    st.metric("Critical", critical_alerts)


st.divider()


# --------------------------------------------------
# Alert table
# --------------------------------------------------

st.subheader("Detected Alerts")

for index, alert in enumerate(alerts):

    severity = alert["severity"]

    if severity == "CRITICAL":
        icon = "🔴"
    elif severity == "HIGH":
        icon = "🟠"
    else:
        icon = "🟡"

    with st.expander(
        f"{icon} {alert['alert_type']} — "
        f"{alert.get('source_ip', 'Unknown IP')}"
    ):

        left, right = st.columns(2)

        with left:
            st.write("**Alert Type:**", alert["alert_type"])
            st.write("**Severity:**", alert["severity"])
            st.write("**Source IP:**", alert.get("source_ip", "N/A"))
            st.write("**User:**", alert.get("user", "N/A"))

        with right:
            st.write(
                "**Failed Attempts:**",
                alert.get("failed_attempts", "N/A")
            )
            st.write("**MITRE ATT&CK:**", alert.get("mitre", "N/A"))

        st.divider()

        # --------------------------------------------------
        # IOC extraction
        # --------------------------------------------------

        st.write("### IOC Extraction")

        iocs = extract_iocs_from_alert(alert)

        st.json(iocs)

        # --------------------------------------------------
        # Threat intelligence
        # --------------------------------------------------

        st.write("### Threat Intelligence")

        threat_intel = {}

        ip_addresses = iocs.get("ip_addresses", [])

        if ip_addresses:

            ip = ip_addresses[0]

            with st.spinner(f"Checking AbuseIPDB for {ip}..."):
                threat_intel = check_ip_reputation(ip)

            if "error" in threat_intel:
                st.error(threat_intel["error"])
            else:

                ti1, ti2, ti3 = st.columns(3)

                with ti1:
                    st.metric(
                        "Abuse Confidence",
                        threat_intel.get(
                            "abuse_confidence_score",
                            "N/A"
                        )
                    )

                with ti2:
                    st.metric(
                        "Historical Reports",
                        threat_intel.get(
                            "total_reports",
                            "N/A"
                        )
                    )

                with ti3:
                    st.write(
                        "**Country:**",
                        threat_intel.get("country", "N/A")
                    )
                    st.write(
                        "**ISP:**",
                        threat_intel.get("isp", "N/A")
                    )

        # --------------------------------------------------
        # AI investigation
        # --------------------------------------------------

        st.write("### 🤖 AI Investigation")

        if st.button(
            "Run AI Investigation",
            key=f"ai_button_{index}"
        ):

            with st.spinner("Analyzing alert with local Qwen3..."):

                ai_result = analyze_alert(
                    alert,
                    threat_intel
                )

            st.markdown(ai_result)


st.divider()

st.caption(
    "AI provides investigation assistance only. "
    "Final triage and response decisions remain with the SOC analyst."
)
