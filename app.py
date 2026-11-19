
import streamlit as st
import pandas as pd
import plotly.express as px

from firewall import check_firewall, FIREWALL_RULES
from database import (
    initialize_database,
    save_traffic,
    get_traffic_logs,
    get_suspicious_ips,
    save_alert,
    get_alerts
)

st.set_page_config(
    page_title="Network Security Monitoring System",
    page_icon="🛡️",
    layout="wide"
)

initialize_database()

st.title("🛡️ Network Security and Firewall Monitoring System")
st.caption("Firewall Traffic Monitoring | Threat Detection | Security Logs")

# Sidebar
st.sidebar.header("Firewall Configuration")
st.sidebar.write("Total Rules:", len(FIREWALL_RULES))
st.sidebar.write("Default Policy: BLOCK")

# Traffic simulation
st.subheader("Simulate Network Traffic")

with st.form("traffic_form"):
    col1, col2 = st.columns(2)

    with col1:
        source_ip = st.text_input("Source IP", "192.168.1.10")
        destination_ip = st.text_input(
            "Destination IP", "192.168.1.20"
        )
        port = st.number_input(
            "Port Number", min_value=1, max_value=65535, value=443
        )

    with col2:
        protocol = st.selectbox("Protocol", ["TCP", "UDP"])
        traffic_type = st.selectbox(
            "Traffic Type", ["Incoming", "Outgoing"]
        )

    submitted = st.form_submit_button("Check Firewall")

if submitted:
    try:
        result = check_firewall(
            source_ip,
            destination_ip,
            int(port),
            protocol,
            traffic_type
        )

        save_traffic(result)

        st.success(
            "Traffic ALLOWED"
            if result["Access Status"] == "ALLOWED"
            else "Traffic BLOCKED"
        )

        st.json(result)

    except ValueError as error:
        st.error(str(error))

# Retrieve database records
logs = get_traffic_logs()
suspicious = pd.DataFrame(get_suspicious_ips(3), columns=["source_ip", "blocked_attempts"])

# Generate alerts
if not suspicious.empty:
    for _, row in suspicious.iterrows():
        save_alert(row["source_ip"], int(row["blocked_attempts"]))

alerts = get_alerts()

st.divider()
st.subheader("📊 Security Dashboard")

total = len(logs)

allowed = (
    int((logs["access_status"] == "ALLOWED").sum())
    if total else 0
)

blocked = (
    int((logs["access_status"] == "BLOCKED").sum())
    if total else 0
)

alert_count = len(suspicious)

c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Traffic", total)
c2.metric("Allowed Traffic", allowed)
c3.metric("Blocked Traffic", blocked)
c4.metric("Suspicious IPs", alert_count)

if total:
    left, right = st.columns(2)

    with left:
        fig = px.pie(
            names=["Allowed", "Blocked"],
            values=[allowed, blocked],
            title="Traffic Access Distribution"
        )
        st.plotly_chart(fig, use_container_width=True)

    with right:
        fig = px.bar(
            x=["Allowed", "Blocked"],
            y=[allowed, blocked],
            title="Firewall Traffic Analysis",
            labels={"x": "Access Status", "y": "Number of Requests"}
        )
        st.plotly_chart(fig, use_container_width=True)

st.subheader("🚨 Suspicious Activity Detection")

if suspicious.empty:
    st.info("No suspicious IP addresses detected.")
else:
    st.warning("Repeated blocked attempts detected!")
    st.dataframe(suspicious, use_container_width=True)

st.subheader("📋 Network Traffic Logs")

if logs.empty:
    st.info("No traffic records available yet.")
else:
    st.dataframe(logs, use_container_width=True)

st.subheader("🔔 Security Alerts")

if alerts.empty:
    st.info("No security alerts available.")
else:
    st.dataframe(alerts, use_container_width=True)

st.caption(
    "Academic demonstration using simulated network traffic. "
    "This prototype does not capture live network packets."
)
