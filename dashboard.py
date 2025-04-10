import streamlit as st
import os

st.set_page_config(page_title="Threat Detection Dashboard", layout="wide")
st.title("🔐 Network Threat Detection Dashboard")

# File paths
packet_log_path = "packets.log"
alert_log_path = "alerts.log"

# --- Packet Logs Section ---
st.subheader("📦 Captured Packets")
if os.path.exists(packet_log_path):
    with open(packet_log_path, "r") as f:
        packets = f.readlines()
    st.metric("Total Packets Captured", len(packets))
    st.text_area("Packet Log", "".join(packets), height=300)
else:
    st.warning("⚠️ packets.log file not found!")

# --- Alert Logs Section ---
st.subheader("🚨 Suspicious Activity Detected")
if os.path.exists(alert_log_path):
    with open(alert_log_path, "r") as f:
        alerts = f.readlines()
    st.metric("Suspicious Alerts", len(alerts))
    st.text_area("Alert Log", "".join(alerts), height=300)
else:
    st.warning("⚠️ alerts.log file not found!")
