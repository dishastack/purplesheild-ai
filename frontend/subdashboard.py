
import streamlit as st

def show_packetpilot_dashboard():

    st.title("🛡️ PacketPilot AI")
    st.caption("Network Security & Traffic Intelligence")

    st.divider()

    st.subheader("Network Security Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric("Packet Analysis", "Ready")
    col2.metric("DNS Investigation", "Ready")
    col3.metric("Threat Hunting", "Ready")

    st.divider()

    st.subheader("Network Security Modules")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📡 Packet Analyzer")
        st.write("Analyze uploaded PCAP and PCAPNG files.")

        st.markdown("### 🌐 DNS Investigation")
        st.write("Investigate DNS queries and suspicious domains.")

        st.markdown("### 🔄 TCP Handshake Analyzer")
        st.write("Inspect TCP SYN, SYN-ACK and ACK communication.")

        st.markdown("### 📊 Protocol Intelligence")
        st.write("Understand network protocol distribution.")

    with col2:
        st.markdown("### 🚨 SOC Command Center")
        st.write("Monitor network security indicators.")

        st.markdown("### 🔎 Threat Hunting Workbench")
        st.write("Investigate suspicious network activity.")

        st.markdown("### 📈 Executive Dashboard")
        st.write("View summarized network security findings.")

    st.divider()

    st.info(
        "PacketPilot backend integration will be connected "
        "in the next development stage."
    )
