import streamlit as st
import sys
from pathlib import Path
from datetime import datetime

# Add project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from database import get_security_events

# Page configuration
st.set_page_config(
    page_title="PurpleShield AI",
    page_icon="🛡️",
    layout="wide"
)

# Custom styling
st.markdown("""
<style>
    .main {
        background-color: #0b1120;
    }

    .block-container {
        padding-top: 2rem;
    }

    .dashboard-title {
        font-size: 35px;
        font-weight: bold;
        color: #38bdf8;
    }

    .dashboard-subtitle {
        color: #94a3b8;
        font-size: 16px;
    }

    div[data-testid="stMetric"] {
        background-color: #172033;
        border: 1px solid #263449;
        padding: 20px;
        border-radius: 12px;
    }

    .status-box {
        background-color: #172033;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #263449;
    }
</style>
""", unsafe_allow_html=True)


# Sidebar
st.sidebar.title("🛡️ PurpleShield AI")
st.sidebar.caption("Cybersecurity Intelligence Platform")

page = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Email Security",
        "Network Security",
        "Threat Intelligence",
        "Security Events"
    ]
)

st.sidebar.markdown("---")
st.sidebar.success("Platform Status: Online")
st.sidebar.caption(
    f"Last accessed: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}"
)


# Dashboard page
if page == "Dashboard":

    st.markdown(
        '<div class="dashboard-title">🛡️ PurpleShield AI</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="dashboard-subtitle">'
        'Your centralized cybersecurity command center.'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown("---")

    # Fetch security events
    try:
        events = get_security_events()
    except Exception as error:
        st.error(f"Database error: {error}")
        events = []

    total_events = len(events)

    high_risk = sum(
        1 for event in events
        if str(event[3]).upper() == "HIGH"
    )

    medium_risk = sum(
        1 for event in events
        if str(event[3]).upper() == "MEDIUM"
    )

    low_risk = sum(
        1 for event in events
        if str(event[3]).upper() == "LOW"
    )

    # Security metrics
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Security Events", total_events)
    col2.metric("High Risk Events", high_risk)
    col3.metric("Medium Risk Events", medium_risk)
    col4.metric("Low Risk Events", low_risk)

    st.markdown("---")

    # Security overview
    left, right = st.columns(2)

    with left:
        st.subheader("📊 Security Overview")

        if total_events > 0:
            st.bar_chart({
                "Events": {
                    "High": high_risk,
                    "Medium": medium_risk,
                    "Low": low_risk
                }
            })
        else:
            st.info("No security events recorded yet.")

    with right:
        st.subheader("🔍 Security Modules")

        modules = [
            ("Email Threat Detection", "Ready"),
            ("Network Traffic Analysis", "Ready"),
            ("Threat Intelligence", "In Development"),
            ("Security Event Monitoring", "Ready")
        ]

        for module, status in modules:
            st.markdown(
                f"""
                <div class="status-box">
                    <b>{module}</b>
                    <span style="float:right;">{status}</span>
                </div>
                <br>
                """,
                unsafe_allow_html=True
            )

    st.markdown("---")

    # Recent security events
    st.subheader("🚨 Recent Security Events")

    if events:
        for event in events[-10:][::-1]:
            st.write(
                f"**Event:** {event[1]} | "
                f"**Source:** {event[2]} | "
                f"**Severity:** {event[3]}"
            )
    else:
        st.info("Your security event history is currently empty.")


# Email security page
elif page == "Email Security":

    st.title("📧 Email Security")
    st.write("Phishing and suspicious email investigation.")

    st.info(
        "Email analysis module will be connected here."
    )


# Network security page
elif page == "Network Security":

    st.title("🌐 Network Security")
    st.write("Network traffic monitoring and analysis.")

    st.info(
        "Network packet analysis module will be connected here."
    )


# Threat intelligence page
elif page == "Threat Intelligence":

    st.title("🕵️ Threat Intelligence")

    st.write(
        "Investigate suspicious IP addresses, domains and URLs."
    )

    st.info(
        "Threat intelligence integrations will be added here."
    )


# Security events page
elif page == "Security Events":

    st.title("🚨 Security Event Monitoring")

    try:
        events = get_security_events()

        if events:
            for event in events[::-1]:
                st.write({
                    "Event Type": event[1],
                    "Source": event[2],
                    "Severity": event[3],
                    "Description": event[4]
                })
        else:
            st.info("No security events available.")

    except Exception as error:
        st.error(f"Unable to retrieve security events: {error}")