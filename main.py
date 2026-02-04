import streamlit as st
import pandas as pd
from core.network_scanner import discovery_scan
from core.port_scanner import fast_port_scan
from utils.logger import setup_logger

# Inisialisasi Logger
logger = setup_logger()

st.set_page_config(page_title="Liyas Security Pro", layout="wide", page_icon="🛡️")

# Styling Custom
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1f2937; padding: 15px; border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Liyas Security Scanner Pro")
st.write("Alat audit keamanan jaringan lokal berbasis Python.")

# Sidebar
st.sidebar.header("Scan Control")
target_input = st.sidebar.text_input("Target Subnet", "192.168.1.0/24")
scan_btn = st.sidebar.button("Run Global Scan")

if scan_btn:
    logger.info(f"User memulai scan pada {target_input}")
    
    with st.spinner("Step 1: Discovering Devices..."):
        devices = discovery_scan(target_input)
    
    if devices:
        st.success(f"Berhasil menemukan {len(devices)} perangkat.")
        
        results_data = []
        progress_text = st.empty()
        bar = st.progress(0)
        
        for i, dev in enumerate(devices):
            progress_text.text(f"Scanning Ports for: {dev['ip']}")
            ports = fast_port_scan(dev['ip'])
            
            status = "⚠️ Berisiko" if ports else "✅ Aman"
            results_data.append({
                "IP Address": dev['ip'],
                "MAC Address": dev['mac'],
                "Open Ports": ", ".join(map(str, ports)) if ports else "None",
                "Security Status": status
            })
            bar.progress((i + 1) / len(devices))
        
        # Dashboard Stats
        st.markdown("---")
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Devices", len(devices))
        c2.metric("Total Open Ports", sum(1 for r in results_data if r["Open Ports"] != "None"))
        c3.metric("Critical Alerts", sum(1 for r in results_data if "⚠️" in r["Security Status"]))

        # Data Table
        df = pd.DataFrame(results_data)
        st.subheader("Detail Perangkat Terdeteksi")
        st.dataframe(df, use_container_width=True)

        # Charting
        st.subheader("📊 Distribusi Port Terbuka")
        all_ports = []
        for r in results_data:
            if r["Open Ports"] != "None":
                all_ports.extend(r["Open Ports"].split(", "))
        
        if all_ports:
            p_counts = pd.Series(all_ports).value_counts()
            st.bar_chart(p_counts)
        
        # Export
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download Report (CSV)", csv, "security_report.csv", "text/csv")
        
    else:
        st.error("Tidak ada perangkat yang merespons. Jalankan sebagai Administrator.")
        logger.warning("Scan selesai tanpa hasil.")

st.sidebar.markdown("---")
st.sidebar.caption("© 2026 Liyas Security Dev")