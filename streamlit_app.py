import streamlit as st
import pandas as pd
import socket
import logging
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp

# ==========================================
# 1. KONFIGURASI LOGGING & SETUP
# ==========================================
if not os.path.exists('logs'):
    os.makedirs('logs')

logging.basicConfig(
    filename='logs/scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ==========================================
# 2. LOGIKA CORE (SCANNING ENGINE)
# ==========================================

def discovery_scan(ip_range):
    """Mencari perangkat aktif menggunakan protokol ARP."""
    try:
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        combined_packet = broadcast / arp_request
        answered_list = srp(combined_packet, timeout=2, verbose=False)[0]
        
        devices = []
        for element in answered_list:
            devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
        return devices
    except Exception as e:
        logging.error(f"Discovery Error: {e}")
        return []

def check_port(ip, port):
    """Mengecek apakah port tertentu terbuka."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        if s.connect_ex((ip, port)) == 0:
            return port
    except:
        pass
    finally:
        s.close()
    return None

def fast_port_scan(ip, ports=[21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080]):
    """Melakukan scanning port secara paralel menggunakan Multi-threading."""
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda p: check_port(ip, p), ports)
    return [p for p in results if p]

def get_recommendation(port):
    """Memberikan rekomendasi keamanan berdasarkan port yang terbuka."""
    advice = {
        21: "FTP (Insecure): Gunakan SFTP atau matikan jika tidak perlu.",
        22: "SSH: Pastikan menggunakan Key-Auth, bukan password.",
        23: "TELNET (Critical): Matikan segera! Gunakan SSH sebagai gantinya.",
        80: "HTTP: Port Web. Pastikan server selalu di-update.",
        443: "HTTPS: Aman. Cek masa berlaku sertifikat SSL.",
        445: "SMB: Risiko Ransomware tinggi! Batasi akses IP lokal saja.",
        3306: "MySQL: Jangan ekspos database ke jaringan publik.",
        3389: "RDP (Remote Desktop): Gunakan VPN, jangan buka langsung ke publik."
    }
    return advice.get(port, "Layanan terdeteksi. Lakukan audit manual.")

# ==========================================
# 3. INTERFACE (STREAMLIT UI)
# ==========================================

st.set_page_config(page_title="Liyas Security Pro", layout="wide", page_icon="🛡️")

# Custom Styling
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1f2937; padding: 15px; border-radius: 10px; border-left: 5px solid #00ff00; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Liyas Security Scanner Professional")
st.write(f"Sistem Audit Keamanan Jaringan Lokal | Tanggal: {datetime.now().strftime('%d-%m-%Y')}")
st.markdown("---")

# Sidebar Configuration
st.sidebar.header("🔧 Pengaturan Scanner")
target_subnet = st.sidebar.text_input("Input Target Subnet", "192.168.1.0/24")
scan_type = st.sidebar.selectbox("Mode Scan", ["Quick Scan", "Full Audit (Port 1-1024)"])
start_btn = st.sidebar.button("Mulai Audit Jaringan")

if start_btn:
    logging.info(f"User memulai scan pada: {target_subnet}")
    
    # --- PHASE 1: DISCOVERY ---
    with st.status("🔍 Mencari perangkat aktif di jaringan...", expanded=True) as status:
        devices = discovery_scan(target_subnet)
        if not devices:
            st.error("Gagal mendeteksi perangkat. Harap jalankan sebagai Administrator.")
            st.stop()
        
        status.update(label=f"Ditemukan {len(devices)} perangkat aktif!", state="complete", expanded=False)

    # --- PHASE 2: PORT SCANNING ---
    results_list = []
    progress_bar = st.progress(0)
    
    port_list = range(1, 1025) if scan_type == "Full Audit (Port 1-1024)" else [21, 22, 23, 80, 443, 445, 3306, 3389]

    for idx, dev in enumerate(devices):
        st.write(f"Analisis Mendalam: {dev['ip']}")
        open_ports = fast_port_scan(dev['ip'], ports=port_list)
        
        # Mapping rekomendasi
        recommendations = [get_recommendation(p) for p in open_ports]
        
        risk_level = "🔴 Tinggi" if any(p in [21, 23, 445, 3389] for p in open_ports) else "🟢 Rendah"
        
        results_list.append({
            "IP Address": dev['ip'],
            "MAC Address": dev['mac'],
            "Port Terbuka": ", ".join(map(str, open_ports)) if open_ports else "Bersih",
            "Rekomendasi Tindakan": " | ".join(recommendations) if recommendations else "Tidak ada tindakan mendesak.",
            "Risiko": risk_level
        })
        progress_bar.progress((idx + 1) / len(devices))

    # --- PHASE 3: DASHBOARD DISPLAY ---
    st.markdown("### 📊 Ringkasan Keamanan Jaringan")
    df = pd.DataFrame(results_list)
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Host Terdeteksi", len(devices))
    col2.metric("Perangkat Berisiko", sum(1 for r in results_list if "🔴" in r["Risiko"]))
    col3.metric("Total Port Terbuka", sum(len(r["Port Terbuka"].split(", ")) if r["Port Terbuka"] != "Bersih" else 0 for r in results_list))

    st.subheader("📋 Laporan Hasil Audit")
    st.dataframe(df, use_container_width=True)

    # Visualization
    if any(r["Port Terbuka"] != "Bersih" for r in results_list):
        st.subheader("📈 Statistik Sebaran Port")
        all_found_ports = []
        for r in results_list:
            if r["Port Terbuka"] != "Bersih":
                all_found_ports.extend(r["Port Terbuka"].split(", "))
        
        port_counts = pd.Series(all_found_ports).value_counts()
        st.bar_chart(port_counts)

    # Exporting
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 Ekspor Laporan Keamanan (CSV)",
        data=csv,
        file_name=f"Audit_Report_{datetime.now().strftime('%Y%m%d')}.csv",
        mime='text/csv',
    )

st.sidebar.markdown("---")
st.sidebar.caption("© 2026 Developer: Liyas Syarifudin, M.Pd.")