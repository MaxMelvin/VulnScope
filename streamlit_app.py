import streamlit as st
import subprocess
import json
import os
import pandas as pd
import io
from datetime import datetime
import matplotlib.pyplot as plt

# ---------- Config ----------
SCAN_FILE = "scan_results.json"
REPORT_SCRIPT = "report.py"
SCANNER_SCRIPT = "scanner.py"

st.set_page_config(page_title="Vuln Scanner Dashboard", layout="wide")

# ---------- Helpers ----------
def load_scan_results(path=SCAN_FILE):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def hosts_to_dataframe(scan_json):
    rows = []
    for host in scan_json.get("hosts", []):
        ip = host.get("ip", "")
        state = host.get("state", "")
        ports = host.get("ports", [])
        alerts = host.get("alerts", [])
        cves = host.get("cves", {})
        rows.append({
            "ip": ip,
            "state": state,
            "num_ports": len(ports),
            "num_alerts": len(alerts),
            "num_cves": sum(len(v) for v in cves.values()) if isinstance(cves, dict) else 0,
            "raw": host
        })
    df = pd.DataFrame(rows)
    return df

def expand_ports(host):
    rows = []
    for p in host.get("ports", []):
        rows.append({
            "ip": host.get("ip"),
            "port": p.get("port"),
            "service": p.get("service"),
            "version": p.get("version")
        })
    return rows

def expand_alerts(host):
    rows = []
    for a in host.get("alerts", []):
        rows.append({
            "ip": host.get("ip"),
            "message": a.get("message"),
            "severity": a.get("severity"),
            "score": a.get("score")
        })
    return rows

def expand_cves(host):
    rows = []
    cves = host.get("cves", {}) or {}
    for svc, items in cves.items():
        for c in items:
            rows.append({
                "ip": host.get("ip"),
                "service_port": svc,
                "cve_id": c.get("cve_id"),
                "severity": c.get("severity"),
                "score": c.get("score"),
                "description": (c.get("description") or "")[:300]
            })
    return rows

def severity_counts_from_scan(scan_json):
    counts = {"critical":0,"high":0,"medium":0,"low":0}
    for host in scan_json.get("hosts", []):
        for a in host.get("alerts", []):
            sev = (a.get("severity") or "").lower()
            if sev in counts:
                counts[sev] += 1
    return counts

def cve_severity_counts(scan_json):
    counts = {"critical":0,"high":0,"medium":0,"low":0,"unknown":0}
    for host in scan_json.get("hosts", []):
        cves = host.get("cves", {}) or {}
        for svc, items in cves.items():
            for c in items:
                sev = (c.get("severity") or "").lower()
                if sev in counts:
                    counts[sev] += 1
                else:
                    counts["unknown"] += 1
    return counts

def run_scanner_interactive(target):
    # Run scanner.py as a subprocess (interactive)
    # This will run nmap and take user input in the terminal; only call this if user agrees.
    cmd = ["python", SCANNER_SCRIPT]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # Provide target input and close stdin so scanner runs non-interactively
    try:
        out, err = proc.communicate(input=target + "\n", timeout=600)
    except Exception as e:
        proc.kill()
        out, err = proc.communicate()
        return False, out + "\n" + str(e)
    return proc.returncode == 0, out + ("\nERR:\n" + err if err else "")

def generate_report():
    if not os.path.exists(REPORT_SCRIPT):
        return False, "report.py not found in project."
    try:
        proc = subprocess.run(["python", REPORT_SCRIPT], capture_output=True, text=True, timeout=60)
        return proc.returncode == 0, proc.stdout + ("\nERR:\n" + proc.stderr if proc.stderr else "")
    except Exception as e:
        return False, str(e)

def download_link_for_df(df, filename):
    csv = df.to_csv(index=False)
    return st.download_button(label=f"Download {filename}", data=csv, file_name=filename, mime="text/csv")

# ---------- UI ----------
st.title("Local Vulnerability Scanner — Dashboard")
st.markdown("Control panel for scanning, exploring results, exporting CSV/PDF, and visualizing risks. Only scan networks you own.")

# Left sidebar controls
with st.sidebar:
    st.header("Actions")
    if st.button("Load latest scan_results.json"):
        st.experimental_rerun()

    st.markdown("### Run scan (optional)")
    run_now = st.checkbox("Run scanner now from dashboard (uses scanner.py)", value=False)
    if run_now:
        target_input = st.text_input("Enter target IP or subnet (example: 192.168.1.0/24)", value="192.168.1.0/24")
        if st.button("Start scan"):
            st.info("Starting scanner. It may take some time. Check console where Streamlit is running for nmap logs.")
            ok, out = run_scanner_interactive(target_input)
            if ok:
                st.success("Scanner finished. Reloading scan results.")
            else:
                st.error("Scanner failed or timed out. See output below.")
            st.code(out[:4000])

    st.markdown("---")
    st.markdown("### Report")
    if st.button("Generate PDF report (report.py)"):
        ok, out = generate_report()
        if ok:
            st.success("Report generated successfully. Check project folder for the PDF.")
            st.code(out[:2000])
        else:
            st.error("Report generation failed.")
            st.code(out[:2000])
    st.markdown("---")
    st.markdown("Upload a different scan JSON (optional)")
    uploaded = st.file_uploader("Upload scan_results.json", type=["json"])
    if uploaded:
        # save temporary file to disk as scan_results.json
        bytes_data = uploaded.getvalue()
        with open(SCAN_FILE, "wb") as f:
            f.write(bytes_data)
        st.success("Uploaded and saved as scan_results.json")
        st.experimental_rerun()

# Main panel
scan_json = load_scan_results()
if not scan_json:
    st.warning("No scan_results.json found. Run scanner.py first or upload a scan_results.json.")
else:
    # Top summary
    st.subheader("Scan summary")
    scanned_at = scan_json.get("scanned_at", "")
    target = scan_json.get("target", "")
    hosts = scan_json.get("hosts", [])
    st.write(f"Target: **{target}**")
    st.write(f"Scanned at (UTC): **{scanned_at}**")
    st.write(f"Discovered hosts: **{len(hosts)}**")

    # Severity counts
    sev_counts = severity_counts_from_scan(scan_json)
    fig, ax = plt.subplots(figsize=(6,2))
    labels = list(sev_counts.keys())
    values = [sev_counts[k] for k in labels]
    ax.barh(labels, values)
    ax.set_xlabel("Alert count")
    st.pyplot(fig)

    # Hosts table
    st.subheader("Hosts")
    df_hosts = hosts_to_dataframe(scan_json)
    st.dataframe(df_hosts.drop(columns=["raw"]), use_container_width=True)
    download_link_for_df(df_hosts.drop(columns=["raw"]), "hosts_summary.csv")

    # Expand selected host
    st.subheader("Host details")
    ip_choice = st.selectbox("Choose host IP", options=[h.get("ip") for h in hosts])
    chosen = next((h for h in hosts if h.get("ip") == ip_choice), None)
    if chosen:
        st.markdown(f"**Host:** {chosen.get('ip')}  —  State: {chosen.get('state')}")
        # Ports
        st.markdown("**Ports**")
        df_ports = pd.DataFrame(expand_ports(chosen))
        st.table(df_ports if not df_ports.empty else "No ports")
        if not df_ports.empty:
            download_link_for_df(df_ports, f"ports_{chosen.get('ip')}.csv")

        # Alerts
        st.markdown("**Alerts**")
        df_alerts = pd.DataFrame(expand_alerts(chosen))
        st.table(df_alerts if not df_alerts.empty else "No alerts")
        if not df_alerts.empty:
            download_link_for_df(df_alerts, f"alerts_{chosen.get('ip')}.csv")

        # CVEs
        st.markdown("**CVE Findings**")
        df_cves = pd.DataFrame(expand_cves(chosen))

        if not df_cves.empty:
            st.table(df_cves)
            download_link_for_df(df_cves, f"cves_{chosen.get('ip')}.csv")
        else:
            st.info("No CVEs found for this host.")

    # Global CVE summary
    st.subheader("Global CVE Summary")
    cve_counts = cve_severity_counts(scan_json)
    cve_df = pd.DataFrame([
        {"severity": k, "count": v} for k, v in cve_counts.items()
    ])
    st.table(cve_df)
    download_link_for_df(cve_df, "cve_summary.csv")

    # Raw JSON viewer
    st.subheader("Raw scan JSON (preview)")
    st.json(scan_json)

    st.markdown("---")
    st.markdown("**Notes & Ethics**")
    st.write("Only scan devices and networks you own or have permission to test. Running scans may disrupt some devices or services.")

