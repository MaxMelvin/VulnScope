import json
from fpdf import FPDF
from datetime import datetime
import os

INPUT_FILE = "scan_results.json"
OUTPUT_FILE = f"vuln_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

if not os.path.exists(INPUT_FILE):
    print(f"Missing {INPUT_FILE}. Run scanner.py first.")
    raise SystemExit(1)

with open(INPUT_FILE, encoding="utf-8") as f:
    data = json.load(f)

scanned_at = data.get("scanned_at", "")
target = data.get("target", "")
hosts = data.get("hosts", [])


# ---------------------------------------------------------
# COUNT CVEs
# ---------------------------------------------------------
cve_severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
total_cves = 0
top_cves = []

for host in hosts:
    host_cves = host.get("cves", {})
    for svc, cve_list in host_cves.items():
        for cve in cve_list:
            sev = cve["severity"].lower()
            if sev in cve_severity_count:
                cve_severity_count[sev] += 1
            else:
                cve_severity_count["unknown"] += 1
            total_cves += 1
            top_cves.append(cve)


# ---------------------------------------------------------
# COUNT SEVERITIES
# ---------------------------------------------------------
severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
total_score = 0

for host in hosts:
    for alert in host.get("alerts", []):
        sev = alert["severity"]
        score = alert["score"]
        if sev in severity_count:
            severity_count[sev] += 1
        total_score += score


# ---------------------------------------------------------
# PDF CLASS
# ---------------------------------------------------------
class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 14)
        self.cell(0, 10, "Local Vulnerability Scan Report", ln=True, align="C")
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "", 9)
        self.cell(
            0,
            10,
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC   |   Page {self.page_no()}",
            align="C"
        )


pdf = PDF()
pdf.set_auto_page_break(auto=True, margin=15)

# ---------------------------------------------------------
# COVER PAGE
# ---------------------------------------------------------
pdf.add_page()
pdf.set_font("Arial", "B", 20)
pdf.cell(0, 20, "Vulnerability Scan Report", ln=True, align="C")
pdf.ln(6)

pdf.set_font("Arial", "", 12)
pdf.cell(0, 8, f"Target: {target}", ln=True)
pdf.cell(0, 8, f"Scanned at (UTC): {scanned_at}", ln=True)
pdf.cell(0, 8, f"Generated at (UTC): {datetime.utcnow().isoformat()}", ln=True)
pdf.ln(10)

pdf.multi_cell(
    0,
    6,
    "This report summarizes discovered hosts, open ports, detected services, "
    "and rule-based vulnerability alerts. Use this report strictly for devices "
    "you own or are authorized to test."
)
pdf.ln(10)

# ---------------------------------------------------------
# SEVERITY SUMMARY PAGE WITH COLOR BARS
# ---------------------------------------------------------
pdf.add_page()
pdf.set_font("Arial", "B", 18)
pdf.cell(0, 12, "Severity Summary", ln=True)
pdf.ln(4)

pdf.set_font("Arial", "", 12)
pdf.cell(0, 8, f"Total Alerts Found: {sum(severity_count.values())}", ln=True)
pdf.cell(0, 8, f"Total Risk Score: {total_score}", ln=True)
pdf.ln(10)

pdf.set_font("Arial", "B", 14)
pdf.cell(0, 10, "Severity Breakdown", ln=True)
pdf.ln(4)

# Draw severity bars
bar_width = 150
bar_height = 8
start_x = pdf.get_x()

def draw_sev_bar(label, count, rgb):
    pdf.set_font("Arial", "B", 11)
    pdf.set_fill_color(*rgb)
    y = pdf.get_y()
    pdf.rect(start_x, y, bar_width, bar_height, "F")
    pdf.set_xy(start_x + 2, y + 1)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 6, f"{label}: {count}", ln=True)

# Critical - Red
draw_sev_bar("Critical", severity_count["critical"], (255, 0, 0))

# High - Orange
draw_sev_bar("High", severity_count["high"], (255, 128, 0))

# Medium - Yellow
draw_sev_bar("Medium", severity_count["medium"], (255, 215, 0))

# Low - Green
draw_sev_bar("Low", severity_count["low"], (0, 200, 0))

pdf.set_text_color(0, 0, 0)
pdf.ln(12)


# -------------------------------
# CVE SUMMARY PAGE
# -------------------------------
pdf.add_page()
pdf.set_font("Arial", "B", 18)
pdf.cell(0, 12, "CVE Summary", ln=True)
pdf.ln(4)

pdf.set_font("Arial", "", 12)
pdf.cell(0, 8, f"Total CVEs Found: {total_cves}", ln=True)
pdf.ln(4)

# Severity breakdown
pdf.set_font("Arial", "B", 14)
pdf.cell(0, 10, "CVE Severity Breakdown", ln=True)
pdf.ln(4)

# Draw colored bars for CVEs
bar_width = 150
bar_height = 8
start_x = pdf.get_x()

def draw_cve_bar(label, count, rgb):
    pdf.set_font("Arial", "B", 11)
    pdf.set_fill_color(*rgb)
    y = pdf.get_y()
    pdf.rect(start_x, y, bar_width, bar_height, "F")
    pdf.set_xy(start_x + 2, y + 1)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 6, f"{label}: {count}", ln=True)

# Critical – Red
draw_cve_bar("Critical", cve_severity_count["critical"], (255, 0, 0))

# High – Orange
draw_cve_bar("High", cve_severity_count["high"], (255, 128, 0))

# Medium – Yellow
draw_cve_bar("Medium", cve_severity_count["medium"], (255, 215, 0))

# Low – Green
draw_cve_bar("Low", cve_severity_count["low"], (0, 200, 0))

# Unknown – Grey
draw_cve_bar("Unknown", cve_severity_count["unknown"], (180, 180, 180))

pdf.ln(10)

# Top CVEs section
pdf.set_font("Arial", "B", 14)
pdf.cell(0, 10, "Top Risk CVEs", ln=True)
pdf.set_font("Arial", "", 11)
pdf.ln(3)

# Sort top CVEs by score descending
top_cves_sorted = sorted(top_cves, key=lambda x: float(x["score"]) if str(x["score"]).replace('.', '', 1).isdigit() else 0, reverse=True)

if top_cves_sorted:
    for c in top_cves_sorted[:8]:  # limit to top 8
        pdf.multi_cell(
            0,
            6,
            f"- {c['cve_id']} | Severity: {c['severity']} | Score: {c['score']}\n"
            f"  {c['description'][:120]}..."
        )
        pdf.ln(1)
else:
    pdf.cell(0, 8, "No CVE data found.", ln=True)

pdf.set_text_color(0, 0, 0)
pdf.ln(10)


# ---------------------------------------------------------
# DETAILED HOST PAGES
# ---------------------------------------------------------
for host in hosts:
    pdf.add_page()
    ip = host.get("ip", "")
    state = host.get("state", "")

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"Host: {ip} ({state})", ln=True)
    pdf.ln(5)

    # ---- Ports Table ----
    pdf.set_font("Arial", "B", 12)
    pdf.cell(28, 8, "Port", border=1)
    pdf.cell(50, 8, "Service", border=1)
    pdf.cell(0, 8, "Version", border=1, ln=True)

    pdf.set_font("Arial", "", 11)
    for p in host.get("ports", []):
        pdf.cell(28, 7, str(p.get("port", "")), border=1)
        pdf.cell(50, 7, p.get("service", "")[:40], border=1)
        pdf.cell(0, 7, p.get("version", "")[:90], border=1, ln=True)

    pdf.ln(5)

    # ---- Alerts ----
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "Alerts", ln=True)

    pdf.set_font("Arial", "", 11)
    alerts = host.get("alerts", [])
    if alerts:
        for a in alerts:
            pdf.multi_cell(
                0,
                6,
                f"- {a['message']} (Severity: {a['severity'].upper()}, Score: {a['score']})"
            )
    else:
        pdf.cell(0, 6, "No critical alerts found.", ln=True)

    pdf.ln(5)

    # ---- Recommendations ----
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "Recommendations", ln=True)
    pdf.set_font("Arial", "", 11)

    ports = host.get("ports", [])
    recs = []

    if any(p.get("port") == 23 for p in ports):
        recs.append("Disable Telnet. Use SSH instead.")
    if any(p.get("port") == 21 for p in ports):
        recs.append("Disable FTP or enforce strong authentication.")
    if any(p.get("port") == 445 for p in ports):
        recs.append("Disable SMBv1 and apply security patches.")
    if any("mysql" in p.get("service", "") for p in ports):
        recs.append("Restrict MySQL usage to localhost or secure the port.")
    if not recs:
        recs.append("No immediate recommendations for this host.")

    for r in recs:
        pdf.multi_cell(0, 6, f"- {r}")

# ---------------------------------------------------------
# FINAL NOTES
# ---------------------------------------------------------
pdf.add_page()
pdf.set_font("Arial", "B", 14)
pdf.cell(0, 10, "Final Notes & Ethics", ln=True)
pdf.ln(5)

pdf.set_font("Arial", "", 11)
pdf.multi_cell(
    0,
    6,
    "This report is generated for educational and authorized use only. "
    "Never scan networks without explicit permission. High severity items should "
    "be addressed immediately. Medium and low severity items still pose risk and "
    "should be reviewed based on your environment."
)

# ---------------------------------------------------------
# SAVE PDF
# ---------------------------------------------------------
pdf.output(OUTPUT_FILE)
print(f"Report generated: {OUTPUT_FILE}")
