<p align="center">
  <img src="vulnscope_logo_dark.png" width="320">
</p>

<h1 align="center">VulnScope</h1>

<p align="center">
An advanced local vulnerability scanner with CVE lookup, severity scoring, PDF reporting, and a full Streamlit dashboard.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue.svg">
  <img src="https://img.shields.io/badge/Nmap-Integrated-orange.svg">
  <img src="https://img.shields.io/badge/Report-PDF-green.svg">
  <img src="https://img.shields.io/badge/CVEs-NVD%20Database-critical.svg">
  <img src="https://img.shields.io/badge/UI-Streamlit-red.svg">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg">
</p>

---

# 🚀 Overview

**VulnScope** is a powerful local-network vulnerability scanner built for cybersecurity learning, ethical hacking, and network assessment.  
It uses **Nmap**, a custom rules engine, and **offline CVE lookup** to identify weak services and outdated software with precision.

It includes:

- Real-time scanning  
- Severity scoring  
- CVE analysis  
- PDF reporting  
- Interactive Streamlit dashboard  

Perfect for:
- Portfolio projects  
- Learning cybersecurity  
- Practical network testing  
- Academic submissions  

---

# 🧰 Features

### 🔍 Port & Service Scanning (Nmap)
Detects:
- Open ports  
- Service names  
- Version fingerprints  

### ⚠️ Rule-Based Vulnerability Detection
Identifies common high-risk services:
- Telnet  
- SMB  
- FTP  
- MySQL  
- Apache  
- And more…

Includes:
- Critical  
- High  
- Medium  
- Low severity scoring  

### 🛡 CVE Lookup (Fast, Offline)
Matches detected service versions with CVEs from NVD.

Each CVE shows:
- ID  
- Description  
- Severity  
- CVSS score  

### 📊 Streamlit Dashboard
Includes:
- Host overview table  
- Alerts & vulnerabilities  
- CVE table  
- Severity charts  
- Export buttons  
- Run scan button  

### 📄 Professional PDF Report
Contains:
- Cover page  
- Severity summary  
- Color severity bars  
- CVE summary  
- Per-host analysis  

---

# 📁 Project Structure

