# Mini SIEM Lab – Security Event Monitoring & Analysis

This project simulates a small SIEM (Security Information and Event Management) pipeline for Level 1–2 security operations.

It ingests simulated:
- Windows Security Event logs
- Firewall logs
- Web server access logs

Then:
- Normalizes and correlates events
- Detects suspicious activity (e.g., brute-force attempts, privilege escalation, suspicious IPs)
- Generates an alert list and a short metrics summary
- Concludes with a professional-style security report

---

## 🧱 Objectives

- Demonstrate understanding of **SIEM concepts** using realistic logs.
- Practice **log analysis, correlation, and alerting** with Python.
- Show the ability to **document findings** in a professional report.
- Build a **GitHub-ready security project** for a SOC / security analyst or IT support role.

---

## 📂 Project Structure

```text
mini-siem-lab/
├─ README.md
├─ report/
│  └─ security_assessment_report.md
├─ logs/
│  ├─ windows_security.log
│  ├─ firewall.log
│  └─ webserver.log
├─ src/
│  └─ siem_simulator.py
├─ output/
│  ├─ alerts.csv
│  └─ metrics_summary.txt
└─ screenshots/
   ├─ failed_logons_chart.png
   ├─ alerts_table.png
   └─ timeline_view.png

