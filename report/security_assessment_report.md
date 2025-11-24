# Mini SIEM Lab – Security Event Monitoring Report

**Author:** Arnaud Brice Shimwa  
**Date:** {{DATE}}  
**Environment:** Simulated Windows, Firewall, and Web Logs

---

## 1. Executive Summary

This report presents the results of a simulated SIEM (Security Information and Event Management) analysis performed on sample Windows Security, firewall, and web server logs.

The objective was to:
- Validate the ability to ingest and normalize heterogeneous log sources.
- Detect common attack patterns (brute-force attempts, privilege escalation, suspicious web access).
- Produce a concise summary of security-relevant findings and recommendations.

Overall, the simulated environment revealed:
- Indicators consistent with brute-force login attempts.
- A suspicious successful logon following multiple failures.
- Privilege escalation events involving the creation and promotion of a new user.
- High volumes of blocked firewall traffic from the same external hosts.
- Suspicious access attempts to administrative web paths.

---

## 2. Environment & Methodology

### 2.1 Environment

The analysis was performed using:
- **Log sources:**
  - `windows_security.log` – Simulated Windows Security events.
  - `firewall.log` – Simulated firewall allow/deny events.
  - `webserver.log` – Simulated web access logs.
- **Processing tools:**
  - Python 3 with a custom script: `src/siem_simulator.py`
  - Output files: `output/alerts.csv` and `output/metrics_summary.txt`

### 2.2 Methodology

1. **Log Ingestion & Parsing**  
   - Each log line was parsed into a structured event (timestamp, host, event ID, IP, action, etc.).
2. **Normalization & Correlation**  
   - Events were grouped by source IP and user where applicable.
   - Time windows were applied to identify burst activity.
3. **Detection Rules**  
   The following rules were implemented:
   - **Brute-force login attempts**:  
     - ≥ 3 failed logon attempts from the same IP within 10 minutes.
   - **Suspicious success after failures**:  
     - A successful logon within 15 minutes after ≥ 3 failures from the same IP.
   - **Privilege escalation**:  
     - Occurrences of user creation or membership changes to privileged groups.
   - **Firewall scans**:  
     - ≥ 3 blocked firewall events from the same IP within 10 minutes.
   - **Suspicious web access**:  
     - Access to administrative paths or unknown/risky regions.

4. **Reporting**  
   - Alerts were exported to `alerts.csv`.
   - Summary metrics were documented.
   - Key observations were consolidated into this report.

---

## 3. Key Metrics

> Update the placeholders below with real numbers from `metrics_summary.txt`.

- **Total events processed:**  _X_  
  - Windows Security: _X_  
  - Firewall: _X_  
  - Web: _X_  
- **Total alerts generated:**  _Y_  
  - Brute-force login alerts: _Y1_  
  - Success-after-failure alerts: _Y2_  
  - Privilege escalation alerts: _Y3_  
  - Firewall scan alerts: _Y4_  
  - Suspicious web access alerts: _Y5_  

```markdown
![Alerts by type](../screenshots/alerts_table.png)

