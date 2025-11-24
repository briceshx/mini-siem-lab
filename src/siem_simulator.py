import os
import csv
from collections import defaultdict, Counter
from datetime import datetime, timedelta

LOG_DIR = "logs"
OUTPUT_DIR = "output"

WINDOWS_LOG = os.path.join(LOG_DIR, "windows_security.log")
FIREWALL_LOG = os.path.join(LOG_DIR, "firewall.log")
WEB_LOG = os.path.join(LOG_DIR, "webserver.log")

ALERTS_CSV = os.path.join(OUTPUT_DIR, "alerts.csv")
METRICS_TXT = os.path.join(OUTPUT_DIR, "metrics_summary.txt")


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def parse_timestamp(ts: str) -> datetime:
    # Example format: 2025-11-20T09:01:05Z
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def parse_kv_fields(raw: str) -> dict:
    fields = {}
    if not raw:
        return fields
    for item in raw.split(";"):
        if "=" in item:
            k, v = item.split("=", 1)
            fields[k.strip()] = v.strip()
    return fields


def load_windows_logs():
    events = []
    with open(WINDOWS_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ts, host, event_id, level, msg, raw_fields = line.split("|", 5)
            fields = parse_kv_fields(raw_fields)
            events.append({
                "timestamp": parse_timestamp(ts),
                "host": host,
                "event_id": event_id,
                "level": level,
                "message": msg,
                **fields
            })
    return events


def load_firewall_logs():
    events = []
    with open(FIREWALL_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ts, device, action, proto, src_ip, dst_ip, dst_port = line.split("|")
            events.append({
                "timestamp": parse_timestamp(ts),
                "device": device,
                "action": action,
                "protocol": proto,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port
            })
    return events


def load_web_logs():
    events = []
    with open(WEB_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ts, host, ip, method, path, status, extra = line.split("|")
            fields = parse_kv_fields(extra)
            events.append({
                "timestamp": parse_timestamp(ts),
                "host": host,
                "ip": ip,
                "method": method,
                "path": path,
                "status": status,
                **fields
            })
    return events


def detect_bruteforce_login(windows_events, threshold=3, window_minutes=10):
    alerts = []
    failed_by_ip = defaultdict(list)

    for ev in windows_events:
        if ev["event_id"] == "4625":  # failed logon
            ip = ev.get("ip", "unknown")
            failed_by_ip[ip].append(ev["timestamp"])

    for ip, times in failed_by_ip.items():
        times = sorted(times)
        window = timedelta(minutes=window_minutes)
        for i in range(len(times)):
            count = 1
            for j in range(i + 1, len(times)):
                if times[j] - times[i] <= window:
                    count += 1
                else:
                    break
            if count >= threshold:
                alerts.append({
                    "type": "BRUTE_FORCE_LOGIN",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "count": count,
                    "time_window_start": times[i],
                    "time_window_end": times[i] + window,
                    "description": f"{count} failed logons from {ip} within {window_minutes} minutes"
                })
                break

    return alerts


def detect_suspicious_success_after_fail(windows_events, fail_threshold=3, window_minutes=15):
    alerts = []
    by_ip = defaultdict(list)

    for ev in windows_events:
        ip = ev.get("ip", "unknown")
        by_ip[ip].append(ev)

    window = timedelta(minutes=window_minutes)

    for ip, events in by_ip.items():
        events = sorted(events, key=lambda e: e["timestamp"])
        failed_times = [e["timestamp"] for e in events if e["event_id"] == "4625"]
        success_times = [e["timestamp"] for e in events if e["event_id"] == "4624"]

        if not failed_times or not success_times:
            continue

        for s_time in success_times:
            fails_before = [t for t in failed_times if s_time - t <= window and t < s_time]
            if len(fails_before) >= fail_threshold:
                alerts.append({
                    "type": "SUCCESS_AFTER_MULTIPLE_FAILURES",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "fail_count": len(fails_before),
                    "success_time": s_time,
                    "description": f"Successful logon from {ip} after {len(fails_before)} failures within {window_minutes} minutes"
                })
                break

    return alerts


def detect_privilege_escalation(windows_events):
    alerts = []
    for ev in windows_events:
        if ev["event_id"] in ("4720", "4728"):
            alerts.append({
                "type": "PRIVILEGE_CHANGE",
                "severity": "HIGH",
                "host": ev["host"],
                "event_id": ev["event_id"],
                "user": ev.get("user", ""),
                "description": ev["message"]
            })
    return alerts


def detect_firewall_scans(firewall_events, threshold=3, window_minutes=10):
    alerts = []
    blocked_by_ip = defaultdict(list)

    for ev in firewall_events:
        if ev["action"] == "BLOCK":
            blocked_by_ip[ev["src_ip"]].append(ev["timestamp"])

    window = timedelta(minutes=window_minutes)

    for ip, times in blocked_by_ip.items():
        times = sorted(times)
        for i in range(len(times)):
            count = 1
            for j in range(i + 1, len(times)):
                if times[j] - times[i] <= window:
                    count += 1
                else:
                    break
            if count >= threshold:
                alerts.append({
                    "type": "POSSIBLE_PORT_SCAN",
                    "severity": "MEDIUM",
                    "source_ip": ip,
                    "count": count,
                    "description": f"{count} blocked connections from {ip} within {window_minutes} minutes"
                })
                break
    return alerts


def detect_suspicious_web_access(web_events):
    alerts = []
    risky_paths = ["/admin", "/wp-login.php", "/login"]
    for ev in web_events:
        if ev["path"] in risky_paths or ev.get("region", "") == "Unknown":
            alerts.append({
                "type": "SUSPICIOUS_WEB_ACCESS",
                "severity": "LOW",
                "ip": ev["ip"],
                "path": ev["path"],
                "status": ev["status"],
                "description": f"Suspicious access to {ev['path']} from {ev['ip']} (status {ev['status']})"
            })
    return alerts


def write_alerts(alerts):
    if not alerts:
        print("[!] No alerts generated.")
        return

    fieldnames = sorted({k for a in alerts for k in a.keys()})
    with open(ALERTS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(alert)


def write_metrics(windows_events, firewall_events, web_events, alerts):
    total_events = len(windows_events) + len(firewall_events) + len(web_events)
    by_type = Counter(a["type"] for a in alerts)
    by_severity = Counter(a["severity"] for a in alerts)

    with open(METRICS_TXT, "w", encoding="utf-8") as f:
        f.write("Mini SIEM Metrics Summary\n")
        f.write("=========================\n\n")
        f.write(f"Total events processed: {total_events}\n")
        f.write(f"- Windows security events: {len(windows_events)}\n")
        f.write(f"- Firewall events: {len(firewall_events)}\n")
        f.write(f"- Web events: {len(web_events)}\n\n")

        f.write("Alerts by type:\n")
        for t, c in by_type.items():
            f.write(f"- {t}: {c}\n")

        f.write("\nAlerts by severity:\n")
        for s, c in by_severity.items():
            f.write(f"- {s}: {c}\n")


def main():
    ensure_output_dir()

    windows_events = load_windows_logs()
    firewall_events = load_firewall_logs()
    web_events = load_web_logs()

    alerts = []
    alerts += detect_bruteforce_login(windows_events)
    alerts += detect_suspicious_success_after_fail(windows_events)
    alerts += detect_privilege_escalation(windows_events)
    alerts += detect_firewall_scans(firewall_events)
    alerts += detect_suspicious_web_access(web_events)

    write_alerts(alerts)
    write_metrics(windows_events, firewall_events, web_events, alerts)

    print(f"[+] Processed {len(windows_events)} Windows, {len(firewall_events)} firewall, {len(web_events)} web events.")
    print(f"[+] Generated {len(alerts)} alerts -> {ALERTS_CSV}")
    print(f"[+] Metrics summary -> {METRICS_TXT}")


if __name__ == "__main__":
    main()

