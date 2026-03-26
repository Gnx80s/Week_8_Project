import json
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict

BASE_DIR   = Path(__file__).parent
LOG_DIR    = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "report"

C2_PORTS = {"4444", "1337", "8080", "9999", "31337", "6666", "5555"}
SEVERITY  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_alerts = []


def _setup():
    REPORT_DIR.mkdir(exist_ok=True)


def read(filename):
    path = LOG_DIR / filename
    if not path.exists():
        return ""
    return path.read_text(errors="ignore")


def alert(severity, category, description, evidence=""):
    _alerts.append({
        "severity":    severity,
        "category":    category,
        "description": description,
        "evidence":    evidence,
        "timestamp":   datetime.now().isoformat(),
    })
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🔵", "INFO": "⚪"}.get(severity, "•")
    print(f"  {icon} [{severity:<8}] [{category}] {description}")
    if evidence:
        print(f"           Evidence : {str(evidence)[:120]}")


def section(title):
    print(f"\n{'─'*55}")
    print(f"  {title}")
    print(f"{'─'*55}")


# H1 — Callback Anomaly

def check_callback():
    section("H1: Callback Anomaly Detection")

    sim = read("simulation_timeline.txt")
    for ts, desc in re.findall(r'\[(.+?)\] CALLBACK\s+(.+)', sim):
        port_m = re.search(r':(\d+)', desc)
        port   = port_m.group(1) if port_m else "unknown"
        sev    = "CRITICAL" if port in C2_PORTS else "MEDIUM"
        alert(sev, "CALLBACK",
              f"Outbound callback to {'known C2 ' if port in C2_PORTS else 'non-standard '}port {port}",
              f"[{ts}] {desc}")

    net = read("network_connection.txt")
    for ts, ip in re.findall(r'\[(.+?)\] connection attempted to ([\d.]+)', net):
        alert("HIGH", "CALLBACK",
              f"Manual connection attempt to {ip}",
              f"[{ts}]")

    kali = read("kali_received_callback.txt")
    if "listening on" in kali and len(kali.strip().splitlines()) > 1:
        alert("CRITICAL", "CALLBACK",
              "Kali listener received a connection — callback confirmed",
              kali.strip()[:120])



# H2 — Persistence

def check_persistence():
    section("H2: Persistence Mechanism Detection")

    text = read("persistence.txt")

    if "apache2.service" in text and "active running" in text:
        alert("MEDIUM", "PERSISTENCE",
              "Apache2 web server running on sandbox VM — unexpected service",
              "apache2.service loaded active running")

    if "openvpn" in text:
        alert("LOW", "PERSISTENCE",
              "OpenVPN init script present — could be used for tunneled C2",
              "/etc/init.d/openvpn")

    if "fail2ban.service" in text:
        alert("INFO", "PERSISTENCE",
              "fail2ban active — defensive measure present")

    exports = re.findall(r'^(export\s+\S+.*|alias\s+\S+=.*)', text, re.MULTILINE)
    if exports:
        alert("HIGH", "PERSISTENCE",
              f"Non-default .bashrc modifications detected ({len(exports)} lines)",
              str(exports))

    if "no crontab for vboxuser" in text:
        alert("INFO", "PERSISTENCE",
              "No user-level crontab for vboxuser — clean baseline")



# H3 — Auth Anomalies

def check_auth():
    section("H3: Auth & Privilege Escalation Detection")

    text = read("auth_log.txt")

    fails = re.findall(r'authentication failure.*?user=(\w+)', text)
    if fails:
        alert("HIGH", "AUTH",
              f"Sudo authentication failure(s): {len(fails)} attempt(s)",
              f"Users: {fails}")

    sessions = re.findall(r'(\d{2}:\d{2}:\d{2}) Ubuntu sshd.*?Accepted password', text)
    if len(sessions) >= 4:
        alert("MEDIUM", "AUTH",
              f"Rapid SSH session creation — {len(sessions)} sessions in auth log",
              f"Times: {sessions}")

    strace_sudo = re.findall(r'COMMAND=.*strace.*', text)
    if strace_sudo:
        alert("MEDIUM", "AUTH",
              "strace executed via sudo — active process inspection",
              strace_sudo[0][:120])

    tcpdump_sudo = re.findall(r'COMMAND=.*tcpdump.*', text)
    if tcpdump_sudo:
        alert("LOW", "AUTH",
              "tcpdump run via sudo — network capture activity",
              tcpdump_sudo[0][:120])

    if "System is powering down" in text:
        alert("INFO", "AUTH", "System power-down event recorded")



# H4 — Network Anomalies

def check_network():
    section("H4: Network Anomaly Detection")

    text = read("tcpdump_output.txt")

    syn_only = re.findall(r'Flags \[S\].*?length 0', text)
    if len(syn_only) > 3:
        alert("HIGH", "NETWORK",
              f"Repeated SYN with no handshake completion ({len(syn_only)} events) — possible scan",
              syn_only[0][:80])

    plain_http = re.findall(r'HTTP: (GET|POST)', text)
    if plain_http:
        alert("MEDIUM", "NETWORK",
              f"Unencrypted HTTP traffic detected ({len(plain_http)} requests)",
              str(plain_http[:3]))

    mdns_17500 = re.findall(r'192\.168\.56\.1\.17500', text)
    if len(mdns_17500) > 5:
        alert("LOW", "NETWORK",
              f"Repeated UDP broadcasts on port 17500 ({len(mdns_17500)} packets) — Dropbox LAN beacon",
              "Source: 192.168.56.1:17500 → 192.168.56.255:17500")

    ntp = re.findall(r'NTPv4', text)
    if ntp:
        alert("INFO", "NETWORK",
              f"NTP time sync traffic — {len(ntp)} packets (normal baseline)")



# H5 — UFW Firewall

def check_ufw():
    section("H5: UFW Firewall Block Analysis")

    combined = read("kernel_log.txt") + read("journal_log.txt")
    blocks   = re.findall(r'\[UFW BLOCK\] IN=(\S+).*?SRC=(\S+).*?DPT=(\d+)', combined)

    src_counts = defaultdict(int)
    for iface, src, dpt in blocks:
        src_counts[src] += 1

    total = len(blocks)
    print(f"  Total UFW blocks: {total}")

    if total > 30:
        alert("HIGH", "FIREWALL",
              f"High-volume UFW block activity — {total} packets blocked",
              str(dict(list(sorted(src_counts.items(), key=lambda x: -x[1]))[:3])))
    elif total > 10:
        alert("MEDIUM", "FIREWALL",
              f"Moderate UFW block activity — {total} packets blocked")

    kali_blocks = [(i, s, d) for i, s, d in blocks if "enp0s8" in i]
    if kali_blocks:
        alert("HIGH", "FIREWALL",
              f"UFW blocked traffic on VM host-only interface (enp0s8) — {len(kali_blocks)} packets",
              str(kali_blocks[0]))

    ssdp = [(i, s, d) for i, s, d in blocks if d in ("3702", "1900")]
    if ssdp:
        alert("MEDIUM", "FIREWALL",
              f"SSDP/UPnP discovery probes blocked — {len(ssdp)} packets",
              "Ports 3702 / 1900")



# H6 — Syscall Anomalies

def check_syscalls():
    section("H6: Syscall Pattern Analysis")

    text = read("strace_output.txt")

    if "ld.so.preload" in text:
        result = re.findall(r'ld\.so\.preload.*?=\s*(.+)', text)
        is_missing = result and "ENOENT" in result[0]
        if is_missing:
            alert("INFO", "SYSCALL",
                  "Access to /etc/ld.so.preload — file not found (clean)")
        else:
            alert("CRITICAL", "SYSCALL",
                  "ld.so.preload exists — possible library injection vector")

    if "selinux" in text.lower():
        alert("LOW", "SYSCALL",
              "SELinux config access detected — process checking security policy")

    execve = re.findall(r'execve\("([^"]+)"', text)
    if execve:
        alert("INFO", "SYSCALL",
              f"execve() called — process executed: {execve[0]}")

    tmp_opens = re.findall(r'openat.*?"/tmp/([^"]+)"', text)
    if tmp_opens:
        alert("MEDIUM", "SYSCALL",
              f"File access in /tmp via strace ({len(tmp_opens)} files)",
              str(tmp_opens))



# SUMMARY

def _summary():
    print(f"\n{'█'*55}")
    print(f"  DETECTION SUMMARY")
    print(f"{'█'*55}")

    by_sev = defaultdict(list)
    for a in _alerts:
        by_sev[a["severity"]].append(a)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = len(by_sev[sev])
        if count:
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}[sev]
            print(f"  {icon} {sev:<10} {count} alert(s)")

    print(f"\n  Total : {len(_alerts)}")

    out = {
        "timestamp":            datetime.now().isoformat(),
        "total_alerts":         len(_alerts),
        "alerts":               sorted(_alerts, key=lambda x: SEVERITY.get(x["severity"], 99)),
        "summary_by_severity":  {k: len(v) for k, v in by_sev.items()},
    }
    out_path = REPORT_DIR / f"heuristics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"\n  [✓] Heuristics JSON → {out_path.name}")
    return out


# ENTRY POINT

def run():
    """Run all detection heuristics and return the alerts dict."""
    _setup()
    _alerts.clear()

    print("\n" + "█"*55)
    print("  STAGE 2 — BEHAVIORAL HEURISTICS")
    print("█"*55)

    check_callback()
    check_persistence()
    check_auth()
    check_network()
    check_ufw()
    check_syscalls()
    return _summary()


if __name__ == "__main__":
    run()
