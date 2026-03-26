import re
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ─── Paths — always relative to this file's location ─────────────────────────
BASE_DIR   = Path(__file__).parent
LOG_DIR    = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "report"


def _setup():
    REPORT_DIR.mkdir(exist_ok=True)
    if not LOG_DIR.exists():
        LOG_DIR.mkdir(exist_ok=True)
        print(f"  [!] Created logs/ at {LOG_DIR}")
        print(f"      Place your .txt log files there and re-run.")


def read(filename):
    path = LOG_DIR / filename
    if not path.exists():
        print(f"  [!] Missing: {filename}")
        return ""
    return path.read_text(errors="ignore")


def section(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


# 1. AUTH LOG

def parse_auth_log():
    section("AUTH LOG ANALYSIS")
    text = read("auth_log.txt")

    ssh_accept  = re.findall(r"Accepted password for (\w+) from ([\d.]+) port (\d+)", text)
    sudo_cmds   = re.findall(r"sudo:.*?USER=(\w+).*?COMMAND=(.+)", text)
    sudo_fail   = re.findall(r"authentication failure.*?user=(\w+)", text)
    cron_events = re.findall(r"CRON\[(\d+)\].*?session (opened|closed) for user (\w+)", text)

    print(f"\n  SSH Accepted Logins    : {len(ssh_accept)}")
    for user, ip, port in ssh_accept:
        print(f"    → {user} from {ip}:{port}")
    print(f"\n  Sudo Commands          : {len(sudo_cmds)}")
    for user, cmd in sudo_cmds:
        print(f"    → [{user}] {cmd.strip()[:100]}")
    print(f"\n  Sudo Failures          : {len(sudo_fail)}")
    for user in sudo_fail:
        print(f"    → user: {user}")
    print(f"\n  Cron Events            : {len(cron_events)}")

    return {
        "ssh_logins": len(ssh_accept),
        "ssh_sources": list({ip for _, ip, _ in ssh_accept}),
        "sudo_commands": len(sudo_cmds),
        "sudo_failures": len(sudo_fail),
        "sudo_command_list": [cmd.strip() for _, cmd in sudo_cmds],
        "cron_events": len(cron_events),
    }


# 2. NETWORK CONNECTIONS

def parse_network():
    section("NETWORK CONNECTIONS")
    text = read("network_connection.txt")

    tcp_conns = re.findall(
        r"tcp\s+\d+\s+\d+\s+([\d.]+):(\d+)\s+([\d.]+):(\d+)\s+(\w+)", text
    )
    udp_conns = re.findall(
        r"udp\s+\w+\s+\d+\s+\d+\s+([\S]+):(\d+)\s+([\S]+):(\d+)", text
    )
    manual = re.findall(
        r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] connection attempted to ([\d.]+)", text
    )

    print(f"\n  TCP Connections        : {len(tcp_conns)}")
    for la, lp, ra, rp, state in tcp_conns:
        print(f"    → {la}:{lp} → {ra}:{rp}  [{state}]")
    print(f"\n  UDP Connections        : {len(udp_conns)}")
    print(f"\n  Manual Logged Attempts : {len(manual)}")
    for ts, ip in manual:
        print(f"    → [{ts}] → {ip}")

    return {
        "tcp_connections": len(tcp_conns),
        "tcp_details": [{"local": f"{la}:{lp}", "remote": f"{ra}:{rp}", "state": s}
                        for la, lp, ra, rp, s in tcp_conns],
        "udp_connections": len(udp_conns),
        "manual_attempts": [{"timestamp": ts, "target": ip} for ts, ip in manual],
    }


# 3. TCPDUMP ANALYSIS
def parse_tcpdump():
    section("TCPDUMP TRAFFIC ANALYSIS")
    text  = read("tcpdump_output.txt")
    lines = [l for l in text.splitlines() if l.strip()]

    protocols = defaultdict(int)
    for line in lines:
        if "NTPv4"   in line: protocols["NTP"]    += 1
        elif "HTTP"  in line: protocols["HTTP"]   += 1
        elif "53:"   in line: protocols["DNS"]    += 1
        elif "ARP"   in line: protocols["ARP"]    += 1
        elif "ICMP6" in line: protocols["ICMPv6"] += 1
        elif "5353"  in line: protocols["mDNS"]   += 1
        elif "UDP"   in line: protocols["UDP"]    += 1
        elif "Flags" in line: protocols["TCP"]    += 1

    all_ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
    external_ips = sorted({
        ip for ip in all_ips
        if not ip.startswith("127.") and not ip.startswith("10.")
        and not ip.startswith("192.168.") and not ip.startswith("0.")
    })
    http_reqs   = re.findall(r'HTTP: (GET|POST|PUT|DELETE) (\S+)', text)
    conn_checks = re.findall(r'connectivity-check\.ubuntu\.com', text)

    print(f"\n  Total Packets          : {len(lines)}")
    print(f"\n  Protocol Breakdown:")
    for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
        print(f"    {proto:<10} {count}")
    print(f"\n  External IPs           : {len(external_ips)}")
    for ip in external_ips:
        print(f"    → {ip}")
    print(f"\n  HTTP Requests          : {len(http_reqs)}")
    print(f"\n  Connectivity Checks    : {len(conn_checks)}")

    return {
        "total_packets": len(lines),
        "protocol_breakdown": dict(protocols),
        "external_ips": external_ips,
        "http_requests": len(http_reqs),
        "connectivity_checks": len(conn_checks),
    }


# 4. KERNEL LOG
def parse_kernel():
    section("KERNEL LOG ANALYSIS")
    text = read("kernel_log.txt")

    ufw_blocks = re.findall(
        r'\[UFW BLOCK\] IN=(\S+).*?SRC=(\S+).*?DST=(\S+).*?PROTO=(\w+).*?SPT=(\d+) DPT=(\d+)', text
    )
    workqueue_warns = re.findall(r'workqueue:.*?hogged CPU', text)

    src_counts   = defaultdict(int)
    proto_counts = defaultdict(int)
    dpt_counts   = defaultdict(int)
    for iface, src, dst, proto, spt, dpt in ufw_blocks:
        src_counts[src]     += 1
        proto_counts[proto] += 1
        dpt_counts[dpt]     += 1

    print(f"\n  UFW Blocked Packets    : {len(ufw_blocks)}")
    print(f"\n  Top Blocked Sources:")
    for ip, count in sorted(src_counts.items(), key=lambda x: -x[1])[:5]:
        print(f"    → {ip:<45} x{count}")
    print(f"\n  Blocked Protocols      : {dict(proto_counts)}")
    print(f"\n  Workqueue Warnings     : {len(workqueue_warns)}")

    return {
        "ufw_blocked_total": len(ufw_blocks),
        "top_blocked_sources": dict(sorted(src_counts.items(), key=lambda x: -x[1])[:5]),
        "blocked_protocols": dict(proto_counts),
        "blocked_ports": dict(dpt_counts),
        "workqueue_warnings": len(workqueue_warns),
    }


#  5. PERSISTENCE
def parse_persistence():
    section("PERSISTENCE ANALYSIS")
    text = read("persistence.txt")

    cron_jobs        = re.findall(r'^[\d\*].+root.+', text, re.MULTILINE)
    running_services = re.findall(r'(\S+\.service)\s+loaded active running (.+)', text)
    suspicious       = ["apache2.service", "openvpn"]
    flagged          = [s for s, _ in running_services if any(x in s for x in suspicious)]
    bashrc_exports   = re.findall(r'^export\s+\S+', text, re.MULTILINE)

    print(f"\n  System Cron Jobs       : {len(cron_jobs)}")
    print(f"\n  Running Services       : {len(running_services)}")
    print(f"\n  Flagged Services       : {len(flagged)}")
    for s in flagged:
        print(f"    [!] {s}")
    print(f"\n  .bashrc Exports        : {len(bashrc_exports)}")

    return {
        "cron_jobs": len(cron_jobs),
        "running_services": len(running_services),
        "flagged_services": flagged,
        "bashrc_exports": len(bashrc_exports),
    }


#  6. STRACE
def parse_strace():
    section("STRACE SYSCALL ANALYSIS")
    text  = read("strace_output.txt")
    lines = [l for l in text.splitlines() if l.strip() and not l.startswith("+++")]

    syscall_names  = re.findall(r'^(\w+)\(', text, re.MULTILINE)
    syscall_counts = defaultdict(int)
    for s in syscall_names:
        syscall_counts[s] += 1

    file_opens    = re.findall(r'openat\(.*?"([^"]+)"', text)
    access_checks = re.findall(r'access\("([^"]+)"', text)
    net_calls     = re.findall(r'(socket|connect|bind|sendto|recvfrom)\(', text)

    print(f"\n  Total Syscall Lines    : {len(lines)}")
    print(f"\n  Top Syscalls:")
    for sc, count in sorted(syscall_counts.items(), key=lambda x: -x[1])[:8]:
        print(f"    {sc:<20} {count}")
    print(f"\n  Files Opened           : {len(file_opens)}")
    print(f"\n  Access() Checks        : {len(access_checks)}")
    print(f"\n  Network Syscalls       : {len(net_calls)}")

    return {
        "total_syscall_lines": len(lines),
        "top_syscalls": dict(sorted(syscall_counts.items(), key=lambda x: -x[1])[:8]),
        "files_opened": file_opens,
        "access_checks": access_checks,
        "network_syscalls": len(net_calls),
    }



# 7. JOURNAL LOG
def parse_journal():
    section("JOURNAL LOG ANALYSIS")
    text = read("journal_log.txt")

    ufw_blocks     = re.findall(r'\[UFW BLOCK\].*?SRC=(\S+).*?DPT=(\d+)', text)
    service_starts = re.findall(r'Started (.+?)\.', text)
    service_stops  = re.findall(r'Deactivated successfully', text)
    bpf_loads      = re.findall(r'BPF prog-id=(\d+) op=LOAD', text)

    print(f"\n  UFW Blocks             : {len(ufw_blocks)}")
    print(f"\n  Service Starts         : {len(service_starts)}")
    print(f"\n  Service Stops          : {len(service_stops)}")
    print(f"\n  BPF Program Loads      : {len(bpf_loads)}")

    return {
        "ufw_blocks_journal": len(ufw_blocks),
        "service_starts": len(service_starts),
        "service_stops": len(service_stops),
        "bpf_loads": len(bpf_loads),
    }



# 8. KALI LOGS

def parse_kali():
    section("KALI OBSERVER LOGS")

    inbound       = read("kali_inbound_traffic.txt")
    inbound_lines = [l for l in inbound.splitlines() if l.strip()]

    ping       = read("kali_ping_ubuntu.txt")
    ping_stats = re.search(r'(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss', ping)
    rtt        = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', ping)

    callback    = read("kali_received_callback.txt")
    cb_received = "listening on" in callback
    cb_lines    = callback.strip().splitlines()

    print(f"\n  Kali Inbound Packets   : {len(inbound_lines)}")
    if ping_stats:
        sent, recv, loss = ping_stats.groups()
        print(f"\n  Ping Ubuntu ← Kali     : sent={sent}  recv={recv}  loss={loss}%")
    if rtt:
        print(f"  RTT                    : min={rtt.group(1)}ms  avg={rtt.group(2)}ms  max={rtt.group(3)}ms")
    print(f"\n  Callback Received      : {cb_received}")
    for line in cb_lines:
        print(f"    {line}")

    return {
        "kali_inbound_packets": len(inbound_lines),
        "ping_sent":      int(ping_stats.group(1))   if ping_stats else 0,
        "ping_received":  int(ping_stats.group(2))   if ping_stats else 0,
        "ping_loss_pct":  float(ping_stats.group(3)) if ping_stats else None,
        "callback_received": cb_received,
        "callback_content":  cb_lines,
    }



# 9. SIMULATION TIMELINE

def parse_simulation():
    section("SIMULATION TIMELINE")
    text   = read("simulation_timeline.txt")
    events = re.findall(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (\w+)\s+(.+)', text)

    print(f"\n  Simulated Events       : {len(events)}")
    for ts, cat, desc in events:
        print(f"    [{ts}] {cat:<12} {desc}")

    categories = defaultdict(int)
    for _, cat, _ in events:
        categories[cat] += 1

    return {
        "total_events": len(events),
        "events": [{"timestamp": ts, "category": cat, "description": desc}
                   for ts, cat, desc in events],
        "category_counts": dict(categories),
    }


# ENTRY POINT

def run():
    """Run all parsers and return the combined results dict."""
    _setup()
    print("\n" + "█"*55)
    print("  STAGE 1 — LOG PARSING")
    print("█"*55)

    results = {
        "timestamp":   datetime.now().isoformat(),
        "auth":        parse_auth_log(),
        "network":     parse_network(),
        "tcpdump":     parse_tcpdump(),
        "kernel":      parse_kernel(),
        "persistence": parse_persistence(),
        "strace":      parse_strace(),
        "journal":     parse_journal(),
        "kali":        parse_kali(),
        "simulation":  parse_simulation(),
    }

    out_path = REPORT_DIR / f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\n  [✓] Analysis JSON → {out_path.name}")
    return results


if __name__ == "__main__":
    run()
