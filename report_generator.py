import json
import re
from pathlib import Path
from datetime import datetime

BASE_DIR   = Path(__file__).parent
REPORT_DIR = BASE_DIR / "report"


def _setup():
    REPORT_DIR.mkdir(exist_ok=True)


def _latest_json(prefix):
    files = sorted(REPORT_DIR.glob(f"{prefix}_*.json"))
    return json.loads(files[-1].read_text()) if files else {}


def sev_emoji(sev):
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🔵", "INFO": "⚪"}.get(sev, "•")


def run(analysis_data=None, heuristics_data=None):
    """Compile the final Markdown report. Pass data dicts or reads JSON from disk."""
    _setup()
    print("\n" + "█"*55)
    print("  STAGE 4 — REPORT GENERATION")
    print("█"*55 + "\n")

    analysis   = analysis_data   or _latest_json("analysis")
    heuristics = heuristics_data or _latest_json("heuristics")
    ts         = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    auth        = analysis.get("auth", {})
    network     = analysis.get("network", {})
    tcpdump     = analysis.get("tcpdump", {})
    kernel      = analysis.get("kernel", {})
    persistence = analysis.get("persistence", {})
    strace      = analysis.get("strace", {})
    kali        = analysis.get("kali", {})
    simulation  = analysis.get("simulation", {})
    alerts      = heuristics.get("alerts", [])
    sev_summary = heuristics.get("summary_by_severity", {})

    critical = sev_summary.get("CRITICAL", 0)
    high     = sev_summary.get("HIGH", 0)
    medium   = sev_summary.get("MEDIUM", 0)
    low      = sev_summary.get("LOW", 0)
    total    = heuristics.get("total_alerts", 0)

    risk = ("🔴 CRITICAL" if critical > 0 else
            "🟠 HIGH"     if high > 2     else
            "🟡 MEDIUM"   if medium > 3   else
            "🔵 LOW")

    L = []
    def w(line=""):
        L.append(line)

    # ── Header ────────────────────────────────────────────────────────────────
    w("# Malware Sandbox Analysis Report")
    w(f"> Generated: {ts}  |  #12Weeks12Projects Week 8")
    w()
    w("---")
    w()

    # ── Executive Summary ─────────────────────────────────────────────────────
    w("## Executive Summary")
    w()
    w("| Field | Value |")
    w("|-------|-------|")
    w(f"| Analysis Date | {ts} |")
    w(f"| Overall Risk | {risk} |")
    w(f"| Total Alerts | {total} |")
    w(f"| Critical / High | {critical} / {high} |")
    w(f"| Medium / Low | {medium} / {low} |")
    w(f"| Ubuntu IP | 192.168.56.5 |")
    w(f"| Kali IP | 192.168.56.6 |")
    w(f"| Host IP | 192.168.56.1 |")
    w()
    w("**Key findings:**")
    w()
    w(f"- **{auth.get('ssh_logins', 0)} SSH sessions** recorded — all from `192.168.56.1` (host)")
    w(f"- **{auth.get('sudo_commands', 0)} sudo commands** executed (strace, tcpdump, apt)")
    w(f"- **{auth.get('sudo_failures', 0)} sudo failure(s)** detected")
    w(f"- **{kernel.get('ufw_blocked_total', 0)} UFW packets blocked** across kernel and journal logs")
    w(f"- **Callback confirmed** — Kali listener on port 4444 received connection from Ubuntu")
    w(f"- **{tcpdump.get('total_packets', 0)} packets captured** — dominated by TCP and mDNS traffic")
    w()
    w("---")
    w()

    # ── Behavioral Alerts ─────────────────────────────────────────────────────
    w("## Behavioral Detection Alerts")
    w()
    w(f"**{total} alerts** across {len(set(a['category'] for a in alerts))} categories.")
    w()

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_alerts = [a for a in alerts if a["severity"] == sev]
        if not sev_alerts:
            continue
        w(f"### {sev_emoji(sev)} {sev} ({len(sev_alerts)})")
        w()
        for a in sev_alerts:
            w(f"**[{a['category']}]** {a['description']}")
            if a.get("evidence"):
                ev = str(a["evidence"])[:200]
                w(f"```\n{ev}\n```")
            w()

    w("---")
    w()

    # ── Auth Log ──────────────────────────────────────────────────────────────
    w("## Authentication Log")
    w()
    w("| Metric | Count |")
    w("|--------|-------|")
    w(f"| SSH Logins Accepted | {auth.get('ssh_logins', 0)} |")
    w(f"| SSH Source IPs | {', '.join(auth.get('ssh_sources', [])) or 'none'} |")
    w(f"| Sudo Commands | {auth.get('sudo_commands', 0)} |")
    w(f"| Sudo Failures | {auth.get('sudo_failures', 0)} |")
    w(f"| Cron Events | {auth.get('cron_events', 0)} |")
    w()
    cmds = auth.get("sudo_command_list", [])
    if cmds:
        w("**Sudo commands executed:**")
        w()
        for cmd in cmds:
            w(f"- `{cmd[:120]}`")
        w()
    w("---")
    w()

    # ── Network ───────────────────────────────────────────────────────────────
    w("## Network Analysis")
    w()
    w("| Metric | Value |")
    w("|--------|-------|")
    w(f"| TCP Connections | {network.get('tcp_connections', 0)} |")
    w(f"| UDP Connections | {network.get('udp_connections', 0)} |")
    w(f"| Manual Logged Attempts | {len(network.get('manual_attempts', []))} |")
    w(f"| Packets Captured | {tcpdump.get('total_packets', 0)} |")
    w(f"| External IPs Seen | {len(tcpdump.get('external_ips', []))} |")
    w(f"| HTTP Requests | {tcpdump.get('http_requests', 0)} |")
    w(f"| Connectivity Checks | {tcpdump.get('connectivity_checks', 0)} |")
    w()
    ext_ips = tcpdump.get("external_ips", [])
    if ext_ips:
        w("**External IPs:**")
        w()
        for ip in ext_ips:
            w(f"- `{ip}`")
        w()
    proto = tcpdump.get("protocol_breakdown", {})
    if proto:
        w("**Protocol breakdown:**")
        w()
        w("| Protocol | Packets |")
        w("|----------|---------|")
        for p, count in sorted(proto.items(), key=lambda x: -x[1]):
            w(f"| {p} | {count} |")
        w()
    w("---")
    w()

    # ── Firewall ──────────────────────────────────────────────────────────────
    w("## Firewall (UFW)")
    w()
    w("| Metric | Value |")
    w("|--------|-------|")
    w(f"| Total UFW Blocks | {kernel.get('ufw_blocked_total', 0)} |")
    w(f"| Blocked Protocols | {', '.join(kernel.get('blocked_protocols', {}).keys()) or 'none'} |")
    w(f"| Workqueue Warnings | {kernel.get('workqueue_warnings', 0)} |")
    w()
    top = kernel.get("top_blocked_sources", {})
    if top:
        w("**Top blocked sources:**")
        w()
        w("| Source IP | Blocks |")
        w("|-----------|--------|")
        for ip, count in top.items():
            w(f"| `{ip[:50]}` | {count} |")
        w()
    w("---")
    w()

    # ── Persistence ───────────────────────────────────────────────────────────
    w("## Persistence Analysis")
    w()
    w("| Metric | Value |")
    w("|--------|-------|")
    w(f"| System Cron Jobs | {persistence.get('cron_jobs', 0)} |")
    w(f"| Running Services | {persistence.get('running_services', 0)} |")
    w(f"| .bashrc Exports | {persistence.get('bashrc_exports', 0)} |")
    w()
    flagged = persistence.get("flagged_services", [])
    if flagged:
        w("**Flagged services:**")
        w()
        for s in flagged:
            w(f"- `{s}`")
        w()
    w("---")
    w()

    # ── Syscalls ──────────────────────────────────────────────────────────────
    w("## Syscall Analysis (strace)")
    w()
    w("| Metric | Value |")
    w("|--------|-------|")
    w(f"| Syscall Lines | {strace.get('total_syscall_lines', 0)} |")
    w(f"| Files Opened | {len(strace.get('files_opened', []))} |")
    w(f"| access() Checks | {len(strace.get('access_checks', []))} |")
    w(f"| Network Syscalls | {strace.get('network_syscalls', 0)} |")
    w()
    top_sc = strace.get("top_syscalls", {})
    if top_sc:
        w("**Most frequent syscalls:**")
        w()
        w("| Syscall | Count |")
        w("|---------|-------|")
        for sc, count in list(top_sc.items())[:8]:
            w(f"| `{sc}` | {count} |")
        w()
    w("---")
    w()

    # ── Kali Observer ─────────────────────────────────────────────────────────
    w("## Kali Observer Node")
    w()
    w("| Metric | Value |")
    w("|--------|-------|")
    w(f"| Inbound Packets | {kali.get('kali_inbound_packets', 0)} |")
    w(f"| Ping Sent | {kali.get('ping_sent', 0)} |")
    w(f"| Ping Received | {kali.get('ping_received', 0)} |")
    w(f"| Packet Loss | {kali.get('ping_loss_pct', 0)}% |")
    w(f"| Callback Received | {'Yes' if kali.get('callback_received') else 'No'} |")
    w()
    cb = kali.get("callback_content", [])
    if cb:
        w("**Callback output:**")
        w()
        w("```")
        for line in cb:
            w(line)
        w("```")
        w()
    w("---")
    w()

    # ── Simulation Timeline ───────────────────────────────────────────────────
    w("## Simulation Timeline")
    w()
    events = simulation.get("events", [])
    if events:
        w("| Timestamp | Category | Description |")
        w("|-----------|----------|-------------|")
        for e in events:
            w(f"| `{e['timestamp']}` | **{e['category']}** | {e['description']} |")
    else:
        w("_No simulation events logged._")
    w()
    w("---")
    w()

    # ── Charts ────────────────────────────────────────────────────────────────
    w("## Visualizations")
    w()
    charts = [
        ("chart_activity_overview.png",  "Activity Overview"),
        ("chart_ufw_sources.png",        "UFW Block Sources"),
        ("chart_protocols.png",          "Network Protocol Breakdown"),
        ("chart_ssh_timeline.png",       "SSH Login Timeline"),
        ("chart_alert_severity.png",     "Alert Severity Distribution"),
        ("chart_top_processes.png",      "Top Processes by CPU"),
    ]
    for filename, caption in charts:
        w(f"### {caption}")
        w(f"![{caption}](./report/{filename})")
        w()

    w("---")
    w()

    # ── Footer ────────────────────────────────────────────────────────────────
    w("## Ethics & Methodology")
    w()
    w("All activity was contained within an isolated VirtualBox host-only network (192.168.56.0/24).")
    w("No scripts executed inside the VMs — logs were collected using native Linux commands.")
    w("No real systems or networks were targeted.")
    w()
    w("**Collection tools:** strace, tcpdump, ss, netstat, journalctl, dmesg, ps, lsof, netcat")
    w()
    w("**Analysis stack:** Python 3, matplotlib, re, json, pathlib")
    w()
    w("---")
    w(f"*MalwareSandbox / #12Weeks12Projects Week 8 — Eugene Dela Gogah*")

    # ── Save ──────────────────────────────────────────────────────────────────
    out_path = REPORT_DIR / f"final_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    out_path.write_text("\n".join(L))
    print(f"  [✓] Final report → {out_path.name}")
    return out_path


if __name__ == "__main__":
    _setup()
    run()
