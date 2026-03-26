import re
import json
import matplotlib
matplotlib.use("Agg")   # headless — no display needed
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path
from datetime import datetime
from collections import defaultdict

BASE_DIR   = Path(__file__).parent
LOG_DIR    = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "report"

PALETTE = {
    "red":    "#E24B4A",
    "orange": "#EF9F27",
    "teal":   "#1D9E75",
    "blue":   "#378ADD",
    "gray":   "#888780",
    "purple": "#7F77DD",
    "bg":     "#F5F4F0",
    "text":   "#2C2C2A",
}


def _setup():
    REPORT_DIR.mkdir(exist_ok=True)


def read(filename):
    path = LOG_DIR / filename
    if not path.exists():
        return ""
    return path.read_text(errors="ignore")


def _latest_json(prefix):
    files = sorted(REPORT_DIR.glob(f"{prefix}_*.json"))
    return json.loads(files[-1].read_text()) if files else {}


def style_ax(ax, title):
    ax.set_facecolor(PALETTE["bg"])
    ax.set_title(title, fontsize=12, fontweight="bold",
                 color=PALETTE["text"], pad=10)
    ax.tick_params(colors=PALETTE["text"], labelsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines[["left", "bottom"]].set_color("#D3D1C7")


def save(fig, name):
    path = REPORT_DIR / name
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    plt.close(fig)
    print(f"  [✓] {name}")


# ─── Chart 1: Activity Overview ───────────────────────────────────────────────
def chart_activity_overview():
    auth   = read("auth_log.txt")
    net    = read("network_connection.txt")
    kernel = read("kernel_log.txt")
    jrnl   = read("journal_log.txt")
    sim    = read("simulation_timeline.txt")

    data = {
        "SSH Sessions":  len(re.findall(r"Accepted password", auth)),
        "Sudo Commands": len(re.findall(r"sudo:.*COMMAND=", auth)),
        "Sudo Failures": len(re.findall(r"authentication failure", auth)),
        "UFW Blocks":    len(re.findall(r"\[UFW BLOCK\]", kernel + jrnl)),
        "Net Attempts":  len(re.findall(r"connection attempted", net)),
        "Sim Events":    len(re.findall(r"\[\d{4}-\d{2}-\d{2}", sim)),
    }

    colors = [PALETTE["blue"], PALETTE["teal"], PALETTE["red"],
              PALETTE["orange"], PALETTE["purple"], PALETTE["gray"]]

    fig, ax = plt.subplots(figsize=(9, 4.5), facecolor=PALETTE["bg"])
    bars = ax.bar(data.keys(), data.values(), color=colors,
                  width=0.6, edgecolor="none")
    for bar, val in zip(bars, data.values()):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
                str(val), ha="center", va="bottom",
                fontsize=10, fontweight="bold", color=PALETTE["text"])

    ax.set_ylabel("Event Count", color=PALETTE["text"], fontsize=10)
    ax.set_xticklabels(data.keys(), rotation=15, ha="right")
    style_ax(ax, "Sandbox Activity Overview")
    fig.tight_layout()
    save(fig, "chart_activity_overview.png")


# ─── Chart 2: UFW Block Sources ───────────────────────────────────────────────
def chart_ufw_sources():
    combined = read("kernel_log.txt") + read("journal_log.txt")
    blocks   = re.findall(r'\[UFW BLOCK\].*?SRC=(\S+)', combined)

    src_counts = defaultdict(int)
    for src in blocks:
        label = src[:30] + "…" if len(src) > 30 else src
        src_counts[label] += 1

    if not src_counts:
        print("  [!] No UFW blocks — skipping chart.")
        return

    top    = sorted(src_counts.items(), key=lambda x: -x[1])[:8]
    labels, counts = zip(*top)

    fig, ax = plt.subplots(figsize=(9, 4.5), facecolor=PALETTE["bg"])
    ax.barh(labels, counts, color=PALETTE["orange"], edgecolor="none")
    for i, val in enumerate(counts):
        ax.text(val + 0.1, i, str(val), va="center",
                fontsize=9, color=PALETTE["text"])

    ax.set_xlabel("Block Count", color=PALETTE["text"], fontsize=10)
    ax.invert_yaxis()
    style_ax(ax, "Top UFW Blocked Sources")
    fig.tight_layout()
    save(fig, "chart_ufw_sources.png")


# ─── Chart 3: Protocol Breakdown ──────────────────────────────────────────────
def chart_protocols():
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

    if not protocols:
        print("  [!] No protocol data — skipping chart.")
        return

    sorted_p = dict(sorted(protocols.items(), key=lambda x: -x[1]))
    colors   = [PALETTE["blue"], PALETTE["teal"], PALETTE["orange"],
                PALETTE["purple"], PALETTE["red"], PALETTE["gray"],
                "#5DCAA5", "#D4537E"][:len(sorted_p)]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5),
                                    facecolor=PALETTE["bg"])

    wedges, texts, autotexts = ax1.pie(
        sorted_p.values(), labels=sorted_p.keys(), colors=colors,
        autopct="%1.0f%%", startangle=140,
        textprops={"fontsize": 9, "color": PALETTE["text"]},
        wedgeprops={"edgecolor": PALETTE["bg"], "linewidth": 1.5}
    )
    for at in autotexts:
        at.set_fontsize(8)
        at.set_color(PALETTE["bg"])
    ax1.set_title("Protocol Share", fontsize=12, fontweight="bold",
                  color=PALETTE["text"], pad=10)

    ax2.bar(sorted_p.keys(), sorted_p.values(),
            color=colors, edgecolor="none", width=0.6)
    for i, (k, v) in enumerate(sorted_p.items()):
        ax2.text(i, v + 0.2, str(v), ha="center", va="bottom",
                 fontsize=9, color=PALETTE["text"])
    ax2.set_xticklabels(sorted_p.keys(), rotation=20, ha="right")
    style_ax(ax2, "Protocol Packet Counts")

    fig.suptitle("Network Traffic Protocol Breakdown", fontsize=13,
                 fontweight="bold", color=PALETTE["text"], y=1.01)
    fig.tight_layout()
    save(fig, "chart_protocols.png")


# ─── Chart 4: SSH Session Timeline ────────────────────────────────────────────
def chart_ssh_timeline():
    text     = read("auth_log.txt")
    sessions = re.findall(
        r'(\d{2}:\d{2}:\d{2}) Ubuntu sshd.*?Accepted password for (\w+) from ([\d.]+)', text
    )
    if not sessions:
        print("  [!] No SSH sessions — skipping chart.")
        return

    def to_min(t):
        h, m, s = map(int, t.split(":"))
        return h * 60 + m + s / 60

    times = [to_min(ts) for ts, _, _ in sessions]
    users = [u for _, u, _ in sessions]
    ips   = [ip for _, _, ip in sessions]

    fig, ax = plt.subplots(figsize=(9, 3.5), facecolor=PALETTE["bg"])
    ax.scatter(times, [1]*len(times), s=120, color=PALETTE["blue"],
               zorder=3, edgecolors=PALETTE["bg"], linewidths=1.5)

    for t, user, ip in zip(times, users, ips):
        ax.annotate(f"{user}\n{ip}", (t, 1),
                    textcoords="offset points", xytext=(0, 14),
                    ha="center", fontsize=7.5, color=PALETTE["text"])

    ax.set_xlabel("Time (minutes past midnight)", color=PALETTE["text"], fontsize=10)
    ax.set_yticks([])
    ax.set_ylim(0.5, 1.8)
    style_ax(ax, f"SSH Login Events  ({len(sessions)} sessions)")
    fig.tight_layout()
    save(fig, "chart_ssh_timeline.png")


# ─── Chart 5: Alert Severity ──────────────────────────────────────────────────
def chart_alert_severity(heuristics_data=None):
    data = heuristics_data or _latest_json("heuristics")
    summary = data.get("summary_by_severity", {})
    if not summary:
        print("  [!] No heuristics data — skipping chart.")
        return

    order      = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_colors = {
        "CRITICAL": PALETTE["red"],
        "HIGH":     PALETTE["orange"],
        "MEDIUM":   "#EF9F27",
        "LOW":      PALETTE["blue"],
        "INFO":     PALETTE["gray"],
    }
    labels = [s for s in order if s in summary]
    counts = [summary[s] for s in labels]
    colors = [sev_colors[s] for s in labels]

    fig, ax = plt.subplots(figsize=(7, 4), facecolor=PALETTE["bg"])
    bars = ax.bar(labels, counts, color=colors, width=0.5, edgecolor="none")
    for bar, val in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                str(val), ha="center", va="bottom",
                fontsize=11, fontweight="bold", color=PALETTE["text"])

    ax.set_ylabel("Alert Count", color=PALETTE["text"], fontsize=10)
    style_ax(ax, f"Behavioral Alerts by Severity  (total: {sum(counts)})")
    fig.tight_layout()
    save(fig, "chart_alert_severity.png")


# ─── Chart 6: Top Processes by CPU ────────────────────────────────────────────
def chart_top_processes():
    text  = read("processes.txt")
    procs = re.findall(
        r'^(\S+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)',
        text, re.MULTILINE
    )
    user_procs = [
        (cmd.strip()[:30], float(cpu))
        for user, pid, cpu, mem, cmd in procs
        if int(pid) > 100 and float(cpu) > 0
    ]
    user_procs.sort(key=lambda x: -x[1])
    top = user_procs[:10]

    if not top:
        print("  [!] No active user processes — skipping chart.")
        return

    names, cpus = zip(*top)
    colors = [PALETTE["purple"] if cpu > 1.0 else PALETTE["teal"] for cpu in cpus]

    fig, ax = plt.subplots(figsize=(9, 4.5), facecolor=PALETTE["bg"])
    ax.barh(names, cpus, color=colors, edgecolor="none")
    for i, val in enumerate(cpus):
        ax.text(val + 0.01, i, f"{val:.1f}%", va="center",
                fontsize=9, color=PALETTE["text"])

    ax.set_xlabel("CPU %", color=PALETTE["text"], fontsize=10)
    ax.invert_yaxis()
    legend = [
        mpatches.Patch(color=PALETTE["purple"], label=">1% CPU"),
        mpatches.Patch(color=PALETTE["teal"],   label="≤1% CPU"),
    ]
    ax.legend(handles=legend, fontsize=9, loc="lower right")
    style_ax(ax, "Top Processes by CPU Usage")
    fig.tight_layout()
    save(fig, "chart_top_processes.png")


# ENTRY POINT

def run(analysis_data=None, heuristics_data=None):
    """Generate all charts. Pass data dicts from previous stages or reads JSON from disk."""
    _setup()
    print("\n" + "█"*55)
    print("  STAGE 3 — VISUALIZATION")
    print("█"*55 + "\n")

    chart_activity_overview()
    chart_ufw_sources()
    chart_protocols()
    chart_ssh_timeline()
    chart_alert_severity(heuristics_data)
    chart_top_processes()

    print(f"\n  All charts saved to report/")


if __name__ == "__main__":
    run()
