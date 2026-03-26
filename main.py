import sys
import argparse
from pathlib import Path

# ─── Dependency check ─────────────────────────────────────────────────────────
def check_dependencies():
    missing = []
    for pkg in ["matplotlib"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"\n  [!] Missing packages: {', '.join(missing)}")
        print(f"      Install with: pip install {' '.join(missing)}\n")
        sys.exit(1)


# ─── Log folder check ─────────────────────────────────────────────────────────
def check_logs():
    log_dir = Path(__file__).parent / "logs"
    if not log_dir.exists():
        log_dir.mkdir()
        print(f"\n  [!] logs/ folder was missing — created at {log_dir}")
        print(f"      Place your .txt log files there and re-run.\n")
        sys.exit(1)

    log_files = list(log_dir.glob("*.txt"))
    if not log_files:
        print(f"\n  [!] logs/ folder is empty.")
        print(f"      Copy your .txt log files into: {log_dir}\n")
        sys.exit(1)

    print(f"\n  Found {len(log_files)} log file(s) in logs/:")
    for f in sorted(log_files):
        size = f.stat().st_size
        print(f"    {f.name:<40} {size:>7} bytes")


# ─── Banner ───────────────────────────────────────────────────────────────────
def banner(stage=None):
    print("\n" + "█"*55)
    if stage:
        print(f"  MALWARE SANDBOX — {stage}")
    else:
        print(f"  MALWARE SANDBOX — FULL PIPELINE")
    print(f"  #12Weeks12Projects  |  Week 8")
    print("█"*55)


# ─── Individual stage runners ─────────────────────────────────────────────────
def run_analyze():
    from monitor_analysis import run
    return run()


def run_heuristics():
    from heuristics import run
    return run()


def run_visualize(analysis=None, heuristics=None):
    from visualize import run
    run(analysis, heuristics)


def run_report(analysis=None, heuristics=None):
    from report_generator import run
    return run(analysis, heuristics)


# ─── Full pipeline ────────────────────────────────────────────────────────────
def run_all():
    banner()
    check_logs()

    print("\n  Starting pipeline...\n")

    # Stage 1 — parse
    analysis_data = run_analyze()

    # Stage 2 — detect
    heuristics_data = run_heuristics()

    # Stage 3 — visualize (passes live data so no JSON re-read needed)
    run_visualize(analysis_data, heuristics_data)

    # Stage 4 — report (passes live data)
    report_path = run_report(analysis_data, heuristics_data)

    # ── Final summary ──────────────────────────────────────────────────────────
    print("\n" + "█"*55)
    print("  PIPELINE COMPLETE")
    print("█"*55)

    report_dir = Path(__file__).parent / "report"
    outputs = sorted(report_dir.iterdir()) if report_dir.exists() else []

    print(f"\n  Output files in report/:")
    for f in outputs:
        print(f"    {f.name}")

    total_alerts = heuristics_data.get("total_alerts", 0)
    sev          = heuristics_data.get("summary_by_severity", {})
    critical     = sev.get("CRITICAL", 0)
    high         = sev.get("HIGH", 0)

    print(f"\n  Alerts fired  : {total_alerts}")
    print(f"  Critical      : {critical}")
    print(f"  High          : {high}")
    print(f"\n  Report        : {report_path.name if report_path else 'see report/'}")
    print()


# ─── CLI argument parsing ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="MalwareSandbox — behavioral log analysis pipeline",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py                 # run full pipeline\n"
            "  python main.py --analyze       # parse logs only\n"
            "  python main.py --heuristics    # detection only\n"
            "  python main.py --visualize     # charts only\n"
            "  python main.py --report        # report only\n"
        )
    )

    parser.add_argument("--analyze",    action="store_true",
                        help="Stage 1 — parse log files → JSON")
    parser.add_argument("--heuristics", action="store_true",
                        help="Stage 2 — run behavioral detection → JSON")
    parser.add_argument("--visualize",  action="store_true",
                        help="Stage 3 — generate charts → PNG")
    parser.add_argument("--report",     action="store_true",
                        help="Stage 4 — compile Markdown report")

    args = parser.parse_args()

    check_dependencies()

    # If no flags given → run everything
    if not any([args.analyze, args.heuristics, args.visualize, args.report]):
        run_all()
        return

    # Individual stage mode
    if args.analyze:
        banner("STAGE 1 — LOG PARSING")
        check_logs()
        run_analyze()

    if args.heuristics:
        banner("STAGE 2 — HEURISTICS")
        check_logs()
        run_heuristics()

    if args.visualize:
        banner("STAGE 3 — VISUALIZATION")
        run_visualize()

    if args.report:
        banner("STAGE 4 — REPORT")
        run_report()


if __name__ == "__main__":
    main()
