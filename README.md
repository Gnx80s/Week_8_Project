## Malware Sandbox Project

MalwareSandbox is a controlled security analysis project designed to simulate and study malicious system behavior within isolated VirtualBox virtual machine
System and network logs are collected manually inside the virtual machines and analyzed on a host machine using a Python-based behavioral analysis framework

### Core Philosophy

- Virtual machines act as controlled data sources (manual simulation only)
- Host machine serves as the analysis environment

### Objectives

- Implement Python-based log parsing and monitoring
- Detect suspicious behavior using heuristic-based analysis
- Visualize system and network activity through structured charts
- Maintain safe and ethical malware analysis practices in isolated environments

---

## Requirements

- Python 3.x
- VirtualBox
- Linux virtual machines (e.g., Ubuntu 22.04, Kali Linux)
- Basic familiarity with system and network logging tools

---

## Install Dependencies

Only one external dependency is required:

```bash
pip install matplotlib
```

---

## How It Works

The system follows a four-stage pipeline:

1. Log Parsing
   Raw `.txt` log files are parsed into structured JSON format

2. Behavioral Detection
   Heuristic rules analyze logs for suspicious patterns

3. Visualization
   Data is converted into charts using matplotlib

4. Report Generation
   A final Markdown report is compiled with findings

---

## Usage

### Run Full Pipeline

```bash
python main.py
```

### Run Individual Stages

```bash
python main.py --analyze
python main.py --heuristics
python main.py --visualize
python main.py --report
```

### Run Modules Independently

```bash
python monitor_analysis.py
python heuristics.py
python visualize.py
python report_generator.py
```

All outputs are saved in the `report/` directory.

---

## Detection Heuristics

The system applies the following detection rules:

| ID  | Description                                             | Severity    |
| --- | ------------------------------------------------------- | ----------- |
| H1  | Outbound callback to common command-and-control ports   | 🔴 Critical |
| H2  | Persistence mechanisms (e.g., `.bashrc`, services)      | 🟠 High     |
| H3  | Authentication anomalies (failed sudo or SSH attempts)  | 🟠 High     |
| H4  | SYN scan patterns without handshake completion          | 🟠 High     |
| H5  | High volume of firewall (UFW) blocked traffic           | 🟠 High     |
| H6  | Access to `ld.so.preload` (potential library injection) | 🔴 Critical |

---

## Expected Log Files in `logs/`

The following files are expected for full analysis:

- auth_log.txt
- processes.txt
- open_files.txt
- tmp_files.txt
- strace_output.txt
- persistence.txt
- network_connection.txt
- dns_host.txt
- arp_table.txt
- ping_kali.txt
- tcpdump_output.txt
- kernel_log.txt
- journal_log.txt
- ubuntu_system.txt
- simulation_timeline.txt
- kali_inbound_traffic.txt
- kali_ping_ubuntu.txt
- kali_received_callback.txt

---

## Optional Flags

| Flag         | Description           |
| ------------ | --------------------- |
| --analyze    | Run log parsing stage |
| --heuristics | Run detection engine  |
| --visualize  | Generate charts       |
| --report     | Generate final report |

---

## File Structure

<pre>
Week_8_Project/
│
├── logs/                    # Contains Logs for analyzing 
|
├── report/                  # Contains Generated outputs
|
├── collect_logs.sh          # Commands For Collecting Logs
|
├── heuristics.py.           # Detection engine
|
├── main.py                  # Main Python Script that Runs Everything
|
├── monitor_analysis.py      # Log Parsing Stage
|
├── README.md                # This File
|
├── report_generator.py      # Generate final report
│
└── visualize.py             # Generate charts
</pre>

---

## Output Charts

The system generates the following visual outputs:

- Activity overview
- Firewall (UFW) blocked sources
- Network protocol distribution
- SSH login timeline
- Alert severity distribution
- Top processes by CPU usage

All charts are saved as `.png` files in the `report/` directory.

---

## Disclaimer

**This project is intended strictly for educational and research purposes.**

- All analysis is conducted within isolated virtual environments
- No real systems or networks are targeted
- No automated malware execution occurs within virtual machines
- Real log data is excluded from version control

**Users are responsible for ensuring compliance with applicable laws and ethical guidelines when using this project.**
