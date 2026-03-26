# =============================================================================
# PART 1 — UBUNTU VM
# Run all commands inside Ubuntu VM
# =============================================================================

# Create log folder
mkdir -p ~/Desktop/sandbox_logs


# --- STEP 1: System snapshot ----------------------------------------------

# Save running processes, users, and current user info
ps aux  > ~/Desktop/sandbox_logs/processes.txt
who    >> ~/Desktop/sandbox_logs/processes.txt
id     >> ~/Desktop/sandbox_logs/processes.txt

# List open files
lsof > ~/Desktop/sandbox_logs/open_files.txt

# Check temp directories (common malware locations)
ls -la /tmp      > ~/Desktop/sandbox_logs/tmp_files.txt
ls -la /var/tmp >> ~/Desktop/sandbox_logs/tmp_files.txt


# --- STEP 2: Syscall trace -----------------------------------------------

# Trace file, network, and process calls (example command)
strace -e trace=file,network,process -o ~/Desktop/sandbox_logs/strace_output.txt ls /tmp

# Attach to a running process (example PID)
sudo strace -e trace=file,network,process -p 1234 -o ~/Desktop/sandbox_logs/strace_pid.txt


# --- STEP 3: Persistence checks ------------------------------------------

# Check cron jobs
crontab -l > ~/Desktop/sandbox_logs/persistence.txt 2>&1
cat /etc/crontab >> ~/Desktop/sandbox_logs/persistence.txt

# Check cron folders
ls -la /etc/cron.d/     >> ~/Desktop/sandbox_logs/persistence.txt
ls -la /etc/cron.daily/ >> ~/Desktop/sandbox_logs/persistence.txt

# Check startup files
cat ~/.bashrc >> ~/Desktop/sandbox_logs/persistence.txt
cat ~/.bash_profile >> ~/Desktop/sandbox_logs/persistence.txt 2>&1

# Check autostart programs
ls -la ~/.config/autostart/ >> ~/Desktop/sandbox_logs/persistence.txt 2>&1

# Check init scripts
ls -la /etc/init.d/ >> ~/Desktop/sandbox_logs/persistence.txt

# List running services
systemctl list-units --type=service --state=running >> ~/Desktop/sandbox_logs/persistence.txt


# --- STEP 4: Network activity --------------------------------------------

# Active connections (ss + netstat)
ss -tunp > ~/Desktop/sandbox_logs/network_connection.txt
netstat -tunp >> ~/Desktop/sandbox_logs/network_connection.txt 2>&1

# DNS info
cat /etc/hosts > ~/Desktop/sandbox_logs/dns_host.txt
resolvectl status >> ~/Desktop/sandbox_logs/dns_host.txt 2>&1

# ARP table
arp -a > ~/Desktop/sandbox_logs/arp_table.txt

# Ping Kali VM
ping -c 4 Kali IP Address > ~/Desktop/sandbox_logs/ping_kali.txt

# Log connection attempt
echo "[$(date '+%Y-%m-%d %H:%M:%S')] connection attempted to Kali IP Address" >> ~/Desktop/sandbox_logs/network_connection.txt


# --- STEP 5: Packet capture ----------------------------------------------

# Capture 100 packets from all interfaces
sudo tcpdump -i any -nn -c 100 > ~/Desktop/sandbox_logs/tcpdump_output.txt


# --- STEP 6: System logs -------------------------------------------------

# Auth logs (SSH, sudo)
sudo cat /var/log/auth.log | tail -100 > ~/Desktop/sandbox_logs/auth_log.txt

# Kernel logs
dmesg | tail -100 > ~/Desktop/sandbox_logs/kernel_log.txt

# System logs (systemd)
sudo journalctl -n 100 --no-pager > ~/Desktop/sandbox_logs/journal_log.txt

# Second process snapshot
ps aux > ~/Desktop/sandbox_logs/ubuntu_system.txt


# --- STEP 7: Simulation timeline -----------------------------------------

# Log callback event manually
echo "[$(date '+%Y-%m-%d %H:%M:%S')] CALLBACK Sent test to Kali IP Address:4444" >> ~/Desktop/sandbox_logs/simulation_timeline.txt


# =============================================================================
# PART 2 — KALI VM
# Run all commands inside Kali VM
# =============================================================================

# Create log folder
mkdir -p ~/Desktop/kali_logs


# --- STEP 8: Capture traffic ---------------------------------------------

# Capture inbound traffic
sudo tcpdump -i eth0 -nn -c 100 > ~/Desktop/kali_logs/kali_inbound_traffic.txt

# Ping Ubuntu VM
ping -c 5 Ubuntu IP Adress > ~/Desktop/kali_logs/kali_ping_ubuntu.txt


# --- STEP 9: Netcat listener ---------------------------------------------

# Start listener on port 4444 (background)
nc -lvp 4444 > ~/Desktop/kali_logs/kali_received_callback.txt 2>&1 &

# Log listener start
echo "Listener started on port 4444 at $(date)" >> ~/Desktop/kali_logs/kali_received_callback.txt


# =============================================================================
# PART 3 — HOST MACHINE
# Run on host to collect logs
# =============================================================================

# --- STEP 10: Transfer logs ----------------------------------------------

# Copy logs from Ubuntu VM
scp ubuntu@Ubuntu IP Adress:~/Desktop/sandbox_logs/*.txt ./MalwareSandbox/logs/

# Copy logs from Kali VM
scp kali@Kali IP Address:~/Desktop/kali_logs/*.txt ./MalwareSandbox/logs/

# Verify files
echo "Files collected in logs/:"
ls -1 ./MalwareSandbox/logs/


# =============================================================================
# EXPECTED FILES IN logs/
# =============================================================================

# processes.txt
# open_files.txt
# tmp_files.txt
# strace_output.txt
# strace_pid.txt
# persistence.txt
# network_connection.txt
# dns_host.txt
# arp_table.txt
# ping_kali.txt
# tcpdump_output.txt
# auth_log.txt
# kernel_log.txt
# journal_log.txt
# ubuntu_system.txt
# simulation_timeline.txt
# kali_inbound_traffic.txt
# kali_ping_ubuntu.txt
# kali_received_callback.txt
