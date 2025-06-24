import threading
import os
import datetime
from scapy.all import sniff, IP
from attack_graph import update_graph
from email_alert import send_email_alert
#from slack_alert import send_slack_alert

SUSPICIOUS_IPS = {" 10.20.118.53"}  # your system IP from ipconfig
LOG_FILE = "logs/detected_logs.txt"
ROOT_CAUSE_FILE = "logs/root_cause_report.txt"
os.makedirs("logs", exist_ok=True)


detected_logs = []
blocked_ips = set()
attack_counts = {}
stop_event = threading.Event()
sniff_thread = None

def log_message(message):
    timestamp = datetime.datetime.now().strftime("%I:%M:%S %p")
    full_log = f"[{timestamp}] {message}"
    print(full_log)
    detected_logs.append(full_log)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(full_log + "\n")

def block_ip(ip):
    if ip not in blocked_ips:
        os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
        blocked_ips.add(ip)
        log_message(f"Blocked IP: {ip}")

def analyze_root_cause(packet):
    suspected_cause = "Unknown"
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        if "192.168." in src:
            suspected_cause = "Local misconfiguration"
        elif packet.haslayer("TCP"):
            dport = packet["TCP"].dport
            if dport == 21:
                suspected_cause = "FTP service exposed"
            elif dport == 23:
                suspected_cause = "Telnet (insecure)"
            elif dport == 445:
                suspected_cause = "SMB service vulnerability"
        elif packet.haslayer("UDP"):
            suspected_cause = "DNS or NTP abuse"

        timestamp = datetime.datetime.now().strftime("%I:%M:%S %p")
        with open(ROOT_CAUSE_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] Root Cause Trace: {src} → {dst} | Cause: {suspected_cause}\n")

        log_message(f"Root cause suspected: {suspected_cause}")
        send_email_alert(src, dst, suspected_cause)
        #send_slack_alert(src, dst, suspected_cause)

def packet_callback(packet):
    print(packet.summary())  # Debug print

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        print(f"[DEBUG] {src} → {dst}")

        attack_counts[src] = attack_counts.get(src, 0) + 1

        if src in SUSPICIOUS_IPS:
            log_message(f"Suspicious from: {src} → {dst}")
            update_graph(src, dst)
            analyze_root_cause(packet)
            block_ip(src)
        elif dst in SUSPICIOUS_IPS:
            log_message(f"Suspicious to: {src} → {dst}")
            update_graph(src, dst)
            analyze_root_cause(packet)
            block_ip(dst)
        else:
            log_message(f"Packet: {src} → {dst}")

def sniff_packets():
    log_message("Sniffer started.")
    sniff(prn=packet_callback, stop_filter=lambda x: stop_event.is_set())
    log_message("Sniffer stopped.")

def run_sniffer_in_background():
    global sniff_thread
    if sniff_thread and sniff_thread.is_alive():
        log_message("Sniffer is already running.")
        return
    stop_event.clear()
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.daemon = True
    sniff_thread.start()

def stop_sniffing():
    if sniff_thread and sniff_thread.is_alive():
        stop_event.set()
    else:
        log_message("No sniffer running.")
