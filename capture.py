from scapy.all import rdpcap, IP, UDP, TCP
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path
from typing import Optional

# =========================
# CONFIGURATION
# =========================
CAPTURE_DIR = Path("captures")
REPORT_FILE = Path("analysis_report.txt")
TARGET_UDP_PORT = 9999
DEFAULT_PCAP = Path("capture.pcap")

# Seuils de détection
SYN_SCAN_MIN_SYN = 10
SYN_SCAN_MIN_PORTS = 5
AGGRESSIVE_SCAN_MIN_PORTS = 30
UDP_EXFIL_MIN_COUNT = 5

# =========================
# UTILITAIRES
# =========================
def find_latest_pcap(directory: Path) -> Optional[Path]:
    files = list(directory.glob("*.pcap")) + list(directory.glob("*.pcapng"))
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)

def write_report(text: str):
    print(text)
    with REPORT_FILE.open("a", encoding="utf-8") as f:
        f.write(text + "\n")

def safe_decode_udp_payload(packet) -> str:
    try:
        payload = bytes(packet[UDP].payload)
        if not payload:
            return ""
        return payload.decode("ascii", errors="ignore").strip()
    except Exception:
        try:
            return str(bytes(packet[UDP].payload)).strip()
        except Exception:
            return ""

# =========================
# FICHIER A ANALYSER
# =========================
pcap_path = None

if DEFAULT_PCAP.exists():
    pcap_path = DEFAULT_PCAP
else:
    pcap_path = find_latest_pcap(CAPTURE_DIR)

if pcap_path is None:
    print("[!] Aucun fichier pcap trouve.")
    print("[!] Verifie si 'capture.pcap' existe a la racine ou dans captures/")
    raise SystemExit(1)

# Initialisation du rapport
with REPORT_FILE.open("w", encoding="utf-8") as f:
    f.write("===== RAPPORT D'ANALYSE RESEAU =====\n")
    f.write(f"Fichier analyse : {pcap_path}\n")
    f.write(f"Date d'analyse  : {datetime.now()}\n\n")

print("[*] Analyse du trafic reseau...")
print(f"[*] Fichier source : {pcap_path}")
print(f"[*] Rapport        : {REPORT_FILE}")

# =========================
# VARIABLES D'ANALYSE
# =========================
packets = rdpcap(str(pcap_path))

total_packets = 0
ip_packets = 0
udp_count = 0
tcp_count = 0
udp_exfil_count = 0

syn_packets = defaultdict(int)
connection_attempts = defaultdict(set)

ip_src_counter = Counter()
ip_dst_counter = Counter()
ports_counter = Counter()
protocol_counter = Counter()

first_time = None
last_time = None

udp_alert_samples = []

# =========================
# ANALYSE
# =========================
for packet in packets:
    if not packet.haslayer(IP):
        continue

    total_packets += 1
    ip_packets += 1

    src = packet[IP].src
    dst = packet[IP].dst
    timestamp = datetime.fromtimestamp(float(packet.time))

    if first_time is None:
        first_time = timestamp
    last_time = timestamp

    ip_src_counter[src] += 1
    ip_dst_counter[dst] += 1

    # UDP
    if packet.haslayer(UDP):
        udp_count += 1
        protocol_counter["UDP"] += 1
        ports_counter[packet[UDP].dport] += 1

        payload = safe_decode_udp_payload(packet)

        if packet[UDP].dport == TARGET_UDP_PORT and payload:
            udp_exfil_count += 1

            if len(udp_alert_samples) < 5:
                udp_alert_samples.append((timestamp, src, dst, payload))

            write_report("[ALERTE] Donnee UDP detectee")
            write_report(f"  Heure       : {timestamp}")
            write_report(f"  Source      : {src}")
            write_report(f"  Destination : {dst}")
            write_report(f"  Port        : {packet[UDP].dport}")
            write_report(f"  Donnee      : {payload}")
            write_report("")

    # TCP
    if packet.haslayer(TCP):
        tcp_count += 1
        protocol_counter["TCP"] += 1
        ports_counter[packet[TCP].dport] += 1

        tcp = packet[TCP]
        flags = int(tcp.flags)

        syn_only = (flags & 0x02) and not (flags & 0x10)
        if syn_only:
            syn_packets[src] += 1
            connection_attempts[src].add(tcp.dport)

# =========================
# ANALYSE COMPORTEMENTALE
# =========================
scan_syn_detected = False
scan_agressif_detected = False

for ip, syn_count in syn_packets.items():
    unique_ports = len(connection_attempts[ip])

    if syn_count >= SYN_SCAN_MIN_SYN and unique_ports >= SYN_SCAN_MIN_PORTS:
        scan_syn_detected = True
        write_report("[ALERTE] Scan SYN detecte (type nmap -sS)")
        write_report(f"  Source         : {ip}")
        write_report(f"  SYN envoyes     : {syn_count}")
        write_report(f"  Ports cibles    : {unique_ports}")
        write_report("")

for ip, ports in connection_attempts.items():
    unique_ports = len(ports)

    if unique_ports >= AGGRESSIVE_SCAN_MIN_PORTS:
        scan_agressif_detected = True
        write_report("[ALERTE] Scan agressif detecte (type nmap -A)")
        write_report(f"  Source              : {ip}")
        write_report(f"  Nombre de ports     : {unique_ports}")
        write_report("")

# =========================
# STATISTIQUES
# =========================
write_report("\n=========================")
write_report("📊 STATISTIQUES RESEAU")
write_report("=========================")

write_report(f"Total paquets analyses : {total_packets}")
write_report(f"Paquets IP             : {ip_packets}")
write_report(f"Paquets TCP            : {tcp_count}")
write_report(f"Paquets UDP            : {udp_count}")
write_report(f"Paquets UDP suspectes   : {udp_exfil_count}")

if first_time and last_time:
    duration = (last_time - first_time).total_seconds()
    write_report(f"Duree capture          : {duration:.2f} secondes")

write_report("\nTop 5 IP sources :")
for ip, count in ip_src_counter.most_common(5):
    write_report(f"  {ip} -> {count} paquets")

write_report("\nTop 5 IP destinations :")
for ip, count in ip_dst_counter.most_common(5):
    write_report(f"  {ip} -> {count} paquets")

write_report("\nTop 5 ports cibles :")
for port, count in ports_counter.most_common(5):
    write_report(f"  Port {port} -> {count} fois")

write_report("\nProtocoles observes :")
for proto, count in protocol_counter.items():
    write_report(f"  {proto} -> {count}")

# =========================
# RESUME FINAL
# =========================
write_report("\n=========================")
write_report("🧠 RESUME FINAL")
write_report("=========================")

if udp_exfil_count > 0:
    write_report(f"[!] Trafic UDP suspect detecte sur le port {TARGET_UDP_PORT}")
    write_report(f"    Nombre d'occurrences : {udp_exfil_count}")

if scan_syn_detected:
    write_report("[!] Activite de scan SYN detectee")

if scan_agressif_detected:
    write_report("[!] Activite de scan agressif detectee")

if udp_exfil_count == 0 and not scan_syn_detected and not scan_agressif_detected:
    write_report("[*] Aucun comportement clairement suspect detecte")

write_report("[*] Analyse terminee")

# =========================
# EXEMPLES DE DONNEES CAPTUREES
# =========================
if udp_alert_samples:
    write_report("\nExemples de donnees UDP capturees :")
    for ts, src, dst, payload in udp_alert_samples:
        write_report(f"  {ts} | {src} -> {dst} | {payload}")