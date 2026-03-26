import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

from scapy.all import rdpcap, IP, UDP, TCP


# =========================
# CONFIGURATION
# =========================
DEFAULT_CAPTURE_DIR = Path("captures")
DEFAULT_REPORT_FILE = Path("analysis_report.txt")
TARGET_UDP_PORT = 9999

SYN_SCAN_MIN_SYN = 10
SYN_SCAN_MIN_PORTS = 5
AGGRESSIVE_SCAN_MIN_PORTS = 30


# =========================
# MOTEUR D'ANALYSE
# =========================
def find_latest_pcap(directory: Path):
    files = list(directory.glob("*.pcap")) + list(directory.glob("*.pcapng"))
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def safe_decode_udp_payload(packet):
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


def analyze_pcap(pcap_path: Path):
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
    alerts = []

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

                if len(udp_alert_samples) < 10:
                    udp_alert_samples.append((timestamp, src, dst, packet[UDP].dport, payload))

                alerts.append({
                    "type": "UDP EXFIL",
                    "time": timestamp,
                    "source": src,
                    "destination": dst,
                    "port": packet[UDP].dport,
                    "details": payload
                })

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

    # Détection SYN scan
    scan_syn_detected = False
    for ip, syn_count in syn_packets.items():
        unique_ports = len(connection_attempts[ip])
        if syn_count >= SYN_SCAN_MIN_SYN and unique_ports >= SYN_SCAN_MIN_PORTS:
            scan_syn_detected = True
            alerts.append({
                "type": "SCAN SYN",
                "time": "",
                "source": ip,
                "destination": "",
                "port": "",
                "details": f"SYN={syn_count}, ports={unique_ports}"
            })

    # Détection scan agressif
    scan_agressif_detected = False
    for ip, ports in connection_attempts.items():
        unique_ports = len(ports)
        if unique_ports >= AGGRESSIVE_SCAN_MIN_PORTS:
            scan_agressif_detected = True
            alerts.append({
                "type": "SCAN AGRESSIF",
                "time": "",
                "source": ip,
                "destination": "",
                "port": "",
                "details": f"Ports explores={unique_ports}"
            })

    duration = 0.0
    if first_time and last_time:
        duration = (last_time - first_time).total_seconds()

    stats = {
        "total_packets": total_packets,
        "ip_packets": ip_packets,
        "udp_count": udp_count,
        "tcp_count": tcp_count,
        "udp_exfil_count": udp_exfil_count,
        "duration": duration,
        "ip_src_counter": ip_src_counter,
        "ip_dst_counter": ip_dst_counter,
        "ports_counter": ports_counter,
        "protocol_counter": protocol_counter,
        "alerts": alerts,
        "scan_syn_detected": scan_syn_detected,
        "scan_agressif_detected": scan_agressif_detected,
        "udp_alert_samples": udp_alert_samples,
    }

    return stats


def build_report_text(pcap_path: Path, stats: dict):
    lines = []
    lines.append("===== RAPPORT D'ANALYSE RESEAU =====")
    lines.append(f"Fichier analyse : {pcap_path}")
    lines.append(f"Date d'analyse  : {datetime.now()}")
    lines.append("")
    lines.append("📊 STATISTIQUES RESEAU")
    lines.append(f"Total paquets analyses : {stats['total_packets']}")
    lines.append(f"Paquets IP             : {stats['ip_packets']}")
    lines.append(f"Paquets TCP            : {stats['tcp_count']}")
    lines.append(f"Paquets UDP            : {stats['udp_count']}")
    lines.append(f"Paquets UDP suspectes   : {stats['udp_exfil_count']}")
    lines.append(f"Duree capture          : {stats['duration']:.2f} secondes")
    lines.append("")

    lines.append("Top 5 IP sources :")
    for ip, count in stats["ip_src_counter"].most_common(5):
        lines.append(f"  {ip} -> {count} paquets")

    lines.append("")
    lines.append("Top 5 IP destinations :")
    for ip, count in stats["ip_dst_counter"].most_common(5):
        lines.append(f"  {ip} -> {count} paquets")

    lines.append("")
    lines.append("Top 5 ports cibles :")
    for port, count in stats["ports_counter"].most_common(5):
        lines.append(f"  Port {port} -> {count} fois")

    lines.append("")
    lines.append("Protocoles observes :")
    for proto, count in stats["protocol_counter"].items():
        lines.append(f"  {proto} -> {count}")

    lines.append("")
    lines.append("🧠 RESUME FINAL")
    if stats["udp_exfil_count"] > 0:
        lines.append(f"[!] Trafic UDP suspect detecte sur le port {TARGET_UDP_PORT}")
        lines.append(f"    Nombre d'occurrences : {stats['udp_exfil_count']}")
    if stats["scan_syn_detected"]:
        lines.append("[!] Activite de scan SYN detectee")
    if stats["scan_agressif_detected"]:
        lines.append("[!] Activite de scan agressif detectee")
    if (
        stats["udp_exfil_count"] == 0
        and not stats["scan_syn_detected"]
        and not stats["scan_agressif_detected"]
    ):
        lines.append("[*] Aucun comportement clairement suspect detecte")

    lines.append("")
    lines.append("Exemples de donnees UDP capturees :")
    if stats["udp_alert_samples"]:
        for ts, src, dst, port, payload in stats["udp_alert_samples"]:
            lines.append(f"  {ts} | {src} -> {dst} | Port {port} | {payload}")
    else:
        lines.append("  Aucune donnee UDP relevante")

    return "\n".join(lines)


# =========================
# INTERFACE GRAPHIQUE
# =========================
class ForensicApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Analyse Forensique Réseau")
        self.geometry("1200x800")
        self.minsize(1000, 700)

        self.current_pcap = tk.StringVar()
        self.status_text = tk.StringVar(value="Prêt.")
        self.last_stats = None

        self._build_ui()
        self._load_latest_pcap()

    def _build_ui(self):
        # Barre supérieure
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Fichier PCAP :").pack(side="left")
        self.file_entry = ttk.Entry(top, textvariable=self.current_pcap, width=70)
        self.file_entry.pack(side="left", padx=8, fill="x", expand=True)

        ttk.Button(top, text="Choisir", command=self.choose_file).pack(side="left", padx=4)
        ttk.Button(top, text="Dernier PCAP", command=self._load_latest_pcap).pack(side="left", padx=4)
        ttk.Button(top, text="Analyser", command=self.run_analysis).pack(side="left", padx=4)

        # Zone stats
        stats_frame = ttk.Frame(self, padding=(10, 0, 10, 10))
        stats_frame.pack(fill="x")

        self.stat_labels = {}
        fields = [
            "total_packets", "tcp_count", "udp_count",
            "udp_exfil_count", "duration"
        ]
        for i, key in enumerate(fields):
            box = ttk.LabelFrame(stats_frame, text=key.replace("_", " ").title(), padding=8)
            box.grid(row=0, column=i, padx=5, sticky="nsew")
            lbl = ttk.Label(box, text="0", font=("Arial", 14, "bold"))
            lbl.pack()
            self.stat_labels[key] = lbl

        stats_frame.columnconfigure(tuple(range(5)), weight=1)

        # Onglets
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_report = ttk.Frame(notebook)
        self.tab_alerts = ttk.Frame(notebook)
        self.tab_talkers = ttk.Frame(notebook)
        self.tab_ports = ttk.Frame(notebook)

        notebook.add(self.tab_report, text="Rapport")
        notebook.add(self.tab_alerts, text="Alertes")
        notebook.add(self.tab_talkers, text="Top IP")
        notebook.add(self.tab_ports, text="Ports")

        # Rapport
        self.report_text = tk.Text(self.tab_report, wrap="word")
        self.report_text.pack(side="left", fill="both", expand=True)
        scroll_report = ttk.Scrollbar(self.tab_report, command=self.report_text.yview)
        scroll_report.pack(side="right", fill="y")
        self.report_text.configure(yscrollcommand=scroll_report.set)

        # Alertes
        self.alerts_tree = ttk.Treeview(
            self.tab_alerts,
            columns=("type", "time", "source", "destination", "port", "details"),
            show="headings"
        )
        for col, title, width in [
            ("type", "Type", 130),
            ("time", "Heure", 170),
            ("source", "Source", 140),
            ("destination", "Destination", 140),
            ("port", "Port", 80),
            ("details", "Détails", 400),
        ]:
            self.alerts_tree.heading(col, text=title)
            self.alerts_tree.column(col, width=width, anchor="w")
        self.alerts_tree.pack(fill="both", expand=True)

        # Top IP
        self.talkers_tree = ttk.Treeview(
            self.tab_talkers,
            columns=("kind", "ip", "count"),
            show="headings"
        )
        for col, title, width in [
            ("kind", "Type", 120),
            ("ip", "IP", 220),
            ("count", "Paquets", 120),
        ]:
            self.talkers_tree.heading(col, text=title)
            self.talkers_tree.column(col, width=width, anchor="w")
        self.talkers_tree.pack(fill="both", expand=True)

        # Ports
        self.ports_tree = ttk.Treeview(
            self.tab_ports,
            columns=("port", "count"),
            show="headings"
        )
        self.ports_tree.heading("port", text="Port")
        self.ports_tree.heading("count", text="Occurrences")
        self.ports_tree.column("port", width=120, anchor="w")
        self.ports_tree.column("count", width=120, anchor="w")
        self.ports_tree.pack(fill="both", expand=True)

        # Barre de statut
        status = ttk.Label(self, textvariable=self.status_text, relief="sunken", anchor="w", padding=6)
        status.pack(fill="x", side="bottom")

    def _load_latest_pcap(self):
        latest = find_latest_pcap(DEFAULT_CAPTURE_DIR)
        if latest is None:
            # fallback si capture.pcap est à la racine
            root_pcap = Path("capture.pcap")
            if root_pcap.exists():
                self.current_pcap.set(str(root_pcap))
                self.status_text.set("PCAP racine chargé.")
            else:
                self.current_pcap.set("")
                self.status_text.set("Aucun PCAP trouvé.")
            return

        self.current_pcap.set(str(latest))
        self.status_text.set(f"Dernier PCAP chargé : {latest}")

    def choose_file(self):
        file_path = filedialog.askopenfilename(
            title="Choisir un fichier PCAP",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if file_path:
            self.current_pcap.set(file_path)
            self.status_text.set(f"Fichier sélectionné : {file_path}")

    def clear_views(self):
        self.report_text.delete("1.0", tk.END)
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        for item in self.talkers_tree.get_children():
            self.talkers_tree.delete(item)
        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)

    def update_stat_labels(self, stats):
        self.stat_labels["total_packets"].config(text=str(stats["total_packets"]))
        self.stat_labels["tcp_count"].config(text=str(stats["tcp_count"]))
        self.stat_labels["udp_count"].config(text=str(stats["udp_count"]))
        self.stat_labels["udp_exfil_count"].config(text=str(stats["udp_exfil_count"]))
        self.stat_labels["duration"].config(text=f"{stats['duration']:.2f}s")

    def run_analysis(self):
        file_path = self.current_pcap.get().strip()
        if not file_path:
            messagebox.showwarning("PCAP manquant", "Choisis un fichier PCAP avant l'analyse.")
            return

        pcap_path = Path(file_path)
        if not pcap_path.exists():
            messagebox.showerror("Fichier introuvable", f"Le fichier n'existe pas :\n{pcap_path}")
            return

        try:
            self.status_text.set("Analyse en cours...")
            self.update_idletasks()

            stats = analyze_pcap(pcap_path)
            report = build_report_text(pcap_path, stats)
            DEFAULT_REPORT_FILE.write_text(report, encoding="utf-8")

            self.last_stats = stats
            self.clear_views()
            self.report_text.insert("1.0", report)
            self.update_stat_labels(stats)

            for alert in stats["alerts"]:
                self.alerts_tree.insert(
                    "",
                    "end",
                    values=(
                        alert["type"],
                        str(alert["time"]),
                        alert["source"],
                        alert["destination"],
                        alert["port"],
                        alert["details"],
                    )
                )

            for ip, count in stats["ip_src_counter"].most_common(5):
                self.talkers_tree.insert("", "end", values=("Source", ip, count))
            for ip, count in stats["ip_dst_counter"].most_common(5):
                self.talkers_tree.insert("", "end", values=("Destination", ip, count))

            for port, count in stats["ports_counter"].most_common(15):
                self.ports_tree.insert("", "end", values=(port, count))

            self.status_text.set(f"Analyse terminée : {pcap_path}")
        except Exception as e:
            self.status_text.set("Erreur pendant l'analyse.")
            messagebox.showerror("Erreur d'analyse", str(e))


if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()