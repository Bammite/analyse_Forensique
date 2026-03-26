import os
import json
import threading
import urllib.request
import urllib.error
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from scapy.all import rdpcap, IP, UDP, TCP


# =========================
# CONFIGURATION
# =========================
DEFAULT_CAPTURE_DIR = Path("captures")
DEFAULT_REPORT_FILE = Path("analysis_report.txt")
DEFAULT_PCAP_FALLBACK = Path("capture.pcap")

TARGET_UDP_PORT = 9999

SYN_SCAN_MIN_SYN = 10
SYN_SCAN_MIN_PORTS = 5
AGGRESSIVE_SCAN_MIN_PORTS = 30

# Gemini : clé à mettre dans une variable d'environnement
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemma-3-27b-it").strip()
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{0}:generateContent".format(GEMINI_MODEL)


# =========================
# UTILITAIRES FICHIERS
# =========================
def find_latest_pcap(directory):
    if not directory.exists():
        return None

    files = list(directory.glob("*.pcap")) + list(directory.glob("*.pcapng"))
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def get_best_pcap_path():
    latest = find_latest_pcap(DEFAULT_CAPTURE_DIR)
    if latest is not None:
        return latest
    if DEFAULT_PCAP_FALLBACK.exists():
        return DEFAULT_PCAP_FALLBACK
    return None


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


# =========================
# MOTEUR D'ANALYSE
# =========================
def analyze_pcap(pcap_path):
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
                "details": "SYN={0}, ports={1}".format(syn_count, unique_ports)
            })

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
                "details": "Ports explores={0}".format(unique_ports)
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


def build_report_text(pcap_path, stats):
    lines = []
    lines.append("===== RAPPORT D'ANALYSE RESEAU =====")
    lines.append("Fichier analyse : {0}".format(pcap_path))
    lines.append("Date d'analyse  : {0}".format(datetime.now()))
    lines.append("")
    lines.append("STATISTIQUES RESEAU")
    lines.append("Total paquets analyses : {0}".format(stats["total_packets"]))
    lines.append("Paquets IP             : {0}".format(stats["ip_packets"]))
    lines.append("Paquets TCP            : {0}".format(stats["tcp_count"]))
    lines.append("Paquets UDP            : {0}".format(stats["udp_count"]))
    lines.append("Paquets UDP suspectes  : {0}".format(stats["udp_exfil_count"]))
    lines.append("Duree capture          : {0:.2f} secondes".format(stats["duration"]))
    lines.append("")

    lines.append("Top 5 IP sources :")
    for ip, count in stats["ip_src_counter"].most_common(5):
        lines.append("  {0} -> {1} paquets".format(ip, count))

    lines.append("")
    lines.append("Top 5 IP destinations :")
    for ip, count in stats["ip_dst_counter"].most_common(5):
        lines.append("  {0} -> {1} paquets".format(ip, count))

    lines.append("")
    lines.append("Top 5 ports cibles :")
    for port, count in stats["ports_counter"].most_common(5):
        lines.append("  Port {0} -> {1} fois".format(port, count))

    lines.append("")
    lines.append("Protocoles observes :")
    for proto, count in stats["protocol_counter"].items():
        lines.append("  {0} -> {1}".format(proto, count))

    lines.append("")
    lines.append("RESUME FINAL")
    if stats["udp_exfil_count"] > 0:
        lines.append("[!] Trafic UDP suspect detecte sur le port {0}".format(TARGET_UDP_PORT))
        lines.append("    Nombre d'occurrences : {0}".format(stats["udp_exfil_count"]))
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
            lines.append("  {0} | {1} -> {2} | Port {3} | {4}".format(ts, src, dst, port, payload))
    else:
        lines.append("  Aucune donnee UDP relevante")

    return "\n".join(lines)


# =========================
# GEMINI
# =========================
def build_ai_prompt(stats, report_text):
    top_sources = stats["ip_src_counter"].most_common(3)
    top_dests = stats["ip_dst_counter"].most_common(3)
    top_ports = stats["ports_counter"].most_common(5)

    alert_lines = []
    for alert in stats["alerts"][:10]:
        alert_lines.append("- {0} | src={1} | dst={2} | port={3} | {4}".format(
            alert["type"],
            alert["source"],
            alert["destination"],
            alert["port"],
            alert["details"]
        ))

    prompt = """
Tu es un analyste SOC spécialisé en analyse forensique réseau.

Tu dois interpréter les résultats ci-dessous de manière prudente et professionnelle.
Ne fabrique aucune information absente des données.
Réponds en français avec cette structure :

1. Résumé exécutif
2. Niveau de risque (Faible / Moyen / Élevé)
3. Indices observés
4. Hypothèse la plus probable
5. Recommandations concrètes

Contexte :
- Le trafic a été capturé dans un laboratoire contrôlé.
- Les détections possibles sont : UDP suspect sur le port 9999, scan SYN, scan agressif.
- L'objectif est d'aider un étudiant à présenter une analyse forensique.

Statistiques :
- Total paquets : {total_packets}
- TCP : {tcp_count}
- UDP : {udp_count}
- UDP suspect : {udp_exfil_count}
- Durée capture : {duration:.2f} secondes
- Scan SYN détecté : {scan_syn_detected}
- Scan agressif détecté : {scan_agressif_detected}

Top IP sources :
{top_sources}

Top IP destinations :
{top_dests}

Top ports :
{top_ports}

Alertes :
{alerts}

Extrait du rapport brut :
{report_excerpt}
""".format(
        total_packets=stats["total_packets"],
        tcp_count=stats["tcp_count"],
        udp_count=stats["udp_count"],
        udp_exfil_count=stats["udp_exfil_count"],
        duration=stats["duration"],
        scan_syn_detected=stats["scan_syn_detected"],
        scan_agressif_detected=stats["scan_agressif_detected"],
        top_sources=top_sources,
        top_dests=top_dests,
        top_ports=top_ports,
        alerts=alert_lines if alert_lines else ["- Aucune alerte"],
        report_excerpt=report_text[:4000]
    )

    return prompt


def gemini_interpretation(stats, report_text):
    if not GEMINI_API_KEY:
        return "Clé GEMINI_API_KEY absente. Définis la variable d'environnement puis relance l'application."

    prompt = build_ai_prompt(stats, report_text)

    body = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 900
        }
    }

    req = urllib.request.Request(
        GEMINI_ENDPOINT,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": GEMINI_API_KEY
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))

        candidates = data.get("candidates", [])
        if not candidates:
            return "Gemini a répondu sans contenu exploitable."

        content = candidates[0].get("content", {})
        parts = content.get("parts", [])
        if not parts:
            return "Gemini a répondu sans texte exploitable."

        texts = []
        for part in parts:
            if "text" in part:
                texts.append(part["text"])

        if not texts:
            return "Gemini a répondu sans texte exploitable."

        return "\n".join(texts)

    except urllib.error.HTTPError as e:
        try:
            error_body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            error_body = str(e)
        return "Erreur HTTP Gemini : {0}\n{1}".format(e.code, error_body)
    except Exception as e:
        return "Erreur Gemini : {0}".format(str(e))


# =========================
# APPLICATION GRAPHIQUE
# =========================
class ForensicApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Analyse Forensique Réseau")
        self.geometry("1280x820")
        self.minsize(1100, 720)

        self.current_pcap = tk.StringVar()
        self.status_text = tk.StringVar(value="Prêt.")
        self.last_stats = None
        self.last_report_text = ""
        self.ai_running = False

        self._build_ui()
        self._load_latest_pcap()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Fichier PCAP :").pack(side="left")
        self.file_entry = ttk.Entry(top, textvariable=self.current_pcap, width=75)
        self.file_entry.pack(side="left", padx=8, fill="x", expand=True)

        ttk.Button(top, text="Choisir", command=self.choose_file).pack(side="left", padx=4)
        ttk.Button(top, text="Dernier PCAP", command=self._load_latest_pcap).pack(side="left", padx=4)
        ttk.Button(top, text="Analyser", command=self.run_analysis).pack(side="left", padx=4)

        self.btn_ai = ttk.Button(top, text="Interpréter avec IA", command=self.run_ai_analysis)
        self.btn_ai.pack(side="left", padx=4)
        self.btn_ai.config(state="disabled")

        stats_frame = ttk.Frame(self, padding=(10, 0, 10, 10))
        stats_frame.pack(fill="x")

        self.stat_labels = {}
        fields = ["total_packets", "tcp_count", "udp_count", "udp_exfil_count", "duration"]
        titles = {
            "total_packets": "Paquets Totaux",
            "tcp_count": "TCP",
            "udp_count": "UDP",
            "udp_exfil_count": "UDP Suspects",
            "duration": "Durée"
        }

        for i, key in enumerate(fields):
            box = ttk.LabelFrame(stats_frame, text=titles[key], padding=8)
            box.grid(row=0, column=i, padx=5, sticky="nsew")
            lbl = ttk.Label(box, text="0", font=("Arial", 14, "bold"))
            lbl.pack()
            self.stat_labels[key] = lbl

        for i in range(5):
            stats_frame.columnconfigure(i, weight=1)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_report = ttk.Frame(notebook)
        self.tab_alerts = ttk.Frame(notebook)
        self.tab_talkers = ttk.Frame(notebook)
        self.tab_ports = ttk.Frame(notebook)
        self.tab_ai = ttk.Frame(notebook)

        notebook.add(self.tab_report, text="Rapport")
        notebook.add(self.tab_alerts, text="Alertes")
        notebook.add(self.tab_talkers, text="Top IP")
        notebook.add(self.tab_ports, text="Ports")
        notebook.add(self.tab_ai, text="IA")

        self.report_text = tk.Text(self.tab_report, wrap="word")
        self.report_text.pack(side="left", fill="both", expand=True)
        scroll_report = ttk.Scrollbar(self.tab_report, command=self.report_text.yview)
        scroll_report.pack(side="right", fill="y")
        self.report_text.configure(yscrollcommand=scroll_report.set)

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
            ("details", "Détails", 420),
        ]:
            self.alerts_tree.heading(col, text=title)
            self.alerts_tree.column(col, width=width, anchor="w")
        self.alerts_tree.pack(fill="both", expand=True)

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

        ai_top = ttk.Frame(self.tab_ai, padding=8)
        ai_top.pack(fill="x")
        ttk.Label(ai_top, text="Interprétation IA :").pack(side="left")
        self.ai_status_label = ttk.Label(ai_top, text="En attente d'analyse.")
        self.ai_status_label.pack(side="left", padx=8)

        self.ai_text = tk.Text(self.tab_ai, wrap="word")
        self.ai_text.pack(side="left", fill="both", expand=True)
        scroll_ai = ttk.Scrollbar(self.tab_ai, command=self.ai_text.yview)
        scroll_ai.pack(side="right", fill="y")
        self.ai_text.configure(yscrollcommand=scroll_ai.set)

        self.ai_progress = ttk.Progressbar(self.tab_ai, mode="indeterminate")
        self.ai_progress.pack(fill="x", padx=8, pady=(4, 8))

        status = ttk.Label(self, textvariable=self.status_text, relief="sunken", anchor="w", padding=6)
        status.pack(fill="x", side="bottom")

    def _load_latest_pcap(self):
        latest = get_best_pcap_path()
        if latest is None:
            self.current_pcap.set("")
            self.status_text.set("Aucun PCAP trouvé.")
            return

        self.current_pcap.set(str(latest))
        self.status_text.set("Dernier PCAP chargé : {0}".format(latest))

    def choose_file(self):
        file_path = filedialog.askopenfilename(
            title="Choisir un fichier PCAP",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if file_path:
            self.current_pcap.set(file_path)
            self.status_text.set("Fichier sélectionné : {0}".format(file_path))

    def clear_views(self):
        self.report_text.delete("1.0", tk.END)
        self.ai_text.delete("1.0", tk.END)

        for tree in [self.alerts_tree, self.talkers_tree, self.ports_tree]:
            for item in tree.get_children():
                tree.delete(item)

    def update_stat_labels(self, stats):
        self.stat_labels["total_packets"].config(text=str(stats["total_packets"]))
        self.stat_labels["tcp_count"].config(text=str(stats["tcp_count"]))
        self.stat_labels["udp_count"].config(text=str(stats["udp_count"]))
        self.stat_labels["udp_exfil_count"].config(text=str(stats["udp_exfil_count"]))
        self.stat_labels["duration"].config(text="{0:.2f}s".format(stats["duration"]))

    def run_analysis(self):
        file_path = self.current_pcap.get().strip()
        if not file_path:
            messagebox.showwarning("PCAP manquant", "Choisis un fichier PCAP avant l'analyse.")
            return

        pcap_path = Path(file_path)
        if not pcap_path.exists():
            messagebox.showerror("Fichier introuvable", "Le fichier n'existe pas :\n{0}".format(pcap_path))
            return

        try:
            self.status_text.set("Analyse en cours...")
            self.update_idletasks()

            stats = analyze_pcap(pcap_path)
            report = build_report_text(pcap_path, stats)
            DEFAULT_REPORT_FILE.write_text(report, encoding="utf-8")

            self.last_stats = stats
            self.last_report_text = report
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

            self.btn_ai.config(state="normal")
            self.status_text.set("Analyse terminée : {0}".format(pcap_path))
        except Exception as e:
            self.status_text.set("Erreur pendant l'analyse.")
            messagebox.showerror("Erreur d'analyse", str(e))

    def run_ai_analysis(self):
        if self.last_stats is None:
            messagebox.showwarning("Analyse manquante", "Lance d'abord une analyse PCAP.")
            return

        if self.ai_running:
            return

        self.ai_running = True
        self.btn_ai.config(state="disabled")
        self.ai_progress.start(10)
        self.ai_status_label.config(text="Analyse IA en cours...")
        self.status_text.set("Interprétation IA en cours...")

        def worker():
            result = gemini_interpretation(self.last_stats, self.last_report_text)
            self.after(0, lambda: self._finish_ai_analysis(result))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_ai_analysis(self, result):
        self.ai_progress.stop()
        self.ai_text.delete("1.0", tk.END)
        self.ai_text.insert("1.0", result)
        self.ai_status_label.config(text="Interprétation terminée.")
        self.status_text.set("Interprétation IA terminée.")
        self.ai_running = False
        self.btn_ai.config(state="normal")


if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()
