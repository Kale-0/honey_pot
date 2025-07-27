import http.server
import socketserver
import threading
import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from collections import Counter
import matplotlib.pyplot as plt
import geoip2.database

HTTP_LOG = "honeypot_http.log"
COWRIE_LOG = "cowrie.json"
REPORT_FILE = "attack_report.pdf"
GEO_DB = "GeoLite2-City.mmdb"
MAP_IMAGE = "attackers_map.png"

class UnifiedLogger:
    def __init__(self):
        self.http_ips = []
        self.cowrie_ips = []
        self.commands = []

    def log_http_attack(self, ip, request_line):
        log_entry = {
            "type": "http",
            "src_ip": ip,
            "time": datetime.now().isoformat(),
            "request": request_line
        }
        self.http_ips.append(ip)
        with open(HTTP_LOG, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    def parse_cowrie_logs(self):
        if not os.path.exists(COWRIE_LOG):
            print("[!] No cowrie.json log found.")
            return
        with open(COWRIE_LOG) as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if 'src_ip' in entry:
                        self.cowrie_ips.append(entry['src_ip'])
                    if entry.get('eventid') == 'cowrie.command.input':
                        self.commands.append(entry.get('input'))
                except:
                    continue

    def generate_map(self):
        if not os.path.exists(GEO_DB):
            print("[!] GeoLite2 DB not found. Skipping map.")
            return
        reader = geoip2.database.Reader(GEO_DB)
        unique_ips = set(self.http_ips + self.cowrie_ips)
        lats, lons = [], []

        for ip in unique_ips:
            try:
                resp = reader.city(ip)
                lats.append(resp.location.latitude)
                lons.append(resp.location.longitude)
            except:
                continue

        if lats and lons:
            plt.figure(figsize=(8, 4))
            plt.scatter(lons, lats, alpha=0.6)
            plt.title("Attacker IP Locations")
            plt.xlabel("Longitude")
            plt.ylabel("Latitude")
            plt.grid(True)
            plt.tight_layout()
            plt.savefig(MAP_IMAGE)
            plt.close()
            print(f"[✓] Map saved as {MAP_IMAGE}")

    def generate_report(self):
        all_ips = self.http_ips + self.cowrie_ips
        ip_stats = Counter(all_ips)
        command_stats = Counter(self.commands)

        c = canvas.Canvas(REPORT_FILE, pagesize=A4)
        width, height = A4
        margin = 2 * cm
        text = c.beginText(margin, height - margin)

        text.setFont("Helvetica-Bold", 14)
        text.textLine("Unified Honeypot Attack Report")
        text.setFont("Helvetica", 10)
        text.textLine(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        text.textLine(" ")

        text.setFont("Helvetica-Bold", 12)
        text.textLine("1. Summary")
        text.setFont("Helvetica", 10)
        text.textLine(f"Total HTTP Hits: {len(self.http_ips)}")
        text.textLine(f"Total SSH (Cowrie) Hits: {len(self.cowrie_ips)}")
        text.textLine(f"Unique IPs: {len(set(all_ips))}")
        text.textLine(" ")

        text.setFont("Helvetica-Bold", 12)
        text.textLine("2. Top Attacker IPs")
        text.setFont("Helvetica", 10)
        for ip, count in ip_stats.most_common(5):
            text.textLine(f"  - {ip}: {count} attempts")

        text.setFont("Helvetica-Bold", 12)
        text.textLine("\n3. Most Common SSH Commands")
        text.setFont("Helvetica", 10)
        for cmd, freq in command_stats.most_common(3):
            text.textLine(f"  - {cmd}: {freq} times")

        c.drawText(text)
        c.showPage()

        if os.path.exists(MAP_IMAGE):
            c.drawImage(MAP_IMAGE, margin, height / 2, width - 2 * margin, height / 2 - margin)
            c.showPage()

        c.save()
        print(f" Report saved as {REPORT_FILE}")

class HoneypotHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        ip = self.client_address[0]
        request = format % args
        logger.log_http_attack(ip, request)
        print(f"[HTTP] {ip} - {request}")

def run_http_server():
    PORT = 8000
    with socketserver.TCPServer(("", PORT), HoneypotHTTPHandler) as httpd:
        print(f"[HTTP Honeypot] Running on port {PORT}...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Shutting down HTTP server...")
            httpd.server_close()

if __name__ == "__main__":
    logger = UnifiedLogger()

   
    server_thread = threading.Thread(target=run_http_server, daemon=True)
    server_thread.start()

    try:
        while True:
            pass  
    except KeyboardInterrupt:
        print("\n[+] Collecting logs and generating report...")
        logger.parse_cowrie_logs()
        logger.generate_map()
        logger.generate_report()
