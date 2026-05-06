import sys
import csv
import time
import threading
import socket
import datetime
import ctypes
import os

from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QLabel, QHBoxLayout, QWidget
from PyQt5.QtGui import QPixmap

from scapy.all import sniff, srp, Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP

import psutil
import matplotlib.pyplot as plt
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )


def check_npcap():
    return os.path.exists("C:\\Windows\\System32\\Npcap")


class NetworkTool(QMainWindow):
    def __init__(self):
        super().__init__()
        if not is_admin():
            reply = QMessageBox.question(
                self,
                "Administrator Required",
                "Run this tool as Administrator?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                run_as_admin()
                sys.exit()
            else:
                QMessageBox.warning(self, "Warning", "Some features may not work")

        # -------- NPCAP CHECK --------
        if not check_npcap():
            QMessageBox.critical(
                self,
                "Npcap Missing",
                "Npcap is not installed. Please install it."
            )

        self.setWindowTitle("Network Analyzer & Device Scanner")

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.packet_tab = QWidget()
        self.device_tab = QWidget()

        self.tabs.addTab(self.packet_tab, "Packet Analyzer")
        self.tabs.addTab(self.device_tab, "Device Scanner")

        self.init_packet_tab()
        self.init_device_tab()


# ================= PACKET TAB =================
    def init_packet_tab(self):
        main_layout = QVBoxLayout()

        header_layout = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(QPixmap("img/logp.jpeg").scaled(60, 60))

        title = QLabel("Vignan Institute of Technology\nNetwork Traffic Analyzer Tool")
        title.setStyleSheet("font-size:20px; font-weight:bold;")
        title.setWordWrap(False)

        header_layout.addWidget(logo)
        header_layout.addWidget(title)
        header_layout.setAlignment(Qt.AlignLeft)

        self.interface_box = QComboBox()
        for iface, addrs in psutil.net_if_addrs().items():
            ip = ""
            for a in addrs:
                if a.family == socket.AF_INET:
                    ip = a.address
            self.interface_box.addItem(f"{iface} ({ip})", iface)

        self.filter_box = QComboBox()
        self.filter_box.addItems(
            ["ALL","TCP","UDP","HTTP","HTTPS","DNS","DHCP","FTP","SSH","ICMP","ARP","Ethernet"]
        )

        self.table = QTableWidget(0,6)
        self.table.setHorizontalHeaderLabels(
            ["No","Protocol","Source","Destination","Length","Info"]
        )

        self.metrics = QLabel()

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.stop_btn = QPushButton("Stop")
        self.analyze_btn = QPushButton("Analyze")
        self.export_btn = QPushButton("Export CSV")

        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.analyze_btn)
        btn_layout.addWidget(self.export_btn)

        main_layout.addLayout(header_layout)
        main_layout.addWidget(self.interface_box)
        main_layout.addWidget(self.filter_box)
        main_layout.addWidget(self.table)
        main_layout.addLayout(btn_layout)
        main_layout.addWidget(self.metrics)

        self.packet_tab.setLayout(main_layout)

        self.start_btn.clicked.connect(self.start_sniff)
        self.stop_btn.clicked.connect(self.stop_sniff)
        self.export_btn.clicked.connect(self.export_packets)
        self.analyze_btn.clicked.connect(self.analyze_packets)
        self.filter_box.currentTextChanged.connect(self.apply_filter)

        self.packet_data = []
        self.sniffing = False


# ================= PACKET PROCESS =================
    def process_packet(self, pkt):
        if not self.sniffing:
            return

        proto = "Other"
        src = dst = "Unknown"
        info = ""

        ts = datetime.datetime.now().strftime("%H:%M:%S")

        # IP or MAC fallback
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif pkt.haslayer(Ether):
            src = pkt[Ether].src
            dst = pkt[Ether].dst

        # -------- PROTOCOL DETECTION --------
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            if dport == 80 or sport == 80:
                proto = "HTTP"
            elif dport == 443 or sport == 443:
                proto = "HTTPS"
            elif dport == 21:
                proto = "FTP"
            elif dport == 22:
                proto = "SSH"
            else:
                proto = "TCP"

            flags = pkt[TCP].flags
            info = f"[{proto}] {src} → {dst} | Ports {sport}->{dport} | Flags={flags}"

        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

            if dport == 53 or sport == 53:
                proto = "DNS"
                info = f"[DNS] {src} → {dst} | Query"
            elif dport in [67,68]:
                proto = "DHCP"
                info = "[DHCP] Network Configuration"
            else:
                proto = "UDP"
                info = f"[UDP] {src} → {dst} | Ports {sport}->{dport}"

        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            info = f"[ICMP] {src} → {dst} | Ping"

        elif pkt.haslayer(ARP):
            proto = "ARP"
            info = f"[ARP] {pkt[ARP].psrc} → {pkt[ARP].pdst}"

        elif pkt.haslayer(Ether):
            proto = "Ethernet"
            info = f"[Ethernet] {src} → {dst}"

        # Hostname
        try:
            host = socket.gethostbyaddr(dst)[0]
            info += f" | Host: {host}"
        except:
            pass

        length = len(pkt)

        # -------- COLOR DETECTION --------
        color = Qt.white

        if pkt.haslayer(TCP):
            flags = str(pkt[TCP].flags)

            if "R" in flags:
                color = Qt.red
                info += " | RESET"
            elif flags == "S":
                color = Qt.yellow
                info += " | SYN"

        if pkt.haslayer(ICMP):
            color = Qt.yellow

        self.packet_data.append([proto, src, dst, length, info])

        self.add_row(len(self.packet_data), proto, src, dst, length, info, color)


# ================= ADD ROW =================
    def add_row(self, no, proto, src, dst, length, info, color):
        if self.filter_box.currentText() != "ALL":
            if proto != self.filter_box.currentText():
                return

        row = self.table.rowCount()
        self.table.insertRow(row)

        for col, val in enumerate([no, proto, src, dst, length, info]):
            item = QTableWidgetItem(str(val))
            item.setBackground(color)
            self.table.setItem(row, col, item)


# ================= FILTER =================
    def apply_filter(self):
        self.table.setRowCount(0)
        for i, p in enumerate(self.packet_data):
            proto, src, dst, length, info = p
            if self.filter_box.currentText() == "ALL" or proto == self.filter_box.currentText():
                self.add_row(i+1, proto, src, dst, length, info, Qt.white)


# ================= SNIFF =================
    def sniff_thread(self):
        iface = self.interface_box.currentData()
        sniff(iface=iface, prn=self.process_packet, store=False)

    def start_sniff(self):
        self.sniffing = True
        self.packet_data.clear()
        self.table.setRowCount(0)

        self.start_time = time.time()
        self.start_bytes = psutil.net_io_counters().bytes_recv

        threading.Thread(target=self.sniff_thread, daemon=True).start()

    def stop_sniff(self):
        try:
            self.sniffing = False

            duration = time.time() - self.start_time if hasattr(self, "start_time") else 1
            end_bytes = psutil.net_io_counters().bytes_recv

            throughput = (end_bytes - self.start_bytes) / duration if duration > 0 else 0
            rate = len(self.packet_data) / duration if duration > 0 else 0

            # Bandwidth
            stats = psutil.net_if_stats()
            iface = self.interface_box.currentData()

            if iface in stats and stats[iface].speed > 0:
                bandwidth = stats[iface].speed * 1_000_000 / 8
            else:
                bandwidth = 0

            # Packet loss
            if hasattr(self, "total_tcp") and self.total_tcp > 0:
                packet_loss = (self.retransmissions / self.total_tcp) * 100
            else:
                packet_loss = 0

            # Anomaly
            anomaly_score = (
                getattr(self, "retransmissions", 0) +
                getattr(self, "reset_count", 0) +
                getattr(self, "syn_count", 0) +
                getattr(self, "icmp_count", 0)
                )
            
            if anomaly_score < 20:
                anomaly_level = "Low"
            elif anomaly_score < 50:
                anomaly_level = "Medium"
            else:
                anomaly_level = "High"
            
            self.metrics.setText(
                f"Packets: {len(self.packet_data)} \n "
                f"Rate: {rate:.2f} pkt/s \n "
                f"Duration: {duration:.2f}s \n "
                f"Throughput: {throughput:.2f} Bps \n "
                f"Bandwidth: {bandwidth:.2f} Bps \n "
                f"Packet Loss: {packet_loss:.2f}% \n "
                f"Anomaly: {anomaly_level}"
                )
        
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


# ================= EXPORT =================
    def export_packets(self):
        file, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if file:
            with open(file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Protocol","Source","Destination","Length","Info"])
                writer.writerows(self.packet_data)

            QMessageBox.information(self,"Success","Exported successfully")


# ================= ANALYSIS =================
    def analyze_packets(self):
        counts = {}
        for p in self.packet_data:
            counts[p[0]] = counts.get(p[0],0)+1

        plt.figure()
        plt.pie(counts.values(), labels=counts.keys(), autopct="%1.1f%%")
        plt.title("Protocol Distribution")
        plt.show()


# ================= DEVICE SCANNER =================
    def init_device_tab(self):
        layout = QVBoxLayout()

        self.ip_input = QTextEdit()

        self.add_btn = QPushButton("Add IPs")
        self.clear_btn = QPushButton("Clear IPs")
        self.scan_btn = QPushButton("Scan Network")

        self.table_dev = QTableWidget(0,2)
        self.table_dev.setHorizontalHeaderLabels(["IP Address","Status"])

        self.metrics_dev = QLabel()

        layout.addWidget(self.ip_input)
        layout.addWidget(self.add_btn)
        layout.addWidget(self.clear_btn)
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.table_dev)
        layout.addWidget(self.metrics_dev)

        self.device_tab.setLayout(layout)

        self.add_btn.clicked.connect(self.add_ip)
        self.clear_btn.clicked.connect(self.clear_ips)
        self.scan_btn.clicked.connect(self.scan_ips)

        self.ip_list=[]


    def add_ip(self):
        text=self.ip_input.toPlainText()
        new=text.split()

        added=0
        for ip in new:
            if ip not in self.ip_list:
                self.ip_list.append(ip)
                added+=1

        QMessageBox.information(self,"Added",f"{added} IPs added")


    def clear_ips(self):
        count=len(self.ip_list)
        self.ip_list.clear()
        self.table_dev.setRowCount(0)

        QMessageBox.information(self,"Cleared",f"{count} IPs removed")


    def scan_ips(self):
        self.table_dev.setRowCount(0)

        arp=ARP(pdst=self.ip_list)
        ether=Ether(dst="ff:ff:ff:ff:ff:ff")
        packet=ether/arp

        result=srp(packet,timeout=2,verbose=0)[0]
        active=[r.psrc for s,r in result]

        connected=0

        for ip in self.ip_list:
            status="Connected" if ip in active else "Not Connected"
            if status=="Connected":
                connected+=1

            row=self.table_dev.rowCount()
            self.table_dev.insertRow(row)
            self.table_dev.setItem(row,0,QTableWidgetItem(ip))
            self.table_dev.setItem(row,1,QTableWidgetItem(status))

        total=len(self.ip_list)
        self.metrics_dev.setText(
            f"Total: {total} \n Connected: {connected} \n Not Connected: {total-connected}"
        )


# ================= RUN =================
app=QApplication(sys.argv)
window=NetworkTool()
window.show()
sys.exit(app.exec_())