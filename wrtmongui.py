#!/usr/bin/env python3
"""PySide6 prototype dashboard for OpenWrt Monitor
Provides three dial gauges (WAN, LAN, WiFi), colored status buttons, and a Tail Logs window.
If SSH to the router fails the monitor falls back to simulated data.
"""
import os
import sys
import time
import random
import paramiko
from PySide6 import QtWidgets, QtCore, QtGui
import traceback
import re
import logging
import math
VERSION = '0.1.0'
# Debug startup print
print(f"Starting pyside_dashboard.py version {VERSION} -> PID {os.getpid()}")
# Read env
ROUTER_IP = os.environ.get('ROUTER_IP', '192.168.1.1')
SSH_USERNAME = os.environ.get('SSH_USERNAME', 'root')
SSH_KEY_PATH = os.path.expanduser(os.environ.get('SSH_KEY_PATH', '~/.ssh/id_rsa'))
SSH_PORT = int(os.environ.get('SSH_PORT', '2220'))
WAN_IF = os.environ.get('WAN_IF', 'eth0')
LAN_IF = os.environ.get('LAN_IF', 'eth1')
WIFI_IF = os.environ.get('WIFI_IF', 'br-lan')
# Radio interface names (2.4GHz and 5GHz)
RADIO0_IF = os.environ.get('RADIO0_IF', 'wlan0')
RADIO1_IF = os.environ.get('RADIO1_IF', 'wlan1')
# Interfaces monitored (exclude per-radio entries for now)
INTERFACES = [WAN_IF, LAN_IF, WIFI_IF]
def bits_to_display(bps):
    if bps >= 1e9:
        return f"{bps/1e9:.2f} Gbps"
    if bps >= 1e6:
        return f"{bps/1e6:.2f} Mbps"
    if bps >= 1e3:
        return f"{bps/1e3:.2f} Kbps"
    return f"{bps:.0f} bps"
class MonitorThread(QtCore.QThread):
    rates_signal = QtCore.Signal(dict)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("MonitorThread")
        self.running = True
        self.ssh = None
        self.use_ssh = False
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ROUTER_IP, username=SSH_USERNAME, key_filename=SSH_KEY_PATH, port=SSH_PORT, timeout=3)
            self.ssh = client
            self.use_ssh = True
            # Auto-detect radio interface names (2.4G / 5G) if possible
            try:
                iw_out = self.ssh.exec_command('iw dev')[1].read().decode('utf-8', errors='ignore')
                iface_names = []
                for line in iw_out.splitlines():
                    line = line.strip()
                    if line.startswith('Interface '):
                        parts = line.split()
                        if len(parts) >= 2:
                            iface_names.append(parts[1])
                radio0 = None
                radio1 = None
                for ifname in iface_names:
                    try:
                        info = self.ssh.exec_command(f'iwinfo {ifname} info')[1].read().decode('utf-8', errors='ignore')
                        for l in info.splitlines():
                            if 'Channel' in l and '(' in l and 'MHz' in l:
                                mhz_part = l.split('(')[1]
                                mhz = int(mhz_part.split()[0])
                                if mhz < 3000 and radio0 is None:
                                    radio0 = ifname
                                elif mhz >= 3000 and radio1 is None:
                                    radio1 = ifname
                    except Exception:
                        continue
                if radio0:
                    globals()['RADIO0_IF'] = radio0
                if radio1:
                    globals()['RADIO1_IF'] = radio1
                globals()['INTERFACES'] = [globals().get('WAN_IF'), globals().get('LAN_IF'), globals().get('WIFI_IF'), globals().get('RADIO0_IF'), globals().get('RADIO1_IF')]
            except Exception:
                pass
        except Exception:
            self.use_ssh = False
        self.last = {}
        self.last_time = time.time()
    def read_counter(self, iface):
        if not self.use_ssh:
            return None, None
        try:
            cmd = f"cat /sys/class/net/{iface}/statistics/rx_bytes && echo : && cat /sys/class/net/{iface}/statistics/tx_bytes"
            stdin, stdout, stderr = self.ssh.exec_command(cmd)
            out = stdout.read().decode('utf-8', errors='ignore')
            parts = out.strip().split(':')
            if len(parts) >= 2:
                rx = int(parts[0].strip())
                tx = int(parts[1].strip())
                return rx, tx
        except Exception:
            return None, None
        return None, None
    def run(self):
        for iface in INTERFACES:
            rx, tx = self.read_counter(iface)
            if rx is not None:
                self.last[iface] = (rx, tx)
        while self.running:
            now = time.time()
            dt = now - self.last_time if self.last_time else 1.0
            rates = {}
            for iface in INTERFACES:
                if self.use_ssh:
                    rx, tx = self.read_counter(iface)
                    if rx is None:
                        rates[iface] = 0
                        continue
                    lrx, ltx = self.last.get(iface, (rx, tx))
                    bps = ((rx - lrx) + (tx - ltx)) * 8.0 / max(dt, 0.0001)
                    rates[iface] = max(0, bps)
                    self.last[iface] = (rx, tx)
                else:
                    if iface in (RADIO0_IF, RADIO1_IF):
                        rates[iface] = random.uniform(0, 200e6)
                    else:
                        rates[iface] = random.uniform(0, 500e6)
            self.last_time = now
            self.rates_signal.emit(rates)
            time.sleep(1.0)
    def stop(self):
        self.running = False
        self.wait(5000)
        if self.ssh:
            try:
                self.ssh.close()
            except Exception:
                pass
class TailThread(QtCore.QThread):
    line_signal = QtCore.Signal(str)
    def __init__(self, ssh_client=None, parent=None):
        super().__init__(parent)
        self.setObjectName("TailThread")
        self.ssh_client = ssh_client
        self.running = True
    def run(self):
        if not self.ssh_client:
            i = 0
            while self.running and i < 1000:
                self.line_signal.emit(f"[SIM] log line {i}\n")
                time.sleep(0.5)
                i += 1
            return
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command('logread -f')
            while self.running:
                if stdout.channel.recv_ready():
                    out = stdout.read(1024).decode('utf-8', errors='ignore')
                    if out:
                        self.line_signal.emit(out)
                else:
                    time.sleep(0.1)
        except Exception as e:
            self.line_signal.emit(f"[ERROR] {e}\n")
    def stop(self):
        self.running = False
        self.wait(5000)
class TailWindow(QtWidgets.QWidget):
    def __init__(self, ssh_client=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Tail Logs')
        self.resize(800, 600)
        self.layout = QtWidgets.QVBoxLayout(self)
        self.text = QtWidgets.QTextEdit(self)
        self.text.setReadOnly(True)
        self.layout.addWidget(self.text)
        btn = QtWidgets.QPushButton('Close', self)
        btn.clicked.connect(self.close)
        self.layout.addWidget(btn)
        self.thread = TailThread(ssh_client)
        self.thread.line_signal.connect(self.append_text)
        self.thread.start()
    def append_text(self, text):
        self.text.moveCursor(QtWidgets.QTextCursor.End)
        self.text.insertPlainText(text)
        self.text.moveCursor(QtWidgets.QTextCursor.End)
    def closeEvent(self, event):
        self.thread.stop()
        event.accept()
class SpeedGauge(QtWidgets.QWidget):
    """Custom speedometer-style gauge with gradient arc, arrow needle, and digital display, inspired by AnalogGaugeWidget.
    Uses non-linear (sqrt) scale for better sensitivity at low values.
    """
    def __init__(self, nominal_max_bps, parent=None):
        super().__init__(parent)
        self.nominal_max = nominal_max_bps
        self.dial_max = nominal_max_bps
        self.value_bps = 0.0
        self.start_angle = 225.0
        self.span = -270.0
        self.major_step = self.nominal_max / 10
        self.num_major = 11
        self.minor_step = self.major_step / 5
        self.num_minor = self.num_major * 5 - 4
        self.units = "Mbps"
        self.setMinimumSize(200, 200)
        # Theme colors
        self.background_color = QtGui.QColor("#101010")
        self.needle_color = QtGui.QColor("#ffffff")
        self.scale_value_color = QtGui.QColor("#ffffff")
        self.display_value_color = QtGui.QColor("#00ffff")
        self.big_scale_color = QtGui.QColor("#ffffff")
        self.fine_scale_color = QtGui.QColor("#aaaaaa")
        self.center_inner_color = QtGui.QColor("#ff0000")
        self.center_outer_color = QtGui.QColor("#500000")
        self.enable_bar_graph = True
        self.enable_value_text = True
        self.enable_center_point = True
        self.enable_needle = True
        self.enable_scale_text = True
        self.enable_big_scale = True
        self.enable_fine_scale = True
    def setValue(self, bps):
        try:
            v = float(bps)
        except Exception:
            v = 0.0
        self.value_bps = max(0.0, v)
        self.update()
    def get_pc(self, value):
        if value <= 0:
            return 0.0
        return math.sqrt(value) / math.sqrt(self.dial_max)
    def paintEvent(self, event):
        r = min(self.width(), self.height())
        center = QtCore.QPoint(self.width() // 2, self.height() // 2)
        radius = int(r * 0.45)
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.translate(center)
        # Draw background
        painter.setBrush(self.background_color)
        painter.setPen(QtCore.Qt.NoPen)
        painter.drawEllipse(-radius-10, -radius-10, 2*(radius+10), 2*(radius+10))
        # Draw gradient arc
        if self.enable_bar_graph:
            gradient = QtGui.QConicalGradient(0, 0, self.start_angle)
            gradient.setColorAt(0.0, QtGui.QColor('#00ff00'))
            gradient.setColorAt(0.799, QtGui.QColor('#00ff00'))
            gradient.setColorAt(0.8, QtGui.QColor('#ffff00'))
            gradient.setColorAt(0.949, QtGui.QColor('#ffff00'))
            gradient.setColorAt(0.95, QtGui.QColor('#ff0000'))
            gradient.setColorAt(1.0, QtGui.QColor('#ff0000'))
            pen = QtGui.QPen()
            pen.setWidth(20)
            pen.setBrush(gradient)
            painter.setPen(pen)
            rect = QtCore.QRectF(-radius, -radius, 2*radius, 2*radius)
            painter.drawArc(rect, self.start_angle * 16, self.span * 16)
        # Draw major ticks and labels
        if self.enable_big_scale:
            label_font = painter.font()
            label_font.setPointSize(7)
            painter.setFont(label_font)
            fm = painter.fontMetrics()
            for i in range(self.num_major):
                tick_value = i * self.major_step
                pc = self.get_pc(tick_value)
                angle = self.start_angle + (self.span * pc)
                rad = math.radians(angle)
                outer = QtCore.QPointF(math.cos(rad) * (radius - 10), math.sin(rad) * (radius - 10))
                tick_length = 12 if i < self.num_major - 1 else 16
                inner = QtCore.QPointF(math.cos(rad) * (radius - 10 - tick_length), math.sin(rad) * (radius - 10 - tick_length))
                pen = QtGui.QPen(self.big_scale_color)
                pen.setWidth(2)
                painter.setPen(pen)
                painter.drawLine(outer, inner)
                if self.enable_scale_text:
                    label_val = f"{int(i * (self.major_step / 1e6))}"
                    tx = math.cos(rad) * (radius - 30) - fm.horizontalAdvance(label_val) / 2
                    ty = math.sin(rad) * (radius - 30) + fm.ascent() / 2
                    painter.setPen(self.scale_value_color)
                    painter.drawText(QtCore.QPointF(tx, ty), label_val)
        # Draw minor ticks
        if self.enable_fine_scale:
            for i in range(self.num_minor):
                if i % 5 == 0:
                    continue
                tick_value = i * self.minor_step
                pc = self.get_pc(tick_value)
                angle = self.start_angle + self.span * pc
                rad = math.radians(angle)
                outer = QtCore.QPointF(math.cos(rad) * (radius - 10), math.sin(rad) * (radius - 10))
                inner = QtCore.QPointF(math.cos(rad) * (radius - 10 - 8), math.sin(rad) * (radius - 10 - 8))
                pen = QtGui.QPen(self.fine_scale_color)
                pen.setWidth(1)
                painter.setPen(pen)
                painter.drawLine(outer, inner)
        # Draw needle
        if self.enable_needle:
            pc = self.get_pc(min(self.value_bps, self.dial_max))
            angle = self.start_angle + (self.span * pc)
            rad = math.radians(angle)
            tip = QtCore.QPointF(math.cos(rad) * (radius - 20), math.sin(rad) * (radius - 20))
            perp_rad = rad + math.pi / 2
            base_left = QtCore.QPointF(math.cos(perp_rad) * 5, math.sin(perp_rad) * 5)
            base_right = QtCore.QPointF(math.cos(perp_rad + math.pi) * 5, math.sin(perp_rad + math.pi) * 5)
            points = [base_left, tip, base_right]
            painter.setBrush(self.needle_color)
            painter.setPen(QtCore.Qt.NoPen)
            painter.drawConvexPolygon(points)
        # Draw center point
        if self.enable_center_point:
            radial = QtGui.QRadialGradient(0, 0, 20)
            radial.setColorAt(0, self.center_inner_color)
            radial.setColorAt(1, self.center_outer_color)
            painter.setBrush(radial)
            painter.drawEllipse(-10, -10, 20, 20)
        # Draw value text
        if self.enable_value_text:
            painter.setPen(self.display_value_color)
            font = painter.font()
            font.setBold(True)
            font.setPointSize(16)
            painter.setFont(font)
            value_text = f"{int(self.value_bps / 1e6)}"
            fm = painter.fontMetrics()
            painter.drawText(QtCore.QPointF(-fm.horizontalAdvance(value_text)/2, fm.height()/3), value_text)
        # Draw units
        painter.setPen(QtGui.QColor('#ffffff'))
        font.setPointSize(8)
        painter.setFont(font)
        units_text = self.units
        fm = painter.fontMetrics()
        painter.drawText(QtCore.QPointF(-fm.horizontalAdvance(units_text)/2, fm.height() + 10), units_text)
class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f'OpenWrt Admin v.{VERSION} (PySide6)')
        self.resize(900, 500)
        main_layout = QtWidgets.QVBoxLayout(self)
        top_layout = QtWidgets.QHBoxLayout()
        self.gauges_widget = QtWidgets.QWidget(self)
        self.gauges_widget.setLayout(top_layout)
        self.dials = {}
        self.labels = {}
        self.value_labels = {}
        for name, max_bits in [('WAN', 1_000_000_000), ('LAN', 1_000_000_000), ('WiFi', 600_000_000)]:
            v = QtWidgets.QVBoxLayout()
            gauge = SpeedGauge(max_bits)
            v.addWidget(gauge, alignment=QtCore.Qt.AlignCenter)
            lbl = QtWidgets.QLabel(name.upper())
            lbl.setAlignment(QtCore.Qt.AlignCenter)
            v.addWidget(lbl)
            val_lbl = QtWidgets.QLabel(bits_to_display(0))
            val_lbl.setAlignment(QtCore.Qt.AlignCenter)
            v.addWidget(val_lbl)
            top_layout.addLayout(v)
            key = name.lower()
            self.dials[key] = (gauge, max_bits)
            self.labels[key] = lbl
            self.value_labels[key] = val_lbl
        main_layout.addWidget(self.gauges_widget)
        status_layout = QtWidgets.QHBoxLayout()
        self.status_widget = QtWidgets.QWidget(self)
        self.status_widget.setLayout(status_layout)
        self.status_indicators = {}
        for name in ['wan', 'lan', 'wifi']:
            v = QtWidgets.QVBoxLayout()
            color_lbl = QtWidgets.QLabel()
            color_lbl.setFixedSize(24, 24)
            color_lbl.setStyleSheet('background-color: grey; border-radius: 12px;')
            name_lbl = QtWidgets.QLabel(name.upper())
            name_lbl.setAlignment(QtCore.Qt.AlignCenter)
            v.addWidget(color_lbl, alignment=QtCore.Qt.AlignCenter)
            v.addWidget(name_lbl)
            status_layout.addLayout(v)
            self.status_indicators[name] = color_lbl
        main_layout.addWidget(self.status_widget)
        ctrl_layout = QtWidgets.QHBoxLayout()
        tail_btn = QtWidgets.QPushButton('Tail Logs')
        tail_btn.clicked.connect(self.open_tail)
        ctrl_layout.addWidget(tail_btn)
        dns_btn = QtWidgets.QPushButton('DNS')
        dns_btn.clicked.connect(self.show_dns_view)
        ctrl_layout.addWidget(dns_btn)
        exit_btn = QtWidgets.QPushButton('Exit')
        exit_btn.clicked.connect(self.close)
        ctrl_layout.addWidget(exit_btn)
        self.back_btn = QtWidgets.QPushButton('Back')
        self.back_btn.clicked.connect(self.show_main_view)
        self.back_btn.hide()
        ctrl_layout.addWidget(self.back_btn)
        main_layout.addLayout(ctrl_layout)
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(ROUTER_IP, username=SSH_USERNAME, key_filename=SSH_KEY_PATH, port=SSH_PORT, timeout=3)
        except Exception:
            self.ssh = None
        self.monitor = MonitorThread()
        self.monitor.rates_signal.connect(self.on_rates)
        self.monitor.start()
        self.dns_widget = QtWidgets.QWidget(self)
        dns_layout = QtWidgets.QVBoxLayout(self.dns_widget)
        self.leases_table = QtWidgets.QTableWidget(0, 5)
        self.leases_table.setHorizontalHeaderLabels(['IP', 'MAC', 'Hostname', 'Expires', 'Status'])
        self.leases_table.horizontalHeader().setStretchLastSection(True)
        dns_layout.addWidget(self.leases_table)
        self.dns_widget.hide()
        main_layout.addWidget(self.dns_widget)
        self.leases_thread = LeasesThread(self.ssh)
        self.leases_thread.leases_signal.connect(self.update_leases_table)
        self.leases_thread.start()
    def on_rates(self, rates):
        mapping = {WAN_IF: 'wan', LAN_IF: 'lan', WIFI_IF: 'wifi'}
        for iface, val in rates.items():
            name = mapping.get(iface, None)
            if not name:
                continue
            key = name.lower()
            if key in self.dials:
                gauge, max_bits = self.dials[key]
                gauge.setValue(val)
                disp = bits_to_display(val)
                self.value_labels[key].setText(disp)
                self.labels[key].setText(name.upper())
                dot = self.status_indicators.get(name)
                if dot:
                    dot_color = 'green' if val > 0 else 'red'
                    dot.setStyleSheet(f'background-color: {dot_color}; border-radius: 12px;')
    def update_leases_table(self, leases):
        self.leases_table.setRowCount(0)
        for lease in leases:
            row = self.leases_table.rowCount()
            self.leases_table.insertRow(row)
            self.leases_table.setItem(row, 0, QtWidgets.QTableWidgetItem(lease.get('ip', '')))
            self.leases_table.setItem(row, 1, QtWidgets.QTableWidgetItem(lease.get('mac', '')))
            self.leases_table.setItem(row, 2, QtWidgets.QTableWidgetItem(lease.get('name', '')))
            self.leases_table.setItem(row, 3, QtWidgets.QTableWidgetItem(lease.get('expires', '')))
            self.leases_table.setItem(row, 4, QtWidgets.QTableWidgetItem(lease.get('status', '')))
            color = QtCore.Qt.white
            if lease.get('status') == 'known':
                color = QtCore.Qt.green
            elif lease.get('status') == 'named':
                color = QtCore.Qt.yellow
            else:
                color = QtCore.Qt.red
            for c in range(5):
                item = self.leases_table.item(row, c)
                if item:
                    item.setBackground(QtGui.QColor(color))
    def open_tail(self):
        self.tail = TailWindow(self.ssh, parent=self)
        self.tail.show()
    def closeEvent(self, event):
        self.monitor.stop()
        self.leases_thread.stop()
        if hasattr(self, 'tail'):
            self.tail.close()
        event.accept()
    def show_dns_view(self):
        try:
            self.gauges_widget.hide()
            self.status_widget.hide()
            self.dns_widget.show()
            self.back_btn.show()
        except Exception:
            pass
    def show_main_view(self):
        try:
            self.gauges_widget.show()
            self.status_widget.show()
            self.dns_widget.hide()
            self.back_btn.hide()
        except Exception:
            pass
class LeasesThread(QtCore.QThread):
    leases_signal = QtCore.Signal(list)
    def __init__(self, ssh_client=None, parent=None):
        super().__init__(parent)
        self.setObjectName("LeasesThread")
        self.ssh = ssh_client
        self.running = True
    def parse_dhcp_config(self, content):
        hosts_by_mac = {}
        hosts_by_name = set()
        hosts_by_ip = {}
        for m in re.finditer(r"config\s+host([\s\S]*?)(?=\nconfig\s|\Z)", content, re.IGNORECASE):
            block = m.group(1)
            mac = None
            name = None
            ip = None
            for line in block.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(None, 2)
                if len(parts) >= 3 and parts[0].lower() == 'option':
                    key = parts[1].lower()
                    val = parts[2].strip().strip("'\"")
                    if key == 'mac':
                        mac = val.lower()
                    elif key == 'name':
                        name = val
                    elif key == 'ip':
                        ip = val
            if mac:
                hosts_by_mac[mac] = {'mac': mac, 'name': name, 'ip': ip}
            if name:
                hosts_by_name.add(name.lower())
            if ip:
                hosts_by_ip[ip] = {'mac': mac, 'name': name}
        return hosts_by_mac, hosts_by_name, hosts_by_ip
    def run(self):
        while self.running:
            leases = []
            try:
                if not self.ssh:
                    if os.path.exists('/tmp/dhcp.leases'):
                        with open('/tmp/dhcp.leases', encoding='utf-8', errors='ignore') as f:
                            lease_lines = f.read().splitlines()
                    else:
                        lease_lines = []
                    if os.path.exists('/etc/config/dhcp'):
                        with open('/etc/config/dhcp', encoding='utf-8', errors='ignore') as f:
                            dhcp_conf = f.read()
                    else:
                        dhcp_conf = ''
                else:
                    out = self.ssh.exec_command('cat /tmp/dhcp.leases')[1].read().decode('utf-8', errors='ignore')
                    lease_lines = out.splitlines()
                    dhcp_conf = self.ssh.exec_command('cat /etc/config/dhcp')[1].read().decode('utf-8', errors='ignore')
                hosts_by_mac, hosts_by_name, hosts_by_ip = self.parse_dhcp_config(dhcp_conf)
                logging.debug("Parsed hosts_by_mac keys: %s", list(hosts_by_mac.keys()))
                logging.debug("Parsed hosts_by_name: %s", list(hosts_by_name))
                logging.debug("Parsed hosts_by_ip: %s", list(hosts_by_ip.keys()))
                for ln in lease_lines:
                    parts = ln.split()
                    if len(parts) >= 4:
                        expiry = parts[0]
                        mac = parts[1].lower()
                        ip = parts[2]
                        name = parts[3]
                        status = 'unknown'
                        lname = name.lower() if name else ''
                        if mac in hosts_by_mac:
                            status = 'known'
                        elif ip in hosts_by_ip:
                            status = 'known'
                        elif lname in hosts_by_name:
                            status = 'named'
                        else:
                            cleaned_mac = re.sub(r'[^0-9a-f]', '', mac.lower())
                            for hmac in hosts_by_mac.keys():
                                if cleaned_mac == re.sub(r'[^0-9a-f]', '', hmac.lower()):
                                    status = 'known'
                                    break
                        if status == 'unknown':
                            logging.debug("Lease unmatched: ip=%s mac=%s name=%s", ip, mac, name)
                        try:
                            exp_int = int(expiry)
                            remaining = max(0, exp_int - int(time.time()))
                            days = remaining // 86400
                            hours = (remaining % 86400) // 3600
                            minutes = (remaining % 3600) // 60
                            expires_str = f"{days:02d}:{hours:02d}:{minutes:02d}"
                        except Exception:
                            expires_str = expiry
                        leases.append({'ip': ip, 'mac': mac, 'name': name, 'expires': expires_str, 'status': status})
                status_order = {'known': 0, 'named': 1, 'unknown': 2}
                leases.sort(key=lambda l: (status_order.get(l.get('status'), 2), (l.get('name') or '').lower(), l.get('ip')))
            except Exception:
                leases = []
            self.leases_signal.emit(leases)
            time.sleep(10)
    def stop(self):
        self.running = False
        self.wait(5000)
def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
if __name__ == '__main__':
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
