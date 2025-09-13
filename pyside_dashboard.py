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
                                # e.g. "Channel: 1 (2412 MHz)"
                                mhz_part = l.split('(')[1]
                                mhz = int(mhz_part.split()[0])
                                if mhz < 3000 and radio0 is None:
                                    radio0 = ifname
                                elif mhz >= 3000 and radio1 is None:
                                    radio1 = ifname
                    except Exception:
                        continue
                # update globals so UI mapping uses detected names
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
        # warm-up
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
                    # simulated data
                    # use smaller simulated values for radios
                    if iface in (RADIO0_IF, RADIO1_IF):
                        rates[iface] = random.uniform(0, 200e6)
                    else:
                        rates[iface] = random.uniform(0, 500e6)
            self.last_time = now
            self.rates_signal.emit(rates)
            time.sleep(1.0)

    def stop(self):
        self.running = False
        self.wait(2000)
        if self.ssh:
            try:
                self.ssh.close()
            except Exception:
                pass

class TailThread(QtCore.QThread):
    line_signal = QtCore.Signal(str)

    def __init__(self, ssh_client=None, parent=None):
        super().__init__(parent)
        self.ssh_client = ssh_client
        self.running = True

    def run(self):
        if not self.ssh_client:
            # emit simulated lines
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
        self.wait(2000)

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

class GaugeWidget(QtWidgets.QWidget):
    """Custom circular dial gauge with tick marks and numeric labels every 10%.
    Value is expressed as percentage 0..100 via setValue().
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = 0.0
        self.setMinimumSize(160, 160)

    def setValue(self, value):
        try:
            v = float(value)
        except Exception:
            v = 0.0
        self._value = max(0.0, min(100.0, v))
        self.update()

    def paintEvent(self, event):
        r = min(self.width(), self.height())
        center = QtCore.QPoint(self.width() // 2, self.height() // 2)
        radius = int(r * 0.4)

        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.translate(center)

        # Background
        painter.setBrush(QtGui.QColor('#111111'))
        painter.setPen(QtCore.Qt.NoPen)
        painter.drawEllipse(QtCore.QPoint(0, 0), radius + 10, radius + 10)

        # Draw ticks from -120 to +120 degrees
        start_angle = -120.0
        span = 240.0
        for i in range(0, 101):
            angle = start_angle + (span * i / 100.0)
            rad = math.radians(angle)
            outer = QtCore.QPointF(math.cos(rad) * radius, math.sin(rad) * radius)
            if i % 10 == 0:
                inner = QtCore.QPointF(math.cos(rad) * (radius - 16), math.sin(rad) * (radius - 16))
                pen = QtGui.QPen(QtGui.QColor('#dddddd'))
                pen.setWidth(2)
                painter.setPen(pen)
                painter.drawLine(outer, inner)
                # label
                label_val = str(i)
                fm = painter.fontMetrics()
                tx = math.cos(rad) * (radius - 30) - fm.horizontalAdvance(label_val) / 2
                ty = math.sin(rad) * (radius - 30) + fm.height() / 4
                painter.setPen(QtGui.QColor('#ffffff'))
                painter.drawText(QtCore.QPointF(tx, ty), label_val)
            else:
                inner = QtCore.QPointF(math.cos(rad) * (radius - 8), math.sin(rad) * (radius - 8))
                pen = QtGui.QPen(QtGui.QColor('#888888'))
                pen.setWidth(1)
                painter.setPen(pen)
                painter.drawLine(outer, inner)

        # Draw arc (background)
        pen = QtGui.QPen(QtGui.QColor('#444444'))
        pen.setWidth(6)
        painter.setPen(pen)
        rect = QtCore.QRectF(-radius, -radius, radius*2, radius*2)
        painter.drawArc(rect, int((start_angle - 90) * 16), int(span * 16))

        # Draw needle
        angle = start_angle + (span * (self._value / 100.0))
        rad = math.radians(angle)
        needle = QtCore.QPointF(math.cos(rad) * (radius - 18), math.sin(rad) * (radius - 18))
        pen = QtGui.QPen(QtGui.QColor('#ff3333'))
        pen.setWidth(3)
        painter.setPen(pen)
        painter.drawLine(QtCore.QPointF(0, 0), needle)

        # Center cap
        painter.setBrush(QtGui.QColor('#000000'))
        painter.setPen(QtGui.QColor('#666666'))
        painter.drawEllipse(QtCore.QPointF(0, 0), 6, 6)

        # Numeric center value
        painter.setPen(QtGui.QColor('#ffffff'))
        font = painter.font()
        font.setBold(True)
        font.setPointSize(10)
        painter.setFont(font)
        value_text = f"{int(self._value)}%"
        fm = painter.fontMetrics()
        painter.drawText(QtCore.QPointF(-fm.horizontalAdvance(value_text)/2, fm.height()/4), value_text)

class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f'OpenWrt Admin v.{VERSION} (PySide6)')
        self.resize(900, 500)
        main_layout = QtWidgets.QVBoxLayout(self)
        top_layout = QtWidgets.QHBoxLayout()

        # Gauges using custom GaugeWidget (dial) for WAN, LAN, WiFi
        self.dials = {}
        self.labels = {}
        self.value_labels = {}
        for name, max_bits in [('WAN', 2_500_000_000), ('LAN', 1_000_000_000), ('WiFi', 600_000_000)]:
            v = QtWidgets.QVBoxLayout()
            gauge = GaugeWidget()
            v.addWidget(gauge, alignment=QtCore.Qt.AlignCenter)
            lbl = QtWidgets.QLabel(f"{name}\n{bits_to_display(0)}")
            lbl.setAlignment(QtCore.Qt.AlignCenter)
            v.addWidget(lbl)
            # numeric below
            val_lbl = QtWidgets.QLabel(bits_to_display(0))
            val_lbl.setAlignment(QtCore.Qt.AlignCenter)
            v.addWidget(val_lbl)
            top_layout.addLayout(v)
            key = name.lower()
            self.dials[key] = (gauge, max_bits)
            self.labels[key] = lbl
            self.value_labels[key] = val_lbl

        main_layout.addLayout(top_layout)

        # Status buttons -> round indicator lights
        status_layout = QtWidgets.QHBoxLayout()
        self.status_indicators = {}
        self.status_values = {}
        for name in ['wan', 'lan', 'wifi']:
            v = QtWidgets.QVBoxLayout()
            color_lbl = QtWidgets.QLabel()
            color_lbl.setFixedSize(24, 24)
            color_lbl.setStyleSheet('background-color: grey; border-radius: 12px;')
            name_lbl = QtWidgets.QLabel(name.upper())
            name_lbl.setAlignment(QtCore.Qt.AlignCenter)
            value_lbl = QtWidgets.QLabel(bits_to_display(0))
            value_lbl.setAlignment(QtCore.Qt.AlignCenter)
            v.addWidget(color_lbl, alignment=QtCore.Qt.AlignCenter)
            v.addWidget(name_lbl)
            v.addWidget(value_lbl)
            status_layout.addLayout(v)
            self.status_indicators[name] = color_lbl
            self.status_values[name] = value_lbl
        main_layout.addLayout(status_layout)

        # Control buttons
        ctrl_layout = QtWidgets.QHBoxLayout()
        tail_btn = QtWidgets.QPushButton('Tail Logs')
        tail_btn.clicked.connect(self.open_tail)
        ctrl_layout.addWidget(tail_btn)
        exit_btn = QtWidgets.QPushButton('Exit')
        exit_btn.clicked.connect(self.close)
        ctrl_layout.addWidget(exit_btn)
        main_layout.addLayout(ctrl_layout)

        # SSH client attempt
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(ROUTER_IP, username=SSH_USERNAME, key_filename=SSH_KEY_PATH, port=SSH_PORT, timeout=3)
        except Exception:
            self.ssh = None

        # start monitor thread
        self.monitor = MonitorThread()
        self.monitor.rates_signal.connect(self.on_rates)
        self.monitor.start()

        # DHCP leases table
        self.leases_table = QtWidgets.QTableWidget(0, 5)
        self.leases_table.setHorizontalHeaderLabels(['IP', 'MAC', 'Hostname', 'Expires', 'Status'])
        self.leases_table.horizontalHeader().setStretchLastSection(True)
        main_layout.addWidget(self.leases_table)

        # Start leases thread
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
                # percent of interface maximum 0..100
                percent = (val / max_bits) * 100.0 if max_bits > 0 else 0.0
                gauge.setValue(percent)
                # color thresholds relative to max
                if percent >= 100.0:
                    color = '#cc0000'
                elif percent >= 90.0:
                    color = '#ffcc00'
                else:
                    color = '#33cc33'
                # update numeric displays
                disp = bits_to_display(val)
                self.value_labels[key].setText(disp)
                self.labels[key].setText(name.upper())
                # status indicator color and numeric
                dot = self.status_indicators.get(name)
                if dot:
                    dot_color = 'green' if val > 0 else 'red'
                    dot.setStyleSheet(f'background-color: {dot_color}; border-radius: 12px;')
                sval = self.status_values.get(name)
                if sval:
                    sval.setText(disp)

    def update_leases_table(self, leases):
        # leases: list of dicts with keys ip, mac, name, expires, status
        self.leases_table.setRowCount(0)
        for lease in leases:
            row = self.leases_table.rowCount()
            self.leases_table.insertRow(row)
            self.leases_table.setItem(row, 0, QtWidgets.QTableWidgetItem(lease.get('ip', '')))
            self.leases_table.setItem(row, 1, QtWidgets.QTableWidgetItem(lease.get('mac', '')))
            self.leases_table.setItem(row, 2, QtWidgets.QTableWidgetItem(lease.get('name', '')))
            self.leases_table.setItem(row, 3, QtWidgets.QTableWidgetItem(lease.get('expires', '')))
            self.leases_table.setItem(row, 4, QtWidgets.QTableWidgetItem(lease.get('status', '')))
            # color row
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
        event.accept()

# New LeasesThread implementation
class LeasesThread(QtCore.QThread):
    leases_signal = QtCore.Signal(list)

    def __init__(self, ssh_client=None, parent=None):
        super().__init__(parent)
        self.ssh = ssh_client
        self.running = True

    def parse_dhcp_config(self, content):
        hosts_by_mac = {}
        hosts_by_name = set()
        hosts_by_ip = {}
        # find all 'config host' blocks
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
                    # try local files
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
                        # normalize name for comparison
                        lname = name.lower() if name else ''
                        # Primary checks: exact MAC
                        if mac in hosts_by_mac:
                            status = 'known'
                        # fallback: IP match
                        elif ip in hosts_by_ip:
                            status = 'known'
                        # fallback: hostname match
                        elif lname in hosts_by_name:
                            status = 'named'
                        else:
                            # try relaxed MAC matching: compare MACs ignoring separators
                            cleaned_mac = re.sub(r'[^0-9a-f]', '', mac.lower())
                            for hmac in hosts_by_mac.keys():
                                if cleaned_mac == re.sub(r'[^0-9a-f]', '', hmac.lower()):
                                    status = 'known'
                                    break
                        if status == 'unknown':
                            logging.debug("Lease unmatched: ip=%s mac=%s name=%s", ip, mac, name)
                        # convert expiry epoch to remaining DD:HH:MM
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
                # sort leases by status: known, named, unknown, then by name/ip
                status_order = {'known': 0, 'named': 1, 'unknown': 2}
                leases.sort(key=lambda l: (status_order.get(l.get('status'), 2), (l.get('name') or '').lower(), l.get('ip')))
            except Exception:
                leases = []
            self.leases_signal.emit(leases)
            time.sleep(10)

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
