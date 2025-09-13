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
from PySide6 import QtWidgets, QtCore

VERSION = '0.1.0'

# Read env
ROUTER_IP = os.environ.get('ROUTER_IP', '192.168.1.1')
SSH_USERNAME = os.environ.get('SSH_USERNAME', 'root')
SSH_KEY_PATH = os.path.expanduser(os.environ.get('SSH_KEY_PATH', '~/.ssh/id_rsa'))
SSH_PORT = int(os.environ.get('SSH_PORT', '2220'))
WAN_IF = os.environ.get('WAN_IF', 'eth0')
LAN_IF = os.environ.get('LAN_IF', 'eth1')
WIFI_IF = os.environ.get('WIFI_IF', 'wlan0')

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
        for iface in [WAN_IF, LAN_IF, WIFI_IF]:
            rx, tx = self.read_counter(iface)
            if rx is not None:
                self.last[iface] = (rx, tx)
        while self.running:
            now = time.time()
            dt = now - self.last_time if self.last_time else 1.0
            rates = {}
            for iface in [WAN_IF, LAN_IF, WIFI_IF]:
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

class MainWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f'OpenWrt Admin v.{VERSION} (PySide6)')
        self.resize(900, 500)
        main_layout = QtWidgets.QVBoxLayout(self)
        top_layout = QtWidgets.QHBoxLayout()

        # Gauges using QDial and labels
        self.dials = {}
        self.labels = {}
        for name, max_bits in [('WAN', 2_500_000_000), ('LAN', 1_000_000_000), ('WiFi', 600_000_000)]:
            v = QtWidgets.QVBoxLayout()
            dial = QtWidgets.QDial()
            dial.setNotchesVisible(True)
            dial.setRange(0, 1000)
            dial.setEnabled(False)
            lbl = QtWidgets.QLabel(f"{name}\n{bits_to_display(0)}")
            lbl.setAlignment(QtCore.Qt.AlignCenter)
            v.addWidget(dial)
            v.addWidget(lbl)
            top_layout.addLayout(v)
            self.dials[name.lower()] = (dial, max_bits)
            self.labels[name.lower()] = lbl

        main_layout.addLayout(top_layout)

        # Status buttons
        status_layout = QtWidgets.QHBoxLayout()
        self.status_buttons = {}
        for name in ['wan', 'lan', 'wifi']:
            btn = QtWidgets.QPushButton(name.upper())
            btn.setStyleSheet('background-color: grey; color: white')
            status_layout.addWidget(btn)
            self.status_buttons[name] = btn
        main_layout.addLayout(status_layout)

        # Control buttons
        ctrl_layout = QtWidgets.QHBoxLayout()
        tail_btn = QtWidgets.QPushButton('Tail Logs')
        tail_btn.clicked.connect(self.open_tail)
        ctrl_layout.addWidget(tail_btn)
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

    def on_rates(self, rates):
        mapping = {WAN_IF: 'wan', LAN_IF: 'lan', WIFI_IF: 'wifi'}
        for iface, val in rates.items():
            name = mapping.get(iface, None)
            if name in self.dials:
                dial, max_bits = self.dials[name]
                pct = int((val / max_bits) * 1000) if max_bits > 0 else 0
                dial.setValue(min(1000, max(0, pct)))
                self.labels[name].setText(f"{name.upper()}\n{bits_to_display(val)}")
                # set color
                if val > 0:
                    color = 'green'
                else:
                    color = 'red'
                self.status_buttons[name].setStyleSheet(f'background-color: {color}; color: white')

    def open_tail(self):
        self.tail = TailWindow(self.ssh, parent=self)
        self.tail.show()

    def closeEvent(self, event):
        self.monitor.stop()
        event.accept()

def main():
    try:
        app = QtWidgets.QApplication(sys.argv)
    except Exception as e:
        print('PySide6 not installed. Install with: pip install PySide6')
        sys.exit(1)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
