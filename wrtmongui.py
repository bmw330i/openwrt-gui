import tkinter as tk
from tkinter import scrolledtext, messagebox
import paramiko
import threading
import re
import os
import time

# Constants (from your setup)
ROUTER_IP = '192.168.1.1'
SSH_USERNAME = 'root'
SSH_KEY_PATH = os.path.expanduser('~/.ssh/id_rsa')
SSH_PORT = 2220

class LogTailerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("OpenWrt Log Monitor")
        self.root.geometry("800x600")

        # SSH Client
        self.client = None
        self.stdout = None  # Changed from channel to stdout
        self.tailing = False
        self.thread = None

        # Metrics for status bar
        self.metrics = {
            'dhcp_leases': 0,
            'dns_queries': 0,
            'firewall_drops': 0,
            'last_update': time.strftime('%Y-%m-%d %H:%M:%S')
        }

        # GUI Elements
        self.setup_gui()

    def setup_gui(self):
        # Buttons Frame
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="Start Tailing", command=self.start_tailing).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Stop Tailing", command=self.stop_tailing).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Reconnect", command=self.connect_ssh).pack(side=tk.LEFT, padx=5)

        # Filter Entry
        tk.Label(btn_frame, text="Filter (e.g., dnsmasq):").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        tk.Entry(btn_frame, textvariable=self.filter_var, width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Apply Filter", command=self.apply_filter).pack(side=tk.LEFT, padx=5)

        # Log Display
        self.log_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state=tk.DISABLED, bg='black', fg='white')
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Status Bar for Metrics
        self.status_var = tk.StringVar()
        self.update_status_bar()
        tk.Label(self.root, textvariable=self.status_var, bg='black', fg='white', anchor='w').pack(fill=tk.X, padx=5, pady=2)

        # Configure color tags
        self.log_text.tag_configure('red', foreground='red')
        self.log_text.tag_configure('yellow', foreground='yellow')
        self.log_text.tag_configure('green', foreground='green')

        # Connect on startup
        self.connect_ssh()

    def update_status_bar(self):
        """Update status bar with metrics."""
        status = (f"DHCP Leases: {self.metrics['dhcp_leases']} | DNS Queries: {self.metrics['dns_queries']} | "
                  f"Firewall Drops: {self.metrics['firewall_drops']} | Last Update: {self.metrics['last_update']}")
        self.status_var.set(status)

    def connect_ssh(self):
        """Establish SSH connection."""
        try:
            if self.client:
                self.client.close()
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(ROUTER_IP, username=SSH_USERNAME, key_filename=SSH_KEY_PATH, port=SSH_PORT)
            messagebox.showinfo("Success", "SSH Connected!")
        except Exception as e:
            messagebox.showerror("Error", f"SSH Connection Failed: {e}")

    def start_tailing(self):
        """Start tailing logs in a separate thread."""
        if not self.client:
            messagebox.showerror("Error", "Connect SSH first!")
            return
        if self.tailing:
            return
        self.tailing = True
        self.thread = threading.Thread(target=self.tail_logs, daemon=True)
        self.thread.start()
        # Start periodic metrics update
        self.update_metrics()

    def stop_tailing(self):
        """Stop tailing logs."""
        self.tailing = False
        if self.stdout:
            self.stdout.close()
            self.stdout = None

    def tail_logs(self):
        """Tail logs using logread -f."""
        try:
            stdin, stdout, stderr = self.client.exec_command('logread -f')
            self.stdout = stdout
            while self.tailing:
                if stdout.channel.recv_ready():
                    output = stdout.read(1024).decode('utf-8', errors='ignore')
                    if output:
                        self.insert_log(output)
                else:
                    time.sleep(0.1)  # Avoid busy loop
        except Exception as e:
            self.insert_log(f"[ERROR] Tailing failed: {e}\n")
        finally:
            self.tailing = False
            if self.stdout:
                self.stdout.close()
                self.stdout = None

    def insert_log(self, text):
        """Insert log lines into the text widget with color-coding."""
        def update_gui():
            self.log_text.config(state=tk.NORMAL)
            for line in text.split('\n'):
                if not line.strip():
                    continue
                color = 'white'
                # Parse for metrics
                if 'DHCPACK' in line:
                    self.metrics['dhcp_leases'] += 1
                if 'query[A]' in line or 'query[AAAA]' in line:
                    self.metrics['dns_queries'] += 1
                if 'REJECT' in line or 'DROP' in line:
                    self.metrics['firewall_drops'] += 1
                # Color-code based on log level
                if 'daemon.err' in line or 'kern.err' in line:
                    color = 'red'
                elif 'daemon.warn' in line or 'kern.warn' in line:
                    color = 'yellow'
                elif 'daemon.info' in line or 'daemon.notice' in line:
                    color = 'green'
                # Apply filter
                if self.filter_var.get() and self.filter_var.get().lower() not in line.lower():
                    continue
                self.log_text.insert(tk.END, line + '\n', color)
            self.log_text.config(state=tk.DISABLED)
            self.log_text.see(tk.END)  # Auto-scroll
        self.root.after(0, update_gui)

    def update_metrics(self):
        """Periodically update metrics in status bar."""
        if self.tailing:
            self.metrics['last_update'] = time.strftime('%Y-%m-%d %H:%M:%S')
            self.update_status_bar()
            self.root.after(60000, self.update_metrics)  # Update every 60 seconds

    def clear_log(self):
        """Clear the log display."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        # Reset metrics
        self.metrics['dhcp_leases'] = 0
        self.metrics['dns_queries'] = 0
        self.metrics['firewall_drops'] = 0
        self.update_status_bar()

    def apply_filter(self):
        """Apply filter by restarting tailing."""
        if self.tailing:
            self.stop_tailing()
            self.start_tailing()

if __name__ == "__main__":
    root = tk.Tk()
    app = LogTailerGUI(root)
    root.mainloop()