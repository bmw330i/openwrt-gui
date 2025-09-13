# OpenWrt Monitor GUI

A Tkinter and PySide6-based desktop application for real-time monitoring of OpenWrt logs and key metrics on BananaPi One WiFi routers. Includes SSH-based log tailing, filtering, a status dashboard, and a PySide6 prototype dashboard for a modern UI.

## Features
- Real-time log monitoring via SSH (`logread -f`).
- Network gauges for WAN, LAN, and WiFi.
- Status indicators for interface health.
- Tail logs view with live output.
- PySide6 prototype dashboard (modern UI) and Tkinter fallback.
- Placeholder for Ansible playbooks to manage router configuration.

## Requirements
- Python 3.x
- paramiko
- PySide6 (for modern dashboard)

## Setup
1. Clone the repo: `git clone git@github.com:bmw330i/openwrt-gui.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Configure environment variables (do NOT commit secrets):

   export ROUTER_IP=192.168.1.1
   export SSH_USERNAME=root
   export SSH_KEY_PATH=~/.ssh/id_rsa
   export SSH_PORT=2220
   export WAN_IF=eth0
   export LAN_IF=eth1
   export WIFI_IF=wlan0

   (Add these to `~/.zshrc` or source a local file before running.)

4. Run the PySide6 dashboard (recommended):
   `python3 pyside_dashboard.py`

5. Or run the Tkinter app:
   `python3 wrtmongui.py`

## Security
- Keep real credentials out of the repository. Use environment variables or a gitignored config file.

## Contributing
Fork and submit PRs. Ideas: add visual themes, integrate Ansible controls into the UI, support historical charts.

## License
MIT - see LICENSE file.

# openwrt-gui
Mgt Tool for OpenWRT using Tkinter-based GUI
# Ansible Playbooks for OpenWrt Management

This directory will contain Ansible playbooks and roles for remote configuration of your BananaPi router.

## Planned Playbooks
- `firewall.yml`: Update firewall rules.
- `dns.yml`: Configure DNS settings.
- `system.yml`: Manage system updates and services.

## Usage
- Install Ansible: `pip install ansible`
- Run a playbook: `ansible-playbook ansible/firewall.yml -i inventory.ini`

(Inventory and roles to be added in future commits.)
