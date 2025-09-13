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
