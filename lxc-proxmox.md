# Proxmox LXC deployment notes

## Quick deploy in Proxmox

1. Create a Debian 12 LXC container in Proxmox.
2. Attach it to your LAN bridge (for example vmbr0).
3. Enable Start at boot.
4. Start the container and open shell.
5. Run:

```bash
apt-get update
apt-get install -y git curl
cd /root
git clone https://github.com/SecureSiegel/NetID-LXC.git
chmod +x /root/NetID-LXC/scripts/install-lxc.sh
/root/NetID-LXC/scripts/install-lxc.sh
systemctl start netid-lxc.service
systemctl status netid-lxc.service
```

## Recommended container settings

- Template: Debian 12 (bookworm)
- Privilege: unprivileged or privileged depending on your environment
- Network: default bridge with access to the LAN
- CPU: 1
- Memory: 512 MB minimum
- Storage: local-lvm or default storage

## Install inside the container

```bash
chmod +x /root/NetID-LXC/scripts/install-lxc.sh
/root/NetID-LXC/scripts/install-lxc.sh
```

## Run manually

```bash
/usr/local/bin/netid-lxc 30 /var/lib/netid-lxc/output
```

Argument is passive listen time in seconds (max 60).
Second argument is output directory for JSON files.

Terminal output is a readable table. JSON is saved as:

- `/var/lib/netid-lxc/output/latest.json`
- `/var/lib/netid-lxc/output/run-YYYYMMDD-HHMMSS.json`

## Run via systemd

```bash
systemctl start netid-lxc.service
systemctl status netid-lxc.service
```

To read recent table output from the service:

```bash
journalctl -u netid-lxc.service -n 200 --no-pager
```

## Update an existing Proxmox container

Inside the container:

```bash
cd /opt/netid-lxc
git fetch --all
git checkout main
git pull --ff-only origin main

source "$HOME/.cargo/env" 2>/dev/null || true
cargo build --release
cp target/release/netid-lxc /usr/local/bin/netid-lxc
chmod +x /usr/local/bin/netid-lxc

systemctl daemon-reload
systemctl restart netid-lxc.service
systemctl status netid-lxc.service
journalctl -u netid-lxc.service -n 100 --no-pager
```

One-command alternative:

```bash
chmod +x /opt/netid-lxc/scripts/install-lxc.sh
/opt/netid-lxc/scripts/install-lxc.sh
systemctl restart netid-lxc.service
```

## Troubleshooting

- If you see few results, confirm the container has been on-network long enough for neighbor/ARP and mDNS traffic to accumulate.
- If the container cannot reach the network, check the Proxmox bridge and firewall settings.
- If Rust install fails, rerun the script after ensuring `curl` and `git` are available.
- If interface discovery is empty, verify `iproute2` exists in the container and interfaces are UP with IPv4 addresses.
