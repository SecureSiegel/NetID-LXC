# Proxmox LXC deployment notes

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
/usr/local/bin/netid-lxc 192.168.1.0/24
```

## Run via systemd

```bash
systemctl start netid-lxc.service
systemctl status netid-lxc.service
```

## Troubleshooting

- If you see no results, verify the subnet and that hosts respond to ping.
- If the container cannot reach the network, check the Proxmox bridge and firewall settings.
- If Rust install fails, rerun the script after ensuring `curl` and `git` are available.
