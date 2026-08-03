# NetID-LXC

A quiet Rust-based Linux LAN inventory tool designed for Proxmox LXC environments. The binary performs passive discovery only (no active probing), correlates local network evidence, and outputs a JSON device inventory with confidence scoring.

## Features

- Enumerates UP interfaces and directly-connected IPv4 subnets
- Reads IPv4 neighbor/ARP table snapshots (with light refresh fallback)
- Enriches MAC addresses with offline OUI vendor mapping
- Parses local DHCP lease/log state for host hints
- Performs passive mDNS/DNS-SD listening (and optional SSDP capture) for up to 60s
- Performs limited reverse DNS only for already-seen IP addresses
- Classifies devices with confidence scoring and contributing evidence
- Builds as a small Linux container image

## Passive workflow summary

1. Enumerate UP interfaces and connected subnets
2. Snapshot neighbor/ARP table entries
3. Map MAC OUI prefixes to vendor (offline)
4. Parse local DHCP lease/client state
5. Passive mDNS/DNS-SD and SSDP listening (max 60s)
6. Limited reverse DNS hints (timeouts + capped concurrency)
7. Confidence-scored device classification

The program prints stage progress so you can see active interfaces, estimated runtime, and keep-alive progress while passive listening is running.

## Output schema (per device)

- ips
- macs
- interface
- observed_hostnames
- observed_instances
- observed_mdns_services
- observed_ssdp_services
- vendor
- category
- confidence
- confidence_sources
- first_seen
- last_seen

## Build locally

```bash
cargo build --release
```

## Run locally

```bash
./target/release/netid-lxc 30
```

Argument is listen duration in seconds, capped to 60. If omitted, default is 30.

## Container build

```bash
docker build -t netid-lxc:latest .
```

Run the container in host network mode:

```bash
docker run --rm --network host netid-lxc:latest 30
```

## Proxmox LXC notes

For Proxmox, deploy a Debian-based LXC container and run the LXC installer script:

```bash
chmod +x /root/NetID-LXC/scripts/install-lxc.sh
/root/NetID-LXC/scripts/install-lxc.sh
```

The script installs Rust, clones the repository into `/opt/netid-lxc`, builds the binary, installs it to `/usr/local/bin/netid-lxc`, and creates a systemd service that runs it on startup.

For manual execution inside the container:

```bash
/usr/local/bin/netid-lxc 30
```

## Deploy as a Proxmox container (LXC)

1. In Proxmox, create a new Debian 12 LXC container.
2. Recommended settings:
- Network on your LAN bridge (for example vmbr0)
- Start on boot enabled
- At least 1 vCPU and 512 MB RAM
3. Start the container and open its shell.
4. Install required base tools:

```bash
apt-get update
apt-get install -y git curl
```

5. Clone and run installer:

```bash
cd /root
git clone https://github.com/SecureSiegel/NetID-LXC.git
chmod +x /root/NetID-LXC/scripts/install-lxc.sh
/root/NetID-LXC/scripts/install-lxc.sh
```

6. Start the service and verify:

```bash
systemctl start netid-lxc.service
systemctl status netid-lxc.service
journalctl -u netid-lxc.service -n 100 --no-pager
```

7. Optional manual run (30 second passive listen):

```bash
/usr/local/bin/netid-lxc 30
```

## Update an existing Proxmox container

Run these inside the same container where NetID-LXC is installed:

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

If you prefer one command path, rerun the installer script instead:

```bash
chmod +x /opt/netid-lxc/scripts/install-lxc.sh
/opt/netid-lxc/scripts/install-lxc.sh
systemctl restart netid-lxc.service
```

See [lxc-proxmox.md](lxc-proxmox.md) for container settings and troubleshooting.
