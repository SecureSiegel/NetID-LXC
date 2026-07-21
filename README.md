# NetID-LXC

A simple Rust-based network scanner designed for a Proxmox LXC environment. The binary sends ICMP echo requests to hosts in a provided CIDR range and prints the IPv4 addresses that respond.

## Features

- Scans a CIDR range such as 192.168.1.0/24
- Uses ICMP ping requests
- Returns a simple list of responsive IPv4 addresses
- Builds as a small Linux container image

## Build locally

```bash
cargo build --release
```

## Run locally

```bash
./target/release/netid-lxc 192.168.1.0/24
```

## Container build

```bash
docker build -t netid-lxc:latest .
```

Run the container with a target network:

```bash
docker run --rm --network host netid-lxc:latest 192.168.1.0/24
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
/usr/local/bin/netid-lxc 192.168.1.0/24
```

See [lxc-proxmox.md](lxc-proxmox.md) for container settings and troubleshooting.
