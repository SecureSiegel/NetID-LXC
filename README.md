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

For Proxmox, deploy a Debian-based LXC container with the `iputils-ping` package installed, copy the built binary into the container, and run it with the target CIDR argument. This repository also provides a container image build path for the same binary.
