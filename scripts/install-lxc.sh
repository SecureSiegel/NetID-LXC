#!/usr/bin/env bash
set -euo pipefail

if ! command -v curl >/dev/null 2>&1; then
  apt-get update
  apt-get install -y curl git build-essential iproute2 pkg-config
else
  apt-get update
  apt-get install -y git build-essential iproute2 pkg-config
fi

if ! command -v cargo >/dev/null 2>&1; then
  curl https://sh.rustup.rs -sSf | sh -s -- -y
  export PATH="$HOME/.cargo/bin:$PATH"
  echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$HOME/.bashrc"
fi

if [ ! -d /opt/netid-lxc ]; then
  mkdir -p /opt/netid-lxc
fi

cd /opt/netid-lxc
if [ ! -d .git ]; then
  git clone https://github.com/SecureSiegel/NetID-LXC.git .
else
  git pull origin main
fi

source "$HOME/.cargo/env" 2>/dev/null || true
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release
cp target/release/netid-lxc /usr/local/bin/netid-lxc
chmod +x /usr/local/bin/netid-lxc

cat > /etc/systemd/system/netid-lxc.service <<'EOF'
[Unit]
Description=NetID LXC Network Scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/netid-lxc 30 /var/lib/netid-lxc/output
Restart=on-failure
WorkingDirectory=/opt/netid-lxc

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable netid-lxc.service
