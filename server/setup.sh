#!/usr/bin/env bash
# Run on the server as root, from the site folder:  bash server/setup.sh
# It installs the tr33s admin service. You type the admin password yourself; it is never shown.
set -euo pipefail
SITE="$(cd "$(dirname "$0")/.." && pwd)"
if ! command -v node >/dev/null 2>&1; then
  echo "Installing Node.js..."; apt-get update -y && apt-get install -y nodejs
fi
NODE="$(command -v node)"
NODEV="$($NODE -p 'process.versions.node.split(".")[0]')"
[ "$NODEV" -ge 18 ] || { echo "Node 18 or newer is needed (found $($NODE -v)). Install a newer Node and run again."; exit 1; }

mkdir -p /var/lib/tr33s && chmod 750 /var/lib/tr33s
if [ ! -f /etc/tr33s.env ]; then
  while true; do
    read -rsp "Choose an admin password (10+ characters): " PW; echo
    [ "${#PW}" -ge 10 ] || { echo "Too short."; continue; }
    read -rsp "Type it again: " PW2; echo
    [ "$PW" = "$PW2" ] && break || echo "They did not match."
  done
  umask 077
  printf 'ADMIN_PASSWORD=%s\nPORT=3100\nHOST=127.0.0.1\nDATA_DIR=/var/lib/tr33s\n' "$PW" > /etc/tr33s.env
  unset PW PW2
else
  echo "/etc/tr33s.env already exists, keeping your password."
fi

cat > /etc/systemd/system/tr33s-admin.service <<EOF
[Unit]
Description=tr33s admin and waitlist API
After=network.target

[Service]
EnvironmentFile=/etc/tr33s.env
ExecStart=$NODE $SITE/server/server.js
Restart=always
User=root
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=/var/lib/tr33s

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now tr33s-admin
systemctl restart tr33s-admin
sleep 1
systemctl --no-pager --lines=3 status tr33s-admin || true
echo
echo "Service installed. Now add the lines from server/nginx-snippet.conf to the nginx server block, then: nginx -t && systemctl reload nginx"
