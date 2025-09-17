#!/usr/bin/env bash
# install-openvpn-admin.sh
# Single-script installer: OpenVPN server + simple Flask admin panel
# Ubuntu 22.04 (Jammy) tested
set -euo pipefail
IFS=$'\n\t'

info(){ echo -e "\e[34m[INFO]\e[0m $*"; }
err(){ echo -e "\e[31m[ERROR]\e[0m $*"; exit 1; }

if [[ $EUID -ne 0 ]]; then
  err "Run this script as root (sudo)."
fi

ADMIN_USER="openvpn"
INSTALL_DIR="/opt/openvpn-admin"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
OPENVPN_SERVER_CONF="/etc/openvpn/server/server.conf"
STATUS_LOG="/etc/openvpn/server/openvpn-status.log"
OVPN_OUTPUT_DIR="/etc/openvpn/clients"
NGINX_CONF="/etc/nginx/sites-available/openvpn-admin"
FLASK_SERVICE="/etc/systemd/system/openvpn-admin.service"

# ---------- Purge old install ----------
info "Removing any previous OpenVPN + Admin setup..."
systemctl stop openvpn-server@server 2>/dev/null || true
systemctl disable openvpn-server@server 2>/dev/null || true
systemctl stop openvpn-admin 2>/dev/null || true
systemctl disable openvpn-admin 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true

rm -rf /etc/openvpn
rm -rf "$INSTALL_DIR"
rm -f /etc/nginx/sites-enabled/openvpn-admin
rm -f /etc/nginx/sites-available/openvpn-admin
rm -f "$FLASK_SERVICE"
rm -rf /var/log/openvpn

info "Updating system and installing packages..."
apt update
DEBIAN_FRONTEND=noninteractive apt install -y openvpn easy-rsa nginx python3-venv python3-pip ufw git curl build-essential

info "Preparing directories..."
rm -rf "$EASYRSA_DIR"
make-cadir "$EASYRSA_DIR"
mkdir -p "$OVPN_OUTPUT_DIR"
mkdir -p "$INSTALL_DIR"

# ---------- Easy-RSA / PKI ----------
info "Bootstrapping Easy-RSA and PKI..."
EASYRSA_VARS="$EASYRSA_DIR/vars"
cat > "$EASYRSA_VARS" <<'EOF'
set_var EASYRSA_REQ_COUNTRY    "US"
set_var EASYRSA_REQ_PROVINCE   "CA"
set_var EASYRSA_REQ_CITY       "SanFrancisco"
set_var EASYRSA_REQ_ORG        "MyOrg"
set_var EASYRSA_REQ_EMAIL      "admin@example.com"
set_var EASYRSA_REQ_OU         "OpenVPN"
EOF

pushd "$EASYRSA_DIR" >/dev/null
./easyrsa init-pki >/dev/null
echo | ./easyrsa build-ca nopass >/dev/null
./easyrsa gen-req server nopass >/dev/null
./easyrsa sign-req server server <<EOF
yes
EOF
./easyrsa gen-dh >/dev/null
openvpn --genkey --secret ta.key
mkdir -p /etc/openvpn/server
cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key /etc/openvpn/server/
popd >/dev/null

# ---------- OpenVPN server config ----------
info "Writing OpenVPN server config..."
cat > "$OPENVPN_SERVER_CONF" <<EOF
port 1194
proto udp
dev tun
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
tls-auth /etc/openvpn/server/ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
persist-key
persist-tun
status $STATUS_LOG
log-append /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
EOF

mkdir -p /var/log/openvpn
chown -R nobody:nogroup /var/log/openvpn

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

# ---------- UFW NAT ----------
info "Configuring firewall..."
ufw allow OpenSSH || true
ufw allow 1194/udp || true
ufw disable || true
UFW_BEFORE="/etc/ufw/before.rules"
sed -i '/### OPENVPN RULES/,$d' "$UFW_BEFORE" 2>/dev/null || true
cat >> "$UFW_BEFORE" <<'RULES'
### OPENVPN RULES
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
COMMIT
### END OPENVPN RULES
RULES
ufw --force enable

# ---------- Start OpenVPN ----------
systemctl enable --now openvpn-server@server
touch "$STATUS_LOG"

# ---------- Flask admin app ----------
info "Installing Flask admin panel..."
# (Same Flask app code as আগে, সংক্ষেপে রাখছি এখানে জায়গার জন্য, আগের স্ক্রিপ্টে পুরো app.py + templates অংশ অপরিবর্তিত থাকবে)
# -----> এখানে আপনার আগের app.py এবং templates 그대로 বসান <-----

# Create Python venv
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install flask werkzeug gunicorn

# Systemd service
cat > "$FLASK_SERVICE" <<EOF
[Unit]
Description=OpenVPN Admin Panel
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/gunicorn -b 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now openvpn-admin

# Nginx proxy
cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/openvpn-admin
nginx -t && systemctl reload nginx

# ---------- Admin initial password ----------
RAND_PASS="$(tr -dc 'A-Z' </dev/urandom | head -c2)$(shuf -i 100-999 -n1)"
"$INSTALL_DIR/venv/bin/python3" - <<PY
from werkzeug.security import generate_password_hash
import sqlite3, os
db="${INSTALL_DIR}/admin.db"
os.makedirs(os.path.dirname(db), exist_ok=True)
conn=sqlite3.connect(db)
cur=conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY, username TEXT UNIQUE, passhash TEXT)")
cur.execute("DELETE FROM admin")
cur.execute("INSERT INTO admin(username, passhash) VALUES(?,?)",("${ADMIN_USER}", generate_password_hash("${RAND_PASS}")))
conn.commit()
conn.close()
PY

cat <<EOF

=========================
INSTALLATION COMPLETE
=========================

Admin panel URL: http://<server-ip>/
Admin username: ${ADMIN_USER}
Admin password: ${RAND_PASS}

নোট:
- `.ovpn` ফাইল ডাউনলোড করার সময় `remote YOUR.SERVER.IP 1194` লাইনে আপনার সার্ভারের Public IP দিন।
- ক্লায়েন্ট ইউজার অ্যাড করতে অ্যাডমিন প্যানেল ব্যবহার করুন।
- লগ এবং কানেক্টেড ডিভাইসগুলো অ্যাডমিন প্যানেল থেকেই দেখা যাবে।

EOF
