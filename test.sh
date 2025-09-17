#!/usr/bin/env bash
# Full Fresh Installer: OpenVPN + Flask Admin Panel
# Ubuntu 22.04
set -euo pipefail
IFS=$'\n\t'

info(){ echo -e "\e[34m[INFO]\e[0m $*"; }
err(){ echo -e "\e[31m[ERROR]\e[0m $*"; exit 1; }

if [[ $EUID -ne 0 ]]; then
  err "Run as root!"
fi

ADMIN_USER="openvpn"
INSTALL_DIR="/opt/openvpn-admin"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
OPENVPN_SERVER_CONF="/etc/openvpn/server/server.conf"
STATUS_LOG="/etc/openvpn/server/openvpn-status.log"
OVPN_OUTPUT_DIR="/etc/openvpn/clients"
NGINX_CONF="/etc/nginx/sites-available/openvpn-admin"
FLASK_SERVICE="/etc/systemd/system/openvpn-admin.service"

# ---------- PURGE OLD ----------
info "Cleaning old setup..."
systemctl stop openvpn-server@server 2>/dev/null || true
systemctl disable openvpn-server@server 2>/dev/null || true
systemctl stop openvpn-admin 2>/dev/null || true
systemctl disable openvpn-admin 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true
rm -rf /etc/openvpn "$INSTALL_DIR" /var/log/openvpn
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-enabled/openvpn-admin
rm -f /etc/nginx/sites-available/openvpn-admin
rm -f "$FLASK_SERVICE"

# ---------- INSTALL ----------
apt update
DEBIAN_FRONTEND=noninteractive apt install -y openvpn easy-rsa nginx python3-venv python3-pip ufw curl build-essential

# ---------- EASYRSA ----------
info "Setting up EasyRSA..."
rm -rf "$EASYRSA_DIR"
make-cadir "$EASYRSA_DIR"
pushd "$EASYRSA_DIR" >/dev/null
./easyrsa init-pki
echo | ./easyrsa build-ca nopass
./easyrsa gen-req server nopass
./easyrsa sign-req server server <<EOF
yes
EOF
./easyrsa gen-dh
openvpn --genkey --secret ta.key
mkdir -p /etc/openvpn/server
cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key /etc/openvpn/server/
popd >/dev/null

# ---------- OPENVPN SERVER ----------
info "Configuring OpenVPN..."
cat > "$OPENVPN_SERVER_CONF" <<EOF
port 1194
proto udp
dev tun
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
tls-auth /etc/openvpn/server/ta.key 0
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
systemctl enable --now openvpn-server@server

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

# ---------- FIREWALL ----------
ufw allow OpenSSH || true
ufw allow 1194/udp || true
UFW_BEFORE="/etc/ufw/before.rules"
grep -q "OPENVPN RULES" "$UFW_BEFORE" 2>/dev/null || cat >> "$UFW_BEFORE" <<'RULES'
### OPENVPN RULES
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
COMMIT
### END OPENVPN RULES
RULES
ufw --force enable

# ---------- FLASK ADMIN ----------
info "Installing Flask Admin..."
mkdir -p "$INSTALL_DIR/templates"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip flask werkzeug gunicorn

# Flask app
cat > "$INSTALL_DIR/app.py" <<'PY'
from flask import Flask, render_template, request, redirect, send_file, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os, subprocess, sqlite3, re

APP_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(APP_DIR, "admin.db")
OPENVPN_STATUS = "/etc/openvpn/server/openvpn-status.log"
CLIENTS_DIR = "/etc/openvpn/clients"
EASYRSA_DIR = "/etc/openvpn/easy-rsa"

BASE_UDP = """client
dev tun
proto udp
remote YOUR.SERVER.IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
verb 3
key-direction 1
<ca>
{ca}
</ca>
<cert>
{cert}
</cert>
<key>
{key}
</key>
<tls-auth>
{ta}
</tls-auth>
"""

app = Flask(__name__)
app.secret_key = os.urandom(24)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY, username TEXT, passhash TEXT)")
    conn.commit()
    conn.close()

def get_admin():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, passhash FROM admin LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row

def set_admin(username, password):
    ph = generate_password_hash(password)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM admin")
    cur.execute("INSERT INTO admin(username, passhash) VALUES(?,?)",(username,ph))
    conn.commit()
    conn.close()

def parse_status():
    if not os.path.exists(OPENVPN_STATUS): return []
    clients=[]
    with open(OPENVPN_STATUS) as f:
        lines=f.read().splitlines()
    for l in lines:
        if l.startswith("ROUTING TABLE"): break
        if "," in l and not l.startswith("Common Name"):
            p=l.split(",")
            if len(p)>=2: clients.append({"common":p[0],"addr":p[1]})
    return clients

@app.route("/", methods=["GET","POST"])
def login():
    init_db()
    admin=get_admin()
    if request.method=="POST":
        if admin and request.form['username']==admin[0] and check_password_hash(admin[1], request.form['password']):
            session['admin']=admin[0]; return redirect("/dashboard")
        flash("Invalid credentials")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if 'admin' not in session: return redirect("/")
    return render_template("dashboard.html", clients=parse_status())

@app.route("/users", methods=["GET","POST"])
def users():
    if 'admin' not in session: return redirect("/")
    if request.method=="POST":
        cname=request.form['common']
        subprocess.call([os.path.join(EASYRSA_DIR,"easyrsa"),"build-client-full",cname,"nopass"], cwd=EASYRSA_DIR)
        ca=open("/etc/openvpn/server/ca.crt").read()
        cert=open(os.path.join(EASYRSA_DIR,"pki/issued",f"{cname}.crt")).read()
        key=open(os.path.join(EASYRSA_DIR,"pki/private",f"{cname}.key")).read()
        ta=open("/etc/openvpn/server/ta.key").read()
        with open(os.path.join(CLIENTS_DIR,f"{cname}.ovpn"),"w") as f: f.write(BASE_UDP.format(ca=ca,cert=cert,key=key,ta=ta))
    files=[f for f in os.listdir(CLIENTS_DIR) if f.endswith(".ovpn")]
    return render_template("users.html",files=files)

@app.route("/download/<name>")
def download(name):
    if 'admin' not in session: return redirect("/")
    path=os.path.join(CLIENTS_DIR,f"{name}.ovpn")
    return send_file(path,as_attachment=True) if os.path.exists(path) else redirect("/users")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/")
PY

# Templates
cat > "$INSTALL_DIR/templates/login.html" <<'HTML'
<!doctype html><title>Login</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
<h2>Admin Login</h2>
<form method=post>
<label>User <input name=username></label>
<label>Pass <input type=password name=password></label>
<button>Login</button>
</form>
HTML

cat > "$INSTALL_DIR/templates/dashboard.html" <<'HTML'
<!doctype html><title>Dashboard</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
<h2>Dashboard</h2>
<p>Connected Clients: {{clients|length}}</p>
<ul>{% for c in clients %}<li>{{c.common}} - {{c.addr}}</li>{% endfor %}</ul>
<nav><a href="/users">Users</a> | <a href="/logout">Logout</a></nav>
HTML

cat > "$INSTALL_DIR/templates/users.html" <<'HTML'
<!doctype html><title>Users</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
<h2>Users</h2>
<form method=post>
<label>Client Name <input name=common></label>
<button>Create</button>
</form>
<ul>{% for f in files %}<li><a href="/download/{{f[:-5]}}">{{f}}</a></li>{% endfor %}</ul>
<nav><a href="/dashboard">Dashboard</a></nav>
HTML

# ---------- SYSTEMD ----------
cat > "$FLASK_SERVICE" <<EOF
[Unit]
Description=OpenVPN Admin
After=network.target
[Service]
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/gunicorn -b 127.0.0.1:5000 app:app
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now openvpn-admin

# ---------- NGINX ----------
cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/openvpn-admin
systemctl enable nginx
systemctl restart nginx

# ---------- ADMIN CRED ----------
RAND_PASS="$(tr -dc 'A-Z' </dev/urandom | head -c2)$(shuf -i 100-999 -n1)"
"$INSTALL_DIR/venv/bin/python3" - <<PY
from werkzeug.security import generate_password_hash
import sqlite3, os
db="${INSTALL_DIR}/admin.db"
conn=sqlite3.connect(db); cur=conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY, username TEXT, passhash TEXT)")
cur.execute("DELETE FROM admin")
cur.execute("INSERT INTO admin(username,passhash) VALUES(?,?)",("${ADMIN_USER}",generate_password_hash("${RAND_PASS}")))
conn.commit(); conn.close()
PY

echo -e "\n========================"
echo "INSTALL COMPLETE"
echo "Admin URL: http://<server-ip>/"
echo "User: $ADMIN_USER"
echo "Pass: $RAND_PASS"
echo "========================"
