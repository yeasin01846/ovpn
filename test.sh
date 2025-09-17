#!/usr/bin/env bash
# install-openvpn-admin.sh
# Single-script installer: OpenVPN server + simple Flask admin panel
# Tested for Ubuntu 22.04 (Jammy)
set -euo pipefail
IFS=$'\n\t'

# ---------- Helper functions ----------
info(){ echo -e "\e[34m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
err(){ echo -e "\e[31m[ERROR]\e[0m $*"; exit 1; }

if [[ $EUID -ne 0 ]]; then
  err "Run this script as root (sudo)."
fi

# Variables (you can edit if desired)
ADMIN_USER="openvpn"
INSTALL_DIR="/opt/openvpn-admin"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
OPENVPN_SERVER_CONF="/etc/openvpn/server/server.conf"
STATUS_LOG="/etc/openvpn/server/openvpn-status.log"
OVPN_OUTPUT_DIR="/etc/openvpn/clients"
NGINX_CONF="/etc/nginx/sites-available/openvpn-admin"
FLASK_SERVICE="/etc/systemd/system/openvpn-admin.service"

info "Updating packages..."
apt update
DEBIAN_FRONTEND=noninteractive apt install -y openvpn easy-rsa nginx python3-venv python3-pip ufw git curl

info "Preparing directories..."
mkdir -p "$EASYRSA_DIR"
make-cadir "$EASYRSA_DIR"
chown -R root:root "$EASYRSA_DIR"
mkdir -p "$OVPN_OUTPUT_DIR"
mkdir -p "$INSTALL_DIR"

# ---------- Easy-RSA / PKI ----------
info "Bootstrapping Easy-RSA and PKI..."
EASYRSA_VARS="$EASYRSA_DIR/vars"
# minimal vars (noninteractive)
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
# Build CA (no password)
echo | ./easyrsa build-ca nopass >/dev/null
# Server cert
./easyrsa gen-req server nopass >/dev/null
./easyrsa sign-req server server <<EOF
yes
EOF
# Diffie-Hellman
./easyrsa gen-dh >/dev/null
# Generate TLS auth key
openvpn --genkey --secret ta.key
# Move needed files to /etc/openvpn/server
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

# Enable IP forwarding & NAT
info "Enabling IP forwarding and NAT..."
sysctl -w net.ipv4.ip_forward=1
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

# UFW rules
info "Configuring UFW..."
ufw allow OpenSSH >/dev/null || true
ufw allow 1194/udp >/dev/null || true
ufw disable || true
# Set before rules for NAT
UFW_BEFORE="/etc/ufw/before.rules"
if ! grep -q "OPENVPN RULES" "$UFW_BEFORE"; then
  sed -i '1s/^/### OPENVPN RULES\n# nat table rules\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE\nCOMMIT\n### END OPENVPN RULES\n\n/' "$UFW_BEFORE"
fi
ufw --force enable

# Start OpenVPN
info "Starting OpenVPN..."
systemctl enable --now openvpn-server@server || systemctl start openvpn@server

# Wait a moment for status log to appear
sleep 2
touch "$STATUS_LOG"
chown nobody:nogroup "$STATUS_LOG" || true

# ---------- Flask admin app ----------
info "Creating Flask admin app..."
cat > "$INSTALL_DIR/app.py" <<'PY'
from flask import Flask, render_template, request, redirect, send_file, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os, subprocess, sqlite3, time, re, io
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
    cur.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY, username TEXT UNIQUE, passhash TEXT)")
    conn.commit()
    conn.close()

def get_admin():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, passhash FROM admin LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row

def set_admin(username, passplain):
    ph = generate_password_hash(passplain)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM admin")
    cur.execute("INSERT INTO admin(username, passhash) VALUES(?,?)",(username,ph))
    conn.commit()
    conn.close()

def parse_status():
    # parse openvpn-status.log format for connected clients
    if not os.path.exists(OPENVPN_STATUS):
        return []
    clients=[]
    with open(OPENVPN_STATUS) as f:
        lines = f.read().splitlines()
    # find client list section (common format)
    for line in lines:
        if line.startswith("Common Name,Real Address"):
            start = lines.index(line)+1
            break
    else:
        return clients
    for l in lines[start:]:
        if l.strip()=='' or l.startswith('ROUTING TABLE') or l.startswith('GLOBAL STATS'):
            break
        parts = l.split(',')
        if len(parts) >= 2:
            clients.append({'common_name': parts[0], 'real_address': parts[1]})
    return clients

@app.route("/", methods=["GET","POST"])
def login():
    init_db()
    admin = get_admin()
    if not admin:
        # shouldn't happen if installer created admin
        set_admin("openvpn","AB123")
        admin = get_admin()
    if request.method=="POST":
        username = request.form.get("username","")
        password = request.form.get("password","")
        if username==admin[0] and check_password_hash(admin[1], password):
            session['admin']=username
            return redirect(url_for('dashboard'))
        flash("Invalid credentials","danger")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if 'admin' not in session:
        return redirect(url_for('login'))
    clients = parse_status()
    # count unique common names
    return render_template("dashboard.html",clients=clients,count=len(clients))

@app.route("/logs")
def logs():
    if 'admin' not in session:
        return redirect(url_for('login'))
    # show last 200 lines of openvpn log
    logpath="/var/log/openvpn/openvpn.log"
    lines=[]
    if os.path.exists(logpath):
        with open(logpath) as f:
            lines = f.read().splitlines()[-200:]
    return render_template("logs.html",lines=lines)

@app.route("/users", methods=["GET","POST"])
def users():
    if 'admin' not in session:
        return redirect(url_for('login'))
    if request.method=="POST":
        cname = request.form.get("common_name","").strip()
        if not re.match(r'^[A-Za-z0-9._-]+$', cname):
            flash("Invalid username (use letters, numbers, ., -, _)", "danger")
            return redirect(url_for('users'))
        # generate client cert and ovpn
        try:
            # build client request & sign
            subprocess.check_call([os.path.join(EASYRSA_DIR,"easyrsa"),"build-client-full",cname,"nopass"], cwd=EASYRSA_DIR)
            # assemble .ovpn
            ca = open("/etc/openvpn/server/ca.crt").read()
            cert = open(os.path.join(EASYRSA_DIR,"pki","issued",f"{cname}.crt")).read()
            key = open(os.path.join(EASYRSA_DIR,"pki","private",f"{cname}.key")).read()
            ta = open("/etc/openvpn/server/ta.key").read()
            ovpn = BASE_UDP.format(ca=ca, cert=cert, key=key, ta=ta)
            outpath = os.path.join(CLIENTS_DIR,f"{cname}.ovpn")
            with open(outpath,"w") as f:
                f.write(ovpn)
            flash(f"Client {cname} created. Download from /download/{cname}", "success")
        except subprocess.CalledProcessError as e:
            flash("Error creating client: "+str(e),"danger")
    # list existing .ovpn files
    files=[]
    for f in os.listdir(CLIENTS_DIR):
        if f.endswith(".ovpn"):
            files.append(f)
    return render_template("users.html",files=files)

@app.route("/download/<name>")
def download(name):
    if 'admin' not in session:
        return redirect(url_for('login'))
    path = os.path.join(CLIENTS_DIR,f"{name}.ovpn")
    if not os.path.exists(path):
        flash("File not found","danger")
        return redirect(url_for('users'))
    return send_file(path, as_attachment=True)

@app.route("/change_password", methods=["GET","POST"])
def change_password():
    if 'admin' not in session:
        return redirect(url_for('login'))
    if request.method=="POST":
        newp = request.form.get("new_password","").strip()
        if not re.match(r'^[A-Z]{2}\d{3}$', newp):
            flash("Password must be 2 uppercase letters followed by 3 digits (e.g., AB123)","danger")
            return redirect(url_for('change_password'))
        set_admin("openvpn", newp)
        flash("Admin password changed.","success")
    return render_template("change_password.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# templates (very simple) will be provided as files in templates/
if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)
PY

# Create templates
mkdir -p "$INSTALL_DIR/templates"
cat > "$INSTALL_DIR/templates/login.html" <<'HTML'
<!doctype html>
<title>OpenVPN Admin - Login</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
<h2>OpenVPN Admin Login</h2>
<form method=post>
  <label>Username<input name="username" required></label>
  <label>Password<input name="password" type="password" required></label>
  <button>Login</button>
</form>
HTML

cat > "$INSTALL_DIR/templates/dashboard.html" <<'HTML'
<!doctype html>
<title>Dashboard</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
<h2>OpenVPN Admin Dashboard</h2>
<p>Logged in as admin. Connected devices: {{count}}</p>
<table>
  <thead><tr><th>Common Name</th><th>Real Address</th></tr></thead>
  <tbody>
  {% for c in clients %}
    <tr><td>{{c.common_name}}</td><td>{{c.real_address}}</td></tr>
  {% endfor %}
  </tbody>
</table>
<nav><a href="/users">Users</a> | <a href="/logs">Logs</a> | <a href="/change_password">Change Password</a> | <a href="/logout">Logout</a></nav>
HTML

cat > "$INSTALL_DIR/templates/users.html" <<'HTML'
<!doctype html>
<title>Users</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
<h2>Clients</h2>
<form method=post>
  <label>Client name (alphanumeric . _ -)<input name="common_name" required></label>
  <button>Create client</button>
</form>
<h3>Existing .ovpn files</h3>
<ul>
{% for f in files %}
  <li><a href="/download/{{f[:-5]}}">{{f}}</a></li>
{% endfor %}
</ul>
<nav><a href="/dashboard">Dashboard</a></nav>
HTML

cat > "$INSTALL_DIR/templates/logs.html" <<'HTML'
<!doctype html>
<title>Logs</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
<h2>OpenVPN Logs (tail)</h2>
<pre>
{% for l in lines %}
{{l}}
{% endfor %}
</pre>
<nav><a href="/dashboard">Dashboard</a></nav>
HTML

cat > "$INSTALL_DIR/templates/change_password.html" <<'HTML'
<!doctype html>
<title>Change Admin Password</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
<h2>Change Admin Password</h2>
<form method=post>
  <label>New password (2 uppercase letters + 3 digits, e.g., AB123)<input name="new_password" required></label>
  <button>Change</button>
</form>
<nav><a href="/dashboard">Dashboard</a></nav>
HTML

# Create virtualenv and install requirements
info "Creating Python venv and installing dependencies..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install flask werkzeug gunicorn

# Create clients dir and set permissions
mkdir -p "$OVPN_OUTPUT_DIR"
chown -R root:root "$OVPN_OUTPUT_DIR"
chmod 700 "$OVPN_OUTPUT_DIR"

# Create systemd service for the Flask app (gunicorn)
info "Creating systemd service for admin panel..."
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

# Nginx reverse proxy
info "Configuring nginx reverse proxy..."
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
nginx -t
systemctl reload nginx

# ---------- Admin initial password ----------
# Generate password: 2 uppercase letters + 3 digits
RAND_PASS="$(tr -dc 'A-Z' </dev/urandom | head -c2)$(shuf -i 100-999 -n1)"
info "Creating initial admin credentials..."
# Use Python's werkzeug to hash & store via the Flask app DB helper
"$INSTALL_DIR/venv/bin/python3" - <<PY
from werkzeug.security import generate_password_hash
import sqlite3, os
db="${INSTALL_DIR}/admin.db"
if not os.path.exists(db):
    conn=sqlite3.connect(db)
    cur=conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY, username TEXT UNIQUE, passhash TEXT)")
    conn.commit()
    conn.close()
ph=generate_password_hash("${RAND_PASS}")
conn=sqlite3.connect(db)
cur=conn.cursor()
cur.execute("DELETE FROM admin")
cur.execute("INSERT INTO admin(username, passhash) VALUES(?,?)",("${ADMIN_USER}",ph))
conn.commit()
conn.close()
print("OK")
PY

info "Setting file permissions..."
chown -R root:root "$INSTALL_DIR"
chmod -R 700 "$INSTALL_DIR"

# Final output
cat <<EOF

INSTALLATION COMPLETE.

Admin panel URL: http://<server-ip>/
Admin username: ${ADMIN_USER}
Admin password: ${RAND_PASS}

Important notes:
- Change the 'remote YOUR.SERVER.IP 1194' line inside generated .ovpn files to your server's public IP or domain.
  The app writes 'YOUR.SERVER.IP' placeholder; you can replace in templates or edit files in $INSTALL_DIR/app.py BASE_UDP.
- To add a client: Login -> Users -> Create client -> download .ovpn.
- To change admin password: Dashboard -> Change Password (new password must match pattern 2 uppercase letters + 3 digits).
- OpenVPN status file: $STATUS_LOG (used to show connected clients).
- Logs: /var/log/openvpn/openvpn.log

If you want the server to use a real domain + HTTPS, set up TLS in nginx (certbot) after install.

EOF
