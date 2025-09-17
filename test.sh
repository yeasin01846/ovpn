#!/usr/bin/env bash
# install-openvpn-admin-full.sh
# Full automated fresh installer:
# - Purges old install
# - Installs OpenVPN + Easy-RSA
# - Flask Admin Panel (Bootstrap UI) with features:
#   Dashboard (connected clients), Logs, Users (create/download/revoke), Change admin password
# - Gunicorn + systemd service + nginx reverse proxy
# - Opens necessary firewall ports (80/tcp and 1194/udp)
#
# Tested on Ubuntu 22.04 (Jammy). Run as root.
set -euo pipefail
IFS=$'\n\t'

### -------- helper --------
info(){ echo -e "\e[34m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
err(){ echo -e "\e[31m[ERROR]\e[0m $*"; exit 1; }
if [[ $EUID -ne 0 ]]; then err "Run this script as root (sudo)"; fi

ADMIN_USER="openvpn"
INSTALL_DIR="/opt/openvpn-admin"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
OPENVPN_SERVER_DIR="/etc/openvpn/server"
OPENVPN_SERVER_CONF="$OPENVPN_SERVER_DIR/server.conf"
STATUS_LOG="$OPENVPN_SERVER_DIR/openvpn-status.log"
CLIENTS_DIR="/etc/openvpn/clients"
FLASK_SERVICE="/etc/systemd/system/openvpn-admin.service"
NGINX_CONF="/etc/nginx/sites-available/openvpn-admin"

# Get public IP (best-effort)
PUBLIC_IP="$(curl -s https://ifconfig.co || curl -s https://icanhazip.com || echo "")"
if [[ -z "$PUBLIC_IP" ]]; then
  warn "Could NOT determine public IP automatically. .ovpn files will have placeholder; edit manually if needed."
fi

# ---------- PURGE ----------
info "Stopping services and removing any previous install..."
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

# ---------- PACKAGES ----------
info "Updating apt and installing packages..."
apt update
DEBIAN_FRONTEND=noninteractive apt install -y openvpn easy-rsa nginx python3-venv python3-pip ufw curl build-essential

# ---------- EASY-RSA / PKI ----------
info "Creating fresh Easy-RSA PKI..."
rm -rf "$EASYRSA_DIR"
make-cadir "$EASYRSA_DIR"
pushd "$EASYRSA_DIR" >/dev/null
./easyrsa init-pki
# minimal noninteractive vars are fine; we use nopass for ease
echo | ./easyrsa build-ca nopass
./easyrsa gen-req server nopass
# sign server cert automatically
./easyrsa sign-req server server <<'YES'
yes
YES
./easyrsa gen-dh
openvpn --genkey --secret ta.key
mkdir -p "$OPENVPN_SERVER_DIR"
cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key "$OPENVPN_SERVER_DIR/"
popd >/dev/null

# ---------- OPENVPN SERVER CONFIG ----------
info "Writing OpenVPN server config..."
mkdir -p /var/log/openvpn
cat > "$OPENVPN_SERVER_CONF" <<'EOF'
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
status /etc/openvpn/server/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
EOF

systemctl enable --now openvpn-server@server

# enable IP forwarding
info "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# ---------- UFW ----------
info "Configuring UFW..."
ufw allow OpenSSH || true
ufw allow 1194/udp || true
ufw allow 80/tcp || true
UFW_BEFORE="/etc/ufw/before.rules"
if ! grep -q "OPENVPN RULES" "$UFW_BEFORE" 2>/dev/null; then
  cat >> "$UFW_BEFORE" <<'RULES'
### OPENVPN RULES
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
COMMIT
### END OPENVPN RULES
RULES
fi
ufw --force enable

# ---------- CLIENTS DIR ----------
mkdir -p "$CLIENTS_DIR"
chmod 700 "$CLIENTS_DIR"

# ---------- FLASK APP (full) ----------
info "Installing Flask app..."
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/templates" "$INSTALL_DIR/static"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install flask werkzeug gunicorn

# app.py
cat > "$INSTALL_DIR/app.py" <<'PY'
import os, sqlite3, subprocess, re, datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify

APP_DIR = os.path.dirname(__file__)
DB = os.path.join(APP_DIR, "admin.db")
EASYRSA_DIR = "/etc/openvpn/easy-rsa"
CLIENTS_DIR = "/etc/openvpn/clients"
OPENVPN_STATUS = "/etc/openvpn/server/openvpn-status.log"
OPENVPN_LOG = "/var/log/openvpn/openvpn.log"
CA_CRT = "/etc/openvpn/server/ca.crt"
TA_KEY = "/etc/openvpn/server/ta.key"
PUBLIC_IP_PLACEHOLDER = os.environ.get("PUBLIC_IP", "YOUR.SERVER.IP")

app = Flask(__name__, static_folder="static")
app.secret_key = os.urandom(24)

# helpers for DB / admin
def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY, username TEXT UNIQUE, passhash TEXT)")
    conn.commit(); conn.close()

def get_admin_row():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT username, passhash FROM admin LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row

def set_admin(username, passhash):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("DELETE FROM admin")
    cur.execute("INSERT INTO admin(username, passhash) VALUES(?,?)",(username,passhash))
    conn.commit(); conn.close()

# parse openvpn-status.log to structured data
def parse_status():
    if not os.path.exists(OPENVPN_STATUS): return {"clients":[], "routing":[]}
    with open(OPENVPN_STATUS) as f: lines = f.read().splitlines()
    clients = []
    routing = []
    mode = "start"
    for l in lines:
        if l.strip()=="":
            continue
        if l.startswith("Common Name,Real Address"):
            mode="clients"; continue
        if l.startswith("ROUTING TABLE"):
            mode="routing"; continue
        if l.startswith("GLOBAL STATS"):
            break
        if mode=="clients":
            parts = l.split(",")
            if len(parts)>=2:
                common = parts[0]; real = parts[1]
                clients.append({"common":common,"real":real})
        if mode=="routing":
            parts = l.split(",")
            if len(parts)>=3:
                virtual_ip = parts[0]; common = parts[1]; real = parts[2]
                routing.append({"virtual_ip":virtual_ip,"common":common,"real":real})
    return {"clients":clients,"routing":routing}

# read tail of log
def tail(path, n=200):
    if not os.path.exists(path): return []
    with open(path) as f:
        lines = f.read().splitlines()
    return lines[-n:]

# require login
def require_login():
    if 'admin' not in session:
        return False
    return True

@app.route("/", methods=["GET","POST"])
def login():
    init_db()
    row = get_admin_row()
    if not row:
        # safety fallback
        set_admin("openvpn","NOTSET")
        row = get_admin_row()
    if request.method=="POST":
        from werkzeug.security import check_password_hash
        if request.form.get("username")==row[0] and check_password_hash(row[1], request.form.get("password","")):
            session['admin'] = row[0]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials","danger")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if not require_login(): return redirect(url_for("login"))
    status = parse_status()
    logs = tail(OPENVPN_LOG,100)
    return render_template("dashboard.html", clients=status["clients"], routing=status["routing"], logs=logs)

@app.route("/logs")
def logs():
    if not require_login(): return redirect(url_for("login"))
    lines = tail(OPENVPN_LOG,500)
    return render_template("logs.html", lines=lines)

@app.route("/users", methods=["GET","POST"])
def users():
    if not require_login(): return redirect(url_for("login"))
    message = None
    if request.method=="POST":
        cn = request.form.get("common","").strip()
        if not re.match(r'^[A-Za-z0-9._-]{1,64}$', cn):
            flash("Invalid client name. Use letters, numbers, ., -, _","danger")
            return redirect(url_for("users"))
        # build and sign client cert
        try:
            subprocess.check_call([os.path.join(EASYRSA_DIR,"easyrsa"),"build-client-full",cn,"nopass"], cwd=EASYRSA_DIR)
            # build .ovpn
            ca = open(CA_CRT).read()
            cert = open(os.path.join(EASYRSA_DIR,"pki","issued",f"{cn}.crt")).read()
            key = open(os.path.join(EASYRSA_DIR,"pki","private",f"{cn}.key")).read()
            ta = open(TA_KEY).read()
            ovpn = f"""client
dev tun
proto udp
remote {PUBLIC_IP_PLACEHOLDER} 1194
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
            out = os.path.join(CLIENTS_DIR, f"{cn}.ovpn")
            with open(out,"w") as f: f.write(ovpn)
            os.chmod(out,0o600)
            flash(f"Client {cn} created. Download below.","success")
        except subprocess.CalledProcessError as e:
            flash("Error creating client: "+str(e),"danger")
    # list clients
    files = sorted([f for f in os.listdir(CLIENTS_DIR) if f.endswith(".ovpn")])
    return render_template("users.html", files=files)

@app.route("/download/<name>")
def download(name):
    if not require_login(): return redirect(url_for("login"))
    path = os.path.join(CLIENTS_DIR, f"{name}.ovpn")
    if not os.path.exists(path):
        flash("File not found","danger")
        return redirect(url_for("users"))
    return send_file(path, as_attachment=True)

@app.route("/revoke/<name>", methods=["POST"])
def revoke(name):
    if not require_login(): return redirect(url_for("login"))
    cn = name
    try:
        subprocess.check_call([os.path.join(EASYRSA_DIR,"easyrsa"),"revoke",cn], cwd=EASYRSA_DIR)
        subprocess.check_call([os.path.join(EASYRSA_DIR,"easyrsa"),"gen-crl"], cwd=EASYRSA_DIR)
        flash(f"User {cn} revoked. CRL updated.","success")
    except subprocess.CalledProcessError as e:
        flash("Error revoking: "+str(e),"danger")
    return redirect(url_for("users"))

@app.route("/change_password", methods=["GET","POST"])
def change_password():
    if not require_login(): return redirect(url_for("login"))
    from werkzeug.security import generate_password_hash
    if request.method=="POST":
        newp = request.form.get("new_password","").strip()
        if not re.match(r'^[A-Z]{2}\d{3}$', newp):
            flash("Password must be 2 uppercase letters followed by 3 digits (e.g., AB123)","danger")
            return redirect(url_for("change_password"))
        set_admin("openvpn", generate_password_hash(newp))
        flash("Admin password changed.","success")
    return render_template("change_password.html")

@app.route("/api/status")
def api_status():
    # JSON status for advanced frontend or polling
    return jsonify(parse_status())

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000)
PY

# Templates (Bootstrap 5 responsive UI)
cat > "$INSTALL_DIR/templates/base.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>OpenVPN Admin</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding-top: 4.5rem; }
    pre.logbox { max-height: 60vh; overflow:auto; background:#0b1220; color:#cfe8ff; padding:1rem; border-radius:.5rem; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
  <div class="container-fluid">
    <a class="navbar-brand" href="/dashboard">OpenVPN Admin</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navmenu">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div id="navmenu" class="collapse navbar-collapse">
      <ul class="navbar-nav me-auto">
        <li class="nav-item"><a class="nav-link" href="/dashboard">Dashboard</a></li>
        <li class="nav-item"><a class="nav-link" href="/users">Users</a></li>
        <li class="nav-item"><a class="nav-link" href="/logs">Logs</a></li>
        <li class="nav-item"><a class="nav-link" href="/change_password">Change Password</a></li>
      </ul>
      <ul class="navbar-nav">
        <li class="nav-item"><a class="nav-link text-light" href="/logout">Logout</a></li>
      </ul>
    </div>
  </div>
</nav>
<div class="container">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for cat,msg in messages %}
        <div class="alert alert-{{ 'danger' if cat=='danger' else 'success' }} alert-dismissible fade show" role="alert">
          {{msg}} <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {% block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
HTML

cat > "$INSTALL_DIR/templates/login.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6 col-lg-4">
    <div class="card shadow-sm">
      <div class="card-body">
        <h5 class="card-title mb-3">Admin Login</h5>
        <form method="post">
          <div class="mb-2"><label class="form-label">Username</label><input class="form-control" name="username" required></div>
          <div class="mb-2"><label class="form-label">Password</label><input class="form-control" name="password" type="password" required></div>
          <button class="btn btn-primary w-100">Login</button>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
HTML

cat > "$INSTALL_DIR/templates/dashboard.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<div class="row">
  <div class="col-lg-6">
    <div class="card mb-3">
      <div class="card-header">Connected Clients <span class="badge bg-primary">{{clients|length}}</span></div>
      <div class="card-body">
        {% if clients %}
          <div class="list-group">
          {% for c in clients %}
            <div class="list-group-item d-flex justify-content-between align-items-start">
              <div>
                <strong>{{c.common}}</strong><div class="text-muted small">{{c.real}}</div>
              </div>
              <div class="text-end">
                <a class="btn btn-sm btn-outline-danger" href="#" onclick="if(confirm('Revoke {{c.common}}?')) fetch('/revoke/{{c.common}}',{method:'POST'}).then(()=>location.reload())">Revoke</a>
              </div>
            </div>
          {% endfor %}
          </div>
        {% else %}
          <div class="text-muted">No connected clients.</div>
        {% endif %}
      </div>
    </div>
    <div class="card mb-3">
      <div class="card-header">Routing Table</div>
      <div class="card-body">
        {% if routing %}
          <table class="table table-sm">
            <thead><tr><th>Virtual IP</th><th>Common Name</th><th>Real Address</th></tr></thead>
            <tbody>
            {% for r in routing %}
              <tr><td>{{r.virtual_ip}}</td><td>{{r.common}}</td><td>{{r.real}}</td></tr>
            {% endfor %}
            </tbody>
          </table>
        {% else %}
          <div class="text-muted">No routing entries.</div>
        {% endif %}
      </div>
    </div>
  </div>

  <div class="col-lg-6">
    <div class="card mb-3">
      <div class="card-header">Recent OpenVPN Logs</div>
      <div class="card-body">
        <pre class="logbox">{{ logs|join("\n") }}</pre>
      </div>
    </div>
    <div class="card">
      <div class="card-header">Quick Actions</div>
      <div class="card-body">
        <a href="/users" class="btn btn-success">Create Client</a>
        <a href="/logs" class="btn btn-secondary">Full Logs</a>
      </div>
    </div>
  </div>
</div>
{% endblock %}
HTML

cat > "$INSTALL_DIR/templates/users.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<div class="row">
  <div class="col-md-6">
    <div class="card mb-3">
      <div class="card-header">Create New Client</div>
      <div class="card-body">
        <form method="post">
          <div class="mb-2"><label class="form-label">Client name</label><input class="form-control" name="common" placeholder="client1" required></div>
          <button class="btn btn-primary">Create &amp; Build .ovpn</button>
        </form>
      </div>
    </div>
    <div class="card">
      <div class="card-header">Existing .ovpn files</div>
      <div class="card-body">
        {% if files %}
          <ul class="list-group">
          {% for f in files %}
            <li class="list-group-item d-flex justify-content-between align-items-center">
              {{f}}
              <span>
                <a class="btn btn-sm btn-outline-primary" href="/download/{{f[:-5]}}">Download</a>
                <form style="display:inline" method="post" action="/revoke/{{f[:-5]}}" onsubmit="return confirm('Revoke user {{f[:-5]}}?');">
                  <button class="btn btn-sm btn-outline-danger">Revoke</button>
                </form>
              </span>
            </li>
          {% endfor %}
          </ul>
        {% else %}
          <div class="text-muted">No .ovpn files yet.</div>
        {% endif %}
      </div>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card mb-3">
      <div class="card-header">Help & Notes</div>
      <div class="card-body">
        <p><strong>Important:</strong> .ovpn files contain the server address placeholder. If you didn't set PUBLIC_IP env during install, edit the .ovpn and replace <code>YOUR.SERVER.IP</code> with your server IP or domain.</p>
        <p>To enable HTTPS use certbot on the server and update nginx site to listen 443 (I can provide certbot automation if you want).</p>
      </div>
    </div>
  </div>
</div>
{% endblock %}
HTML

cat > "$INSTALL_DIR/templates/logs.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header">OpenVPN Log (tail)</div>
  <div class="card-body">
    <pre class="logbox">{{ lines|join("\n") }}</pre>
  </div>
</div>
{% endblock %}
HTML

cat > "$INSTALL_DIR/templates/change_password.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header">Change Admin Password</div>
  <div class="card-body">
    <form method="post">
      <div class="mb-2"><label class="form-label">New password (2 uppercase letters + 3 digits e.g., AB123)</label>
      <input class="form-control" name="new_password" required></div>
      <button class="btn btn-primary">Change Password</button>
    </form>
  </div>
</div>
{% endblock %}
HTML

# ---------- systemd service for gunicorn ----------
cat > "$FLASK_SERVICE" <<'UNIT'
[Unit]
Description=OpenVPN Admin Panel
After=network.target

[Service]
WorkingDirectory=/opt/openvpn-admin
Environment="PATH=/opt/openvpn-admin/venv/bin"
ExecStart=/opt/openvpn-admin/venv/bin/gunicorn -b 127.0.0.1:5000 app:app
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now openvpn-admin

# ---------- nginx config ----------
info "Writing nginx config..."
cat > "$NGINX_CONF" <<'NGCONF'
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
NGCONF

ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/openvpn-admin
# remove default to avoid conflict
rm -f /etc/nginx/sites-enabled/default || true
nginx -t && systemctl enable --now nginx || { warn "nginx failed to start; check logs"; }

# ---------- admin initial credentials ----------
RAND_PASS="$(tr -dc 'A-Z' </dev/urandom | head -c2)$(shuf -i 100-999 -n1 || echo 123)"
# store hashed password
"$INSTALL_DIR/venv/bin/python3" - <<PY
from werkzeug.security import generate_password_hash
import sqlite3, os
db="${INSTALL_DIR}/admin.db"
os.makedirs(os.path.dirname(db), exist_ok=True)
conn=sqlite3.connect(db); cur=conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY, username TEXT UNIQUE, passhash TEXT)")
cur.execute("DELETE FROM admin")
cur.execute("INSERT INTO admin(username, passhash) VALUES(?,?)",("${ADMIN_USER}", generate_password_hash("${RAND_PASS}")))
conn.commit(); conn.close()
print("OK")
PY

# export PUBLIC_IP for flask app use if available
if [[ -n "$PUBLIC_IP" ]]; then
  # make nginx + flask aware by environment var (gunicorn service picks from environment if set globally)
  # We'll write to /etc/environment for simplicity so that app sees PUBLIC_IP on restart.
  if ! grep -q '^PUBLIC_IP=' /etc/environment 2>/dev/null; then
    echo "PUBLIC_IP=${PUBLIC_IP}" >> /etc/environment
  else
    sed -i "s/^PUBLIC_IP=.*/PUBLIC_IP=${PUBLIC_IP}/" /etc/environment
  fi
fi

# reload services to pick up env and start app
systemctl restart openvpn-admin || true
systemctl restart nginx || true

echo
echo "========================================"
echo "INSTALL COMPLETE"
echo "Admin URL: http://${PUBLIC_IP:-<server-ip>}/dashboard"
echo "Admin user: ${ADMIN_USER}"
echo "Admin pass: ${RAND_PASS}"
echo "Notes:"
echo "- If PUBLIC_IP was not auto-detected, open /opt/openvpn-admin/ and edit .ovpn templates or set PUBLIC_IP in /etc/environment and restart openvpn-admin."
echo "- If your provider has external firewall, open TCP 80 and UDP 1194 there as well."
echo "- To enable HTTPS run certbot and I can provide automation for that."
echo "========================================"
