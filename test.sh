#!/usr/bin/env bash
# install-openvpn-admin-single.sh
# One-shot fresh installer:
# - Purge old install
# - OpenVPN (username+password auth, no client cert required)
# - Easy-RSA for server cert
# - Flask Admin (Bootstrap 5 responsive) with:
#   Users CRUD (username+password), per-user sessions (device items),
#   .ovpn download (auth-user-pass), change password, logs (connection-only)
# - Gunicorn + systemd + Nginx reverse proxy
# - UFW + NAT
# Tested on Ubuntu 22.04

set -euo pipefail
IFS=$'\n\t'

info(){ echo -e "\e[34m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
err(){ echo -e "\e[31m[ERROR]\e[0m $*"; exit 1; }
req_root(){ [[ $EUID -eq 0 ]] || err "Run as root (sudo)."; }; req_root

# Paths & const
ADMIN_USER_WEB="admin"                   # web panel login user created initially
ADMIN_INIT_PASS="AA123"                  # web panel initial password (change from UI)
APP_DIR="/opt/openvpn-admin"
VENV="$APP_DIR/venv"
DB="$APP_DIR/admin.db"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
OVPN_DIR="/etc/openvpn"
OVPN_SERVER_DIR="$OVPN_DIR/server"
SERVER_CONF="$OVPN_SERVER_DIR/server.conf"
CLIENTS_DIR="$OVPN_DIR/clients"
AUTH_SCRIPT="$OVPN_DIR/authenticate.sh"
CC_SCRIPT="$OVPN_DIR/client-connect.sh"
CD_SCRIPT="$OVPN_DIR/client-disconnect.sh"
FLASK_SERVICE="/etc/systemd/system/openvpn-admin.service"
NGINX_SITE="/etc/nginx/sites-available/openvpn-admin"
NGINX_LINK="/etc/nginx/sites-enabled/openvpn-admin"

# Detect public IP & egress interface
PUBLIC_IP="$(curl -s https://ifconfig.co || curl -s https://icanhazip.com || echo "")"
EGRESS_IF="$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for (i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}' || echo eth0)"
[[ -z "$EGRESS_IF" ]] && EGRESS_IF="eth0"

# -------- PURGE OLD INSTALL --------
info "Removing previous OpenVPN/Admin installation..."
systemctl stop openvpn-server@server 2>/dev/null || true
systemctl disable openvpn-server@server 2>/dev/null || true
systemctl stop openvpn-admin 2>/dev/null || true
systemctl disable openvpn-admin 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true

rm -rf "$OVPN_DIR" "$APP_DIR" /var/log/openvpn
rm -f "$FLASK_SERVICE" "$NGINX_SITE" "$NGINX_LINK"
rm -f /etc/nginx/sites-enabled/default

# -------- INSTALL PACKAGES --------
info "Updating apt & installing dependencies..."
apt update
DEBIAN_FRONTEND=noninteractive apt install -y openvpn easy-rsa nginx python3-venv python3-pip ufw curl sqlite3

# -------- EASY-RSA (server cert only) --------
info "Setting up Easy-RSA PKI (server cert)..."
rm -rf "$EASYRSA_DIR"
make-cadir "$EASYRSA_DIR"
pushd "$EASYRSA_DIR" >/dev/null
./easyrsa init-pki
echo | ./easyrsa build-ca nopass
./easyrsa gen-req server nopass
./easyrsa sign-req server server <<'YES'
yes
YES
./easyrsa gen-dh
openvpn --genkey --secret ta.key
mkdir -p "$OVPN_SERVER_DIR"
cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key "$OVPN_SERVER_DIR/"
popd >/dev/null

# -------- OPENVPN SERVER CONFIG --------
info "Writing OpenVPN server config (username+password auth)..."
mkdir -p "$OVPN_SERVER_DIR" /var/log/openvpn "$CLIENTS_DIR"
cat > "$SERVER_CONF" <<EOF
port 1194
proto udp
dev tun
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
tls-auth /etc/openvpn/server/ta.key 0

# Username/password auth (no client cert)
client-cert-not-required
username-as-common-name

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt

# Routes / DNS
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"

# Auth & session tracking
script-security 3
auth-user-pass-verify /etc/openvpn/authenticate.sh via-file
client-connect /etc/openvpn/client-connect.sh
client-disconnect /etc/openvpn/client-disconnect.sh

status /etc/openvpn/server/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
EOF

# Enable IP forwarding
info "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# -------- FIREWALL & NAT --------
info "Configuring UFW + NAT (egress: $EGRESS_IF)..."
ufw allow OpenSSH || true
ufw allow 1194/udp || true
ufw allow 80/tcp || true
UFW_BEFORE="/etc/ufw/before.rules"
# Remove old block then write fresh
sed -i '/### OPENVPN RULES/,/### END OPENVPN RULES/d' "$UFW_BEFORE" 2>/dev/null || true
cat >> "$UFW_BEFORE" <<RULES
### OPENVPN RULES
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/8 -o $EGRESS_IF -j MASQUERADE
COMMIT
### END OPENVPN RULES
RULES
ufw --force enable

# -------- PY ENV & DB --------
info "Creating Flask app (venv) & database..."
mkdir -p "$APP_DIR" "$APP_DIR/templates" "$APP_DIR/static"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip wheel
"$VENV/bin/pip" install flask werkzeug gunicorn

# Create DB schema (users, sessions)
"$VENV/bin/python3" - <<PY
import sqlite3, os
from werkzeug.security import generate_password_hash
db = "$DB"
os.makedirs(os.path.dirname(db), exist_ok=True)
conn = sqlite3.connect(db)
c = conn.cursor()
c.execute("""CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE,
  passhash TEXT
)""")
c.execute("""CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY,
  username TEXT,
  remote_addr TEXT,
  virtual_ip TEXT,
  start_ts INTEGER,
  end_ts INTEGER,
  duration_min REAL,
  client_info TEXT,
  tag TEXT
)""")
# seed web admin user
if not c.execute("SELECT 1 FROM users WHERE username=?", ("$ADMIN_USER_WEB",)).fetchone():
  c.execute("INSERT INTO users(username,passhash) VALUES(?,?)",
            ("$ADMIN_USER_WEB", generate_password_hash("$ADMIN_INIT_PASS")))
conn.commit(); conn.close()
PY

# -------- AUTH/CNX SCRIPTS (OpenVPN calls these) --------
info "Installing OpenVPN auth/connect/disconnect scripts..."
# authentication: verify username/password from SQLite (using venv Python+werkzeug)
cat > "$AUTH_SCRIPT" <<'AUTH'
#!/usr/bin/env bash
CREDFILE="$1"
DB="/opt/openvpn-admin/admin.db"
VENV_PY="/opt/openvpn-admin/venv/bin/python3"
[ ! -f "$CREDFILE" ] && exit 1
USERNAME="$(sed -n '1p' "$CREDFILE" | tr -d '\r\n')"
PASSWORD="$(sed -n '2p' "$CREDFILE" | tr -d '\r\n')"
"$VENV_PY" - <<PY
import sqlite3, sys
from werkzeug.security import check_password_hash
db="$DB"; u="$USERNAME"; p="$PASSWORD"
conn=sqlite3.connect(db); c=conn.cursor()
c.execute("SELECT passhash FROM users WHERE username=?",(u,))
row=c.fetchone(); conn.close()
sys.exit(0 if (row and check_password_hash(row[0], p)) else 1)
PY
AUTH
chmod 700 "$AUTH_SCRIPT"

# client-connect: insert a session row
cat > "$CC_SCRIPT" <<'CC'
#!/usr/bin/env bash
DB="/opt/openvpn-admin/admin.db"
VENV_PY="/opt/openvpn-admin/venv/bin/python3"
USERNAME="${common_name:-unknown}"
REMOTE="${untrusted_ip:-unknown}"
VIP="${ifconfig_pool_remote_ip:-unknown}"
START_TS=$(date +%s)
INFO="${IV_PLAT:-}${IV_GUI_VER:-}${IV_VER:-}"
"$VENV_PY" - <<PY
import sqlite3
conn=sqlite3.connect("$DB"); c=conn.cursor()
c.execute("INSERT INTO sessions(username,remote_addr,virtual_ip,start_ts,client_info) VALUES(?,?,?,?,?)",
          ("$USERNAME","$REMOTE","$VIP",$START_TS,"$INFO"))
conn.commit(); conn.close()
PY
CC
chmod 700 "$CC_SCRIPT"

# client-disconnect: mark session end
cat > "$CD_SCRIPT" <<'CD'
#!/usr/bin/env bash
DB="/opt/openvpn-admin/admin.db"
VENV_PY="/opt/openvpn-admin/venv/bin/python3"
USERNAME="${common_name:-unknown}"
END_TS=$(date +%s)
"$VENV_PY" - <<PY
import sqlite3, time
db="$DB"; u="$USERNAME"; e=$END_TS
conn=sqlite3.connect(db); c=conn.cursor()
c.execute("UPDATE sessions SET end_ts=?, duration_min=ROUND((? - start_ts)/60.0,2) WHERE username=? AND end_ts IS NULL ORDER BY start_ts DESC LIMIT 1",
          (e,e,u))
conn.commit(); conn.close()
PY
CD
chmod 700 "$CD_SCRIPT"

# -------- FLASK APP (full UI) --------
info "Writing Flask application..."
cat > "$APP_DIR/app.py" <<'PY'
import os, sqlite3, time
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session

APP_DIR = "/opt/openvpn-admin"
DB = os.path.join(APP_DIR, "admin.db")
PUBLIC_IP = os.environ.get("PUBLIC_IP","YOUR.SERVER.IP")
LOG_PATH = "/var/log/openvpn/openvpn.log"

app = Flask(__name__)
app.secret_key = os.urandom(24)

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

# ---- filters ----
@app.template_filter('ts')
def ts(v):
    try: return datetime.utcfromtimestamp(int(v)).strftime('%Y-%m-%d %H:%M:%S UTC')
    except: return "-"

def need_login():
    return 'user' in session

# ---- auth ----
from werkzeug.security import generate_password_hash, check_password_hash

@app.route("/", methods=["GET","POST"])
def login():
    if request.method=="POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        conn=db(); cur=conn.cursor()
        cur.execute("SELECT username,passhash FROM users WHERE username=?", (u,))
        row = cur.fetchone(); conn.close()
        if row and check_password_hash(row["passhash"], p):
            session['user']=row["username"]; return redirect("/dashboard")
        flash("Invalid credentials","danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect("/")

# ---- dashboard ----
@app.route("/dashboard")
def dashboard():
    if not need_login(): return redirect("/")
    conn=db(); cur=conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM sessions WHERE end_ts IS NULL")
    connected = cur.fetchone()["c"]
    cur.execute("SELECT * FROM sessions ORDER BY start_ts DESC LIMIT 50")
    sessions = cur.fetchall()
    conn.close()
    return render_template("dashboard.html", connected=connected, sessions=sessions)

# ---- users ----
@app.route("/users", methods=["GET","POST"])
def users():
    if not need_login(): return redirect("/")
    conn=db(); cur=conn.cursor()
    if request.method=="POST":
        uname=request.form.get("username","").strip()
        pwd=request.form.get("password","").strip()
        import re
        if not uname or not pwd:
            flash("Username & password required","danger"); return redirect("/users")
        if not re.match(r'^[A-Z]{2}\d{3}$', pwd):
            flash("Password must be 2 uppercase letters + 3 digits (e.g., AB123)","danger"); return redirect("/users")
        try:
            cur.execute("INSERT INTO users(username,passhash) VALUES(?,?)",(uname,generate_password_hash(pwd)))
            conn.commit(); flash("User created","success")
        except Exception as e:
            flash("Error creating user: "+str(e),"danger")
    cur.execute("SELECT username FROM users ORDER BY username")
    users=[r["username"] for r in cur.fetchall()]
    conn.close()
    return render_template("users.html", users=users)

@app.route("/users/<u>/edit", methods=["GET","POST"])
def edit_user(u):
    if not need_login(): return redirect("/")
    if request.method=="POST":
        newp=request.form.get("password","").strip()
        if newp:
            import re
            if not re.match(r'^[A-Z]{2}\d{3}$', newp):
                flash("Password must be 2 uppercase letters + 3 digits","danger"); return redirect(f"/users/{u}/edit")
            conn=db(); cur=conn.cursor()
            cur.execute("UPDATE users SET passhash=? WHERE username=?",(generate_password_hash(newp),u))
            conn.commit(); conn.close(); flash("Password updated","success")
        return redirect("/users")
    return render_template("edit_user.html", username=u)

@app.route("/users/<u>/delete", methods=["POST"])
def delete_user(u):
    if not need_login(): return redirect("/")
    conn=db(); cur=conn.cursor()
    cur.execute("DELETE FROM users WHERE username=?", (u,))
    conn.commit(); conn.close()
    flash("User deleted","success")
    return redirect("/users")

@app.route("/users/<u>/sessions")
def user_sessions(u):
    if not need_login(): return redirect("/")
    conn=db(); cur=conn.cursor()
    cur.execute("SELECT * FROM sessions WHERE username=? ORDER BY start_ts DESC",(u,))
    rows=cur.fetchall(); conn.close()
    return render_template("user_sessions.html", username=u, sessions=rows)

# ---- sessions ----
@app.route("/sessions/<int:sid>/end", methods=["POST"])
def end_session(sid):
    if not need_login(): return redirect("/")
    now=int(time.time())
    conn=db(); cur=conn.cursor()
    cur.execute("UPDATE sessions SET end_ts=?, duration_min=ROUND((? - start_ts)/60.0,2) WHERE id=? AND end_ts IS NULL",(now,now,sid))
    conn.commit(); conn.close()
    flash("Session marked ended","success")
    return redirect("/dashboard")

# ---- profile download (.ovpn) ----
@app.route("/download/<u>")
def download(u):
    if not need_login(): return redirect("/")
    ca=open("/etc/openvpn/server/ca.crt").read()
    ta=open("/etc/openvpn/server/ta.key").read()
    profile=f"""client
dev tun
proto udp
remote {PUBLIC_IP} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
remote-cert-tls server
cipher AES-256-CBC
verb 3
key-direction 1
<ca>
{ca}
</ca>
<tls-auth>
{ta}
</tls-auth>
"""
    path=f"/tmp/{u}.ovpn"
    with open(path,"w") as f: f.write(profile)
    return send_file(path, as_attachment=True)

# ---- logs (connection-only view) ----
@app.route("/logs")
def logs():
    if not need_login(): return redirect("/")
    lines=[]
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            for ln in f:
                # very light filter: only auth/connect/disconnect-ish entries
                if any(k in ln for k in ("Authenticate/","client-connect","client-disconnect","user-pass")):
                    lines.append(ln.rstrip())
    return render_template("logs.html", lines=lines)

# ---- template helpers ----
@app.context_processor
def inject_helpers():
    return dict()

if __name__=="__main__":
    app.run(host="127.0.0.1",port=5000)
PY

# Templates
cat > "$APP_DIR/templates/base.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenVPN Admin</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{padding-top:70px}.logbox{max-height:60vh;overflow:auto;background:#0b1220;color:#cfe8ff;padding:1rem;border-radius:.5rem}</style>
</head>
<body>
<nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
  <div class="container-fluid">
    <a class="navbar-brand" href="/dashboard">OpenVPN Admin</a>
    <button class="navbar-toggler" data-bs-toggle="collapse" data-bs-target="#nav"><span class="navbar-toggler-icon"></span></button>
    <div class="collapse navbar-collapse" id="nav">
      <ul class="navbar-nav me-auto">
        <li class="nav-item"><a class="nav-link" href="/dashboard">Dashboard</a></li>
        <li class="nav-item"><a class="nav-link" href="/users">Users</a></li>
        <li class="nav-item"><a class="nav-link" href="/logs">Logs</a></li>
      </ul>
      <ul class="navbar-nav">
        <li class="nav-item"><a class="nav-link" href="/logout">Logout</a></li>
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

cat > "$APP_DIR/templates/login.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6 col-lg-4">
    <div class="card shadow-sm">
      <div class="card-body">
        <h5 class="card-title">Admin Login</h5>
        <form method="post">
          <div class="mb-2"><label class="form-label">Username</label><input class="form-control" name="username" required></div>
          <div class="mb-2"><label class="form-label">Password</label><input class="form-control" type="password" name="password" required></div>
          <button class="btn btn-primary w-100">Login</button>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
HTML

cat > "$APP_DIR/templates/dashboard.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<h4 class="mb-3">Connected Devices <span class="badge bg-primary">{{connected}}</span></h4>
{% if sessions %}
  <div class="list-group">
  {% for s in sessions %}
    <div class="list-group-item">
      <div class="d-flex justify-content-between align-items-start">
        <div>
          <strong>{{s['username']}}</strong>
          <div class="small text-muted">{{ s['client_info'] or 'device' }}</div>
          <div class="small text-muted">{{ s['remote_addr'] }} → {{ s['virtual_ip'] }}</div>
        </div>
        <div class="text-end">
          <div>Start: {{ s['start_ts']|ts }}</div>
          <div>Duration: {% if s['end_ts'] %}{{ s['duration_min'] }} min{% else %}<span class="text-success">Active</span>{% endif %}</div>
          <div class="mt-2">
            <form method="post" action="/sessions/{{s['id']}}/end" style="display:inline">
              <button class="btn btn-sm btn-outline-danger">End</button>
            </form>
            <a class="btn btn-sm btn-outline-primary" href="/users/{{s['username']}}/sessions">View</a>
          </div>
        </div>
      </div>
    </div>
  {% endfor %}
  </div>
{% else %}
  <div class="text-muted">No sessions yet.</div>
{% endif %}
{% endblock %}
HTML

cat > "$APP_DIR/templates/users.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<div class="row">
  <div class="col-md-6">
    <div class="card mb-3"><div class="card-header">Create User</div>
      <div class="card-body">
        <form method="post">
          <div class="mb-2"><label class="form-label">Username</label><input class="form-control" name="username" required></div>
          <div class="mb-2"><label class="form-label">Password (e.g., AB123)</label><input class="form-control" name="password" required></div>
          <button class="btn btn-primary">Create</button>
        </form>
      </div>
    </div>
    <div class="card"><div class="card-header">Existing Users</div>
      <div class="card-body">
        {% if users %}
          <ul class="list-group">
          {% for u in users %}
            <li class="list-group-item d-flex justify-content-between align-items-center">
              {{u}}
              <span>
                <a class="btn btn-sm btn-outline-primary" href="/download/{{u}}">Profile</a>
                <a class="btn btn-sm btn-outline-secondary" href="/users/{{u}}/edit">Edit</a>
                <form method="post" action="/users/{{u}}/delete" style="display:inline" onsubmit="return confirm('Delete {{u}}?');">
                  <button class="btn btn-sm btn-outline-danger">Delete</button>
                </form>
              </span>
            </li>
          {% endfor %}
          </ul>
        {% else %}
          <div class="text-muted">No users.</div>
        {% endif %}
      </div>
    </div>
  </div>
  <div class="col-md-6">
    <div class="card"><div class="card-header">Tips</div>
      <div class="card-body">
        <p>Downloaded profile uses <code>auth-user-pass</code>. Clients must provide the created username & password.</p>
      </div>
    </div>
  </div>
</div>
{% endblock %}
HTML

cat > "$APP_DIR/templates/edit_user.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header">Edit User: {{username}}</div>
  <div class="card-body">
    <form method="post">
      <div class="mb-2"><label class="form-label">New Password (AB123)</label><input class="form-control" name="password"></div>
      <button class="btn btn-primary">Save</button>
    </form>
  </div>
</div>
{% endblock %}
HTML

cat > "$APP_DIR/templates/user_sessions.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<h4>Sessions for {{username}}</h4>
{% if sessions %}
  <div class="list-group">
  {% for s in sessions %}
    <div class="list-group-item d-flex justify-content-between">
      <div>
        <strong>{{ s['client_info'] or 'device' }}</strong><br>
        <small class="text-muted">{{ s['remote_addr'] }} → {{ s['virtual_ip'] }}</small>
      </div>
      <div class="text-end">
        <div>Start: {{ s['start_ts']|ts }}</div>
        <div>End: {% if s['end_ts'] %}{{ s['end_ts']|ts }} ({{ s['duration_min'] }} min){% else %}<span class="text-success">Active</span>{% endif %}</div>
      </div>
    </div>
  {% endfor %}
  </div>
{% else %}
  <div class="text-muted">No sessions.</div>
{% endif %}
{% endblock %}
HTML

cat > "$APP_DIR/templates/logs.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<div class="card"><div class="card-header">Connection Logs (filtered)</div>
<div class="card-body"><pre class="logbox">{{ lines|join("\n") }}</pre></div></div>
{% endblock %}
HTML

# -------- SYSTEMD for Gunicorn --------
info "Creating systemd service for admin panel..."
cat > "$FLASK_SERVICE" <<EOF
[Unit]
Description=OpenVPN Admin Panel
After=network.target

[Service]
WorkingDirectory=$APP_DIR
Environment="PATH=$VENV/bin"
ExecStart=$VENV/bin/gunicorn -b 127.0.0.1:5000 app:app
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now openvpn-admin

# -------- NGINX REVERSE PROXY --------
info "Configuring nginx reverse proxy..."
cat > "$NGINX_SITE" <<'NG'
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
NG
ln -sf "$NGINX_SITE" "$NGINX_LINK"
nginx -t && systemctl enable --now nginx && systemctl reload nginx

# -------- START OPENVPN --------
systemctl enable --now openvpn-server@server

# -------- Persist PUBLIC_IP env (optional) --------
if [[ -n "$PUBLIC_IP" ]]; then
  if grep -q '^PUBLIC_IP=' /etc/environment 2>/dev/null; then
    sed -i "s/^PUBLIC_IP=.*/PUBLIC_IP=${PUBLIC_IP}/" /etc/environment
  else
    echo "PUBLIC_IP=${PUBLIC_IP}" >> /etc/environment
  fi
  systemctl restart openvpn-admin || true
fi

echo
echo "=============================="
echo "INSTALL COMPLETE ✅"
echo "Admin URL:  http://${PUBLIC_IP:-<server-ip>}/"
echo "Login:      ${ADMIN_USER_WEB} / ${ADMIN_INIT_PASS}"
echo "Notes:"
echo "- Add users from Users page (password format: AB123)."
echo "- Download profile per user; client will prompt for username/password."
echo "- Connected devices & per-user sessions visible in Dashboard/Users."
echo "- If provider firewall exists, open TCP/80 & UDP/1194 there too."
echo "=============================="
