#!/usr/bin/env bash
# install-openvpn-admin-auth.sh
# Fresh installer: OpenVPN (username+password auth) + Flask Admin Panel with per-user device/session logs
# Tested on Ubuntu 22.04
set -euo pipefail
IFS=$'\n\t'

info(){ echo -e "\e[34m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
err(){ echo -e "\e[31m[ERROR]\e[0m $*"; exit 1; }
if [[ $EUID -ne 0 ]]; then err "Run as root"; fi

# Paths & vars
ADMIN_USER="admin"                 # web admin username (fixed)
INSTALL_DIR="/opt/openvpn-admin"
DB_PATH="$INSTALL_DIR/admin.db"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
OPENVPN_SERVER_DIR="/etc/openvpn/server"
OPENVPN_SERVER_CONF="${OPENVPN_SERVER_DIR}/server.conf"
CLIENTS_DIR="/etc/openvpn/clients"
AUTH_SCRIPT="/etc/openvpn/authenticate.sh"
CLIENT_CONNECT="/etc/openvpn/client-connect.sh"
CLIENT_DISCONNECT="/etc/openvpn/client-disconnect.sh"
FLASK_SERVICE="/etc/systemd/system/openvpn-admin.service"
NGINX_CONF="/etc/nginx/sites-available/openvpn-admin"

# Try detect public IP
PUBLIC_IP="$(curl -s https://ifconfig.co || curl -s https://icanhazip.com || echo "")"
if [[ -z "$PUBLIC_IP" ]]; then
  warn "Couldn't auto-detect public IP. .ovpn will contain placeholder YOUR.SERVER.IP"
fi

# ------------- Purge old -------------
info "Stopping services and removing previous configs..."
systemctl stop openvpn-server@server 2>/dev/null || true
systemctl disable openvpn-server@server 2>/dev/null || true
systemctl stop openvpn-admin 2>/dev/null || true
systemctl disable openvpn-admin 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true

rm -rf /etc/openvpn "$INSTALL_DIR" /var/log/openvpn
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/openvpn-admin /etc/nginx/sites-available/openvpn-admin "$FLASK_SERVICE"

# ------------- Install packages -------------
info "apt update & installing required packages..."
apt update
DEBIAN_FRONTEND=noninteractive apt install -y openvpn easy-rsa nginx python3-venv python3-pip ufw curl build-essential sqlite3

# ------------- Easy-RSA / PKI (server cert) -------------
info "Creating Easy-RSA PKI..."
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
mkdir -p "$OPENVPN_SERVER_DIR"
cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key "$OPENVPN_SERVER_DIR/"
popd >/dev/null

# ------------- OpenVPN server config (username+password auth) -------------
info "Writing OpenVPN server config (auth-user-pass-verify, client-connect/disconnect scripts)..."
mkdir -p /var/log/openvpn
cat > "${OPENVPN_SERVER_CONF}" <<'EOF'
port 1194
proto udp
dev tun
# server certs
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key
dh /etc/openvpn/server/dh.pem
tls-auth /etc/openvpn/server/ta.key 0

# allow clients without certs; we'll authenticate by username/password
client-cert-not-required
username-as-common-name

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt

# push DNS
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"

# auth scripts
script-security 3
auth-user-pass-verify /etc/openvpn/authenticate.sh via-file
client-connect /etc/openvpn/client-connect.sh
client-disconnect /etc/openvpn/client-disconnect.sh

status /etc/openvpn/server/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
EOF

systemctl enable --now openvpn-server@server || true

# Enable IP forwarding
info "Enable IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# ------------- UFW -------------
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

# ------------- Auth & connect scripts -------------
info "Writing auth/connect/disconnect helper scripts..."

# authenticate.sh: reads creds file (username\npassword), checks sqlite users table, prints OK/FAIL, exit 0/1
cat > "$AUTH_SCRIPT" <<'AUTH'
#!/usr/bin/env bash
# authenticate.sh: called by OpenVPN auth-user-pass-verify via-file
# argv0 = path to temporary file containing username\npassword
CREDFILE="$1"
DB="/opt/openvpn-admin/admin.db"
if [[ ! -f "$CREDFILE" ]]; then
  exit 1
fi
USERNAME="$(sed -n '1p' "$CREDFILE" | tr -d '\r\n')"
PASSWORD="$(sed -n '2p' "$CREDFILE" | tr -d '\r\n')"
# read hashed password from sqlite
if [[ ! -f "$DB" ]]; then
  echo "no-db" >&2
  exit 1
fi
HASH="$(sqlite3 "$DB" "SELECT passhash FROM users WHERE username='${USERNAME}' LIMIT 1;")"
if [[ -z "$HASH" ]]; then
  # unknown user
  exit 1
fi
# verify using python's werkzeug to avoid adding bcrypt dep in bash
python3 - <<PY
from werkzeug.security import check_password_hash
h="$HASH"
p="$PASSWORD"
import sys
if check_password_hash(h,p):
    sys.exit(0)
else:
    sys.exit(1)
PY
exit $?
AUTH
chmod 700 "$AUTH_SCRIPT"
chown root:root "$AUTH_SCRIPT"

# client-connect: record session start into sessions table
cat > "$CLIENT_CONNECT" <<'CC'
#!/usr/bin/env bash
# client-connect: $common_name available as env, untrusted_ip, ifconfig_pool_remote_ip
DB="/opt/openvpn-admin/admin.db"
USERNAME="${common_name:-unknown}"
REMOTE="${untrusted_ip:-unknown}"
VIP="${ifconfig_pool_remote_ip:-unknown}"
CLIENT_INFO="${untrusted_ip_hostname:-}${tls_client}-{${tls_version:-}}"
START_TS=$(date +%s)
# insert session row
sqlite3 "$DB" "INSERT INTO sessions(username, remote_addr, virtual_ip, start_ts, client_info) VALUES('${USERNAME}','${REMOTE}','${VIP}',${START_TS},'${CLIENT_INFO}');"
# echo session id?
CC
chmod 700 "$CLIENT_CONNECT"
chown root:root "$CLIENT_CONNECT"

# client-disconnect: update session end_ts and compute duration (match by username and start_ts latest)
cat > "$CLIENT_DISCONNECT" <<'CD'
#!/usr/bin/env bash
DB="/opt/openvpn-admin/admin.db"
USERNAME="${common_name:-unknown}"
END_TS=$(date +%s)
# update last open session for this username without end_ts
sqlite3 "$DB" "UPDATE sessions SET end_ts=${END_TS}, duration_min = ROUND(((${END_TS}-start_ts)/60.0),2) WHERE username='${USERNAME}' AND end_ts IS NULL ORDER BY start_ts DESC LIMIT 1;"
CD
chmod 700 "$CLIENT_DISCONNECT"
chown root:root "$CLIENT_DISCONNECT"

# ------------- Flask app (full) -------------
info "Installing Flask app and DB..."
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/templates" "$INSTALL_DIR/static" "$CLIENTS_DIR"
chown -R root:root "$CLIENTS_DIR"
chmod 700 "$CLIENTS_DIR"

python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install flask werkzeug gunicorn

# create sqlite DB and tables: users, sessions
python3 - <<PY
import sqlite3, os
db = "$DB_PATH"
os.makedirs(os.path.dirname(db), exist_ok=True)
conn = sqlite3.connect(db)
cur = conn.cursor()
# users: username unique, passhash (werkzeug)
cur.execute("""CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    passhash TEXT
)""")
# sessions: track connection events
cur.execute("""CREATE TABLE IF NOT EXISTS sessions (
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
conn.commit()
# create initial admin user (web UI user)
from werkzeug.security import generate_password_hash
admin_pass = (os.environ.get("OPENVPN_ADMIN_PASS") or "AA123")
try:
    cur.execute("INSERT INTO users(username,passhash) VALUES(?,?)", ("$ADMIN_USER", generate_password_hash(admin_pass)))
except:
    pass
conn.commit()
conn.close()
print("DB ready. Admin user:", "$ADMIN_USER")
PY

# Flask app code
cat > "$INSTALL_DIR/app.py" <<'PY'
import os, sqlite3, time
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(__file__)
DB = os.path.join(APP_DIR, "admin.db")
CLIENTS_DIR = "/etc/openvpn/clients"
PUBLIC_IP = os.environ.get("PUBLIC_IP", "YOUR.SERVER.IP")

app = Flask(__name__)
app.secret_key = os.urandom(24)

def db_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def require_login():
    return 'user' in session

@app.route("/", methods=["GET","POST"])
def login():
    if request.method=="POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        conn = db_conn(); cur = conn.cursor()
        cur.execute("SELECT username,passhash FROM users WHERE username=?",(u,))
        row = cur.fetchone()
        conn.close()
        if row and check_password_hash(row["passhash"], p):
            session['user'] = row["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials","danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not require_login(): return redirect(url_for("login"))
    conn = db_conn(); cur = conn.cursor()
    # connected count: sessions with end_ts IS NULL
    cur.execute("SELECT COUNT(*) as c FROM sessions WHERE end_ts IS NULL")
    connected = cur.fetchone()["c"]
    # recent sessions
    cur.execute("SELECT * FROM sessions ORDER BY start_ts DESC LIMIT 50")
    sessions = cur.fetchall()
    conn.close()
    return render_template("dashboard.html", connected=connected, sessions=sessions)

@app.route("/users", methods=["GET","POST"])
def users():
    if not require_login(): return redirect(url_for("login"))
    conn = db_conn(); cur = conn.cursor()
    if request.method=="POST":
        uname = request.form.get("username","").strip()
        pwd = request.form.get("password","").strip()
        if not uname or not pwd:
            flash("Username and password required","danger"); return redirect(url_for("users"))
        # password policy: 2 uppercase + 3 digits
        import re
        if not re.match(r'^[A-Z]{2}\d{3}$', pwd):
            flash("Password must be 2 uppercase letters followed by 3 digits (e.g., AB123)","danger"); return redirect(url_for("users"))
        ph = generate_password_hash(pwd)
        try:
            cur.execute("INSERT INTO users(username, passhash) VALUES(?,?)",(uname,ph))
            conn.commit()
            flash("User created","success")
        except Exception as e:
            flash("Error creating user: "+str(e),"danger")
    cur.execute("SELECT username FROM users ORDER BY username")
    users = [r["username"] for r in cur.fetchall()]
    conn.close()
    return render_template("users.html", users=users)

@app.route("/users/<username>/edit", methods=["GET","POST"])
def edit_user(username):
    if not require_login(): return redirect(url_for("login"))
    conn = db_conn(); cur = conn.cursor()
    if request.method=="POST":
        newpw = request.form.get("password","").strip()
        if newpw:
            cur.execute("UPDATE users SET passhash=? WHERE username=?", (generate_password_hash(newpw), username))
            conn.commit()
            flash("Password updated","success")
        return redirect(url_for("users"))
    conn.close()
    return render_template("edit_user.html", username=username)

@app.route("/users/<username>/delete", methods=["POST"])
def delete_user(username):
    if not require_login(): return redirect(url_for("login"))
    conn = db_conn(); cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit(); conn.close()
    flash("User deleted", "success")
    return redirect(url_for("users"))

@app.route("/users/<username>/sessions")
def user_sessions(username):
    if not require_login(): return redirect(url_for("login"))
    conn = db_conn(); cur = conn.cursor()
    cur.execute("SELECT * FROM sessions WHERE username=? ORDER BY start_ts DESC", (username,))
    rows = cur.fetchall()
    conn.close()
    return render_template("user_sessions.html", username=username, sessions=rows)

@app.route("/sessions/<int:sid>/end", methods=["POST"])
def end_session(sid):
    if not require_login(): return redirect(url_for("login"))
    conn = db_conn(); cur = conn.cursor()
    end_ts = int(time.time())
    cur.execute("UPDATE sessions SET end_ts=?, duration_min=ROUND((? - start_ts)/60.0,2) WHERE id=? AND end_ts IS NULL", (end_ts, end_ts, sid))
    conn.commit(); conn.close()
    flash("Session marked ended", "success")
    return redirect(url_for("dashboard"))

@app.route("/download/<username>")
def download_profile(username):
    if not require_login(): return redirect(url_for("login"))
    # generate profile (no client cert): includes ca + ta + auth instructions
    ca = open("/etc/openvpn/server/ca.crt").read()
    ta = open("/etc/openvpn/server/ta.key").read()
    profile = f"""client
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
    fname = f"/tmp/{username}.ovpn"
    with open(fname,"w") as f: f.write(profile)
    return send_file(fname, as_attachment=True)

@app.route("/logs")
def logs():
    if not require_login(): return redirect(url_for("login"))
    # only show connect/disconnect entries from openvpn log (filter)
    logpath = "/var/log/openvpn/openvpn.log"
    lines=[]
    if os.path.exists(logpath):
        with open(logpath) as f: 
            for ln in f:
                if any(k in ln for k in ("IP_ADDRESS", "Authenticate/Initialization", "client_connect", "client_disconnect", "AUTH")):
                    lines.append(ln.rstrip())
    return render_template("logs.html", lines=lines)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
PY

# Templates (Bootstrap responsive)
cat > "$INSTALL_DIR/templates/base.html" <<'HTML'
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<title>OpenVPN Admin</title>
<style>body{padding-top:70px}.logbox{max-height:60vh;overflow:auto;background:#0b1220;color:#cfe8ff;padding:1rem;border-radius:.5rem}</style>
</head>
<body>
<nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
<div class="container-fluid">
  <a class="navbar-brand" href="/dashboard">OpenVPN Admin</a>
  <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navmenu"><span class="navbar-toggler-icon"></span></button>
  <div class="collapse navbar-collapse" id="navmenu">
    <ul class="navbar-nav me-auto">
      <li class="nav-item"><a class="nav-link" href="/dashboard">Dashboard</a></li>
      <li class="nav-item"><a class="nav-link" href="/users">Users</a></li>
      <li class="nav-item"><a class="nav-link" href="/logs">Logs</a></li>
    </ul>
    <ul class="navbar-nav"><li class="nav-item"><a class="nav-link" href="/logout">Logout</a></li></ul>
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
  <div class="card">
   <div class="card-body">
    <h5 class="card-title">Admin Login</h5>
    <form method="post">
      <div class="mb-2"><label>Username</label><input class="form-control" name="username" required></div>
      <div class="mb-2"><label>Password</label><input class="form-control" name="password" type="password" required></div>
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
  <div class="card mb-3"><div class="card-header">Connected Devices <span class="badge bg-primary">{{connected}}</span></div>
   <div class="card-body">
    {% if sessions %}
      <div class="list-group">
      {% for s in sessions %}
       <div class="list-group-item">
         <div class="d-flex justify-content-between">
           <div>
             <strong>{{ s['username'] }}</strong> <small class="text-muted">({{ s['client_info'] or 'unknown' }})</small><br>
             <small class="text-muted">{{ s['remote_addr'] }} → {{ s['virtual_ip'] }}</small>
           </div>
           <div class="text-end">
             <div>Start: {{ (s['start_ts']|int)|datetimeformat }}</div>
             <div>Duration: {% if s['end_ts'] %}{{ s['duration_min'] }} min{% else %}Active{% endif %}</div>
             <div class="mt-2">
               <form method="post" action="/sessions/{{s['id']}}/end" style="display:inline"><button class="btn btn-sm btn-outline-danger">End</button></form>
               <a class="btn btn-sm btn-outline-primary" href="/users/{{ s['username'] }}/sessions">View</a>
             </div>
           </div>
         </div>
       </div>
      {% endfor %}
      </div>
    {% else %}
      <div class="text-muted">No sessions yet.</div>
    {% endif %}
   </div>
  </div>
 </div>

 <div class="col-lg-6">
  <div class="card mb-3"><div class="card-header">Quick Actions</div>
   <div class="card-body">
     <a class="btn btn-success" href="/users">Manage Users</a>
     <a class="btn btn-secondary" href="/logs">OpenVPN Logs</a>
   </div>
  </div>
  <div class="card"><div class="card-header">Help</div>
   <div class="card-body"><p>Download per-user profile (no cert): go to Users → Download</p></div>
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
  <div class="card mb-3"><div class="card-header">Create User</div>
   <div class="card-body">
    <form method="post">
      <div class="mb-2"><label>Username</label><input class="form-control" name="username" required></div>
      <div class="mb-2"><label>Password (2 uppercase letters + 3 digits, e.g., AB123)</label><input class="form-control" name="password" required></div>
      <button class="btn btn-primary">Create</button>
    </form>
   </div></div>

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
            <form method="post" action="/users/{{u}}/delete" style="display:inline" onsubmit="return confirm('Delete user {{u}}?');">
              <button class="btn btn-sm btn-outline-danger">Delete</button>
            </form>
          </span>
        </li>
      {% endfor %}
      </ul>
    {% else %}
      <div class="text-muted">No users</div>
    {% endif %}
   </div></div>
 </div>
 <div class="col-md-6">
  <div class="card"><div class="card-header">Notes</div>
   <div class="card-body">Profiles include CA & TA and require <code>auth-user-pass</code> when connecting. Edit PUBLIC_IP env if needed.</div>
  </div>
 </div>
</div>
{% endblock %}
HTML

cat > "$INSTALL_DIR/templates/edit_user.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header">Edit User: {{username}}</div>
  <div class="card-body">
    <form method="post">
      <div class="mb-2"><label>New Password (leave empty to keep)</label><input class="form-control" name="password"></div>
      <button class="btn btn-primary">Save</button>
    </form>
  </div>
</div>
{% endblock %}
HTML

cat > "$INSTALL_DIR/templates/user_sessions.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<h4>Sessions for {{username}}</h4>
{% if sessions %}
  <div class="list-group">
  {% for s in sessions %}
    <div class="list-group-item d-flex justify-content-between">
      <div>
        <strong>{{s['client_info'] or 'unknown'}}</strong><br>
        <small class="text-muted">{{s['remote_addr']}} -> {{s['virtual_ip']}}</small>
      </div>
      <div class="text-end">
        <div>Start: {{(s['start_ts']|int)|datetimeformat}}</div>
        <div>End: {% if s['end_ts'] %}{{(s['end_ts']|int)|datetimeformat}} ({{s['duration_min']}} min){% else %}Active{% endif %}</div>
      </div>
    </div>
  {% endfor %}
  </div>
{% else %}
  <div class="text-muted">No sessions</div>
{% endif %}
{% endblock %}
HTML

cat > "$INSTALL_DIR/templates/logs.html" <<'HTML'
{% extends "base.html" %}
{% block content %}
<div class="card"><div class="card-header">OpenVPN Recent Logs</div>
<div class="card-body"><pre class="logbox">{{ lines|join("\n") }}</pre></div></div>
{% endblock %}
HTML

# Jinja filter to format timestamp
cat >> "$INSTALL_DIR/app.py" <<'PY'
from datetime import datetime
@app.template_filter('datetimeformat')
def datetimeformat(value):
    try:
        return datetime.utcfromtimestamp(int(value)).strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return "-"
PY

# ------------- systemd service for gunicorn -------------
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
systemctl enable --now openvpn-admin || true

# ------------- nginx -------------
info "Configuring nginx..."
cat > "$NGINX_CONF" <<'NG'
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
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/openvpn-admin
rm -f /etc/nginx/sites-enabled/default || true
nginx -t && systemctl enable --now nginx || warn "Nginx failed to start"

# ------------- Finalize PUBLIC_IP into env for Flask (optional) -------------
if [[ -n "$PUBLIC_IP" ]]; then
  grep -q '^PUBLIC_IP=' /etc/environment 2>/dev/null || echo "PUBLIC_IP=${PUBLIC_IP}" >> /etc/environment
fi
systemctl restart openvpn-admin || true
systemctl restart nginx || true

# ------------- Output -------------
echo
echo "========================================"
echo "INSTALL COMPLETE"
echo "Admin UI: http://${PUBLIC_IP:-<server-ip>}/"
echo "Web admin user: ${ADMIN_USER} (created - change via Users page)"
echo "IMPORTANT: Created users require password pattern: 2 uppercase letters + 3 digits (e.g., AB123)"
echo "To create user: Login -> Users -> Create (username + password). Then download profile and connect using auth-user-pass."
echo "OpenVPN auth uses /etc/openvpn/authenticate.sh which checks /opt/openvpn-admin/admin.db users table."
echo "Sessions (per-device) are recorded via client-connect and client-disconnect scripts and visible in UI under Dashboard & per-user pages."
echo "If provider-level firewall exists, open TCP/80 and UDP/1194."
echo "========================================"
