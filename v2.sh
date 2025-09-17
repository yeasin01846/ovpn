#!/usr/bin/env bash
set -euo pipefail

# One-click OpenVPN installer + improved Flask admin panel
# Supports Ubuntu/Debian (tested 20.04/22.04)
# Usage: sudo bash openvpn-oneclick.sh
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo)."
  exit 1
fi

# DEFAULT ADMIN: username=openvpn, password=random 5 chars (UPPER+DIGITS, e.g. GK234)
ADMIN_USER="openvpn"
# generate 5-char password with at least one uppercase letter and digits (mix)
ADMIN_PASS="$(tr -dc 'A-Z0-9' </dev/urandom | fold -w5 | head -n1)"
# Ensure it's 5-chars; if for any reason shorter, pad with random A-Z
while [ "${#ADMIN_PASS}" -lt 5 ]; do
  ADMIN_PASS="${ADMIN_PASS}$(tr -dc 'A-Z' </dev/urandom | fold -w1 | head -n1)"
  ADMIN_PASS="$(echo "${ADMIN_PASS}" | cut -c1-5)"
done

OVPN_PORT=1194
PROTO=udp
SERVER_IP="$(hostname -I | awk '{print $1}')"
VPN_NET="10.8.0.0"
VPN_NET_MASK="255.255.255.0"
PKI_DIR="/etc/openvpn/easy-rsa"
OPENVPN_DIR="/etc/openvpn"
ADMIN_DIR="/etc/openvpn-admin"
STATUS_LOG="/var/log/openvpn-status.log"
OPENVPN_LOG="/var/log/openvpn.log"
FLASK_PORT=8080

echo "Installing dependencies..."
apt update
DEBIAN_FRONTEND=noninteractive apt install -y openvpn easy-rsa python3 python3-venv python3-pip nginx iptables-persistent

# Prepare Easy-RSA
mkdir -p "${PKI_DIR}"
cp -r /usr/share/easy-rsa/* "${PKI_DIR}/"
chown -R root:root "${PKI_DIR}"
cd "${PKI_DIR}"

if [ ! -d "${PKI_DIR}/pki" ]; then
  echo "Initializing PKI..."
  ./easyrsa init-pki
  echo "set_var EASYRSA_REQ_CN \"OpenVPN-CA-$(date +%s)\"" > vars
  ./easyrsa --batch build-ca nopass
  ./easyrsa gen-req server nopass
  ./easyrsa sign-req server server <<EOF
yes
EOF
  ./easyrsa gen-dh
  openvpn --genkey --secret "${OPENVPN_DIR}/ta.key"
  cp pki/ca.crt "${OPENVPN_DIR}/"
  cp pki/issued/server.crt "${OPENVPN_DIR}/"
  cp pki/private/server.key "${OPENVPN_DIR}/"
  cp pki/dh.pem "${OPENVPN_DIR}/dh.pem"
fi

# Create server.conf (ensure management enabled for disconnect)
cat > "${OPENVPN_DIR}/server.conf" <<EOF
port ${OVPN_PORT}
proto ${PROTO}
dev tun
user nobody
group nogroup
persist-key
persist-tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
topology subnet
server ${VPN_NET} ${VPN_NET_MASK}
ifconfig-pool-persist /var/log/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
tls-auth /etc/openvpn/ta.key 0
cipher AES-256-CBC
auth SHA256
status ${STATUS_LOG}
log-append ${OPENVPN_LOG}
verb 3
management 127.0.0.1 7505
crl-verify /etc/openvpn/crl.pem
EOF

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
fi

# Setup iptables NAT (adjust interface if not eth0)
IFACE="eth0"
if ip link show eth0 >/dev/null 2>&1; then
  IFACE="eth0"
else
  # try to auto-detect outgoing interface
  IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')
fi

iptables -t nat -C POSTROUTING -s ${VPN_NET}/24 -o "${IFACE}" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s ${VPN_NET}/24 -o "${IFACE}" -j MASQUERADE
netfilter-persistent save

# Start OpenVPN
systemctl enable openvpn
systemctl restart openvpn || systemctl start openvpn

# Create admin dir and virtualenv
mkdir -p "${ADMIN_DIR}"
chown -R root:root "${ADMIN_DIR}"
cd "${ADMIN_DIR}"
python3 -m venv venv
. venv/bin/activate
cat > requirements.txt <<PYREQ
Flask==2.2.5
Flask-HTTPAuth==4.7.0
pyyaml
PYREQ
pip install -r requirements.txt

# Save admin credentials to env file (used by Flask app)
cat > "${ADMIN_DIR}/.env" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PASS=${ADMIN_PASS}
FLASK_PORT=${FLASK_PORT}
OPENVPN_DIR=${OPENVPN_DIR}
PKI_DIR=${PKI_DIR}
STATUS_LOG=${STATUS_LOG}
OPENVPN_LOG=${OPENVPN_LOG}
SERVER_IP=${SERVER_IP}
EOF
chmod 600 "${ADMIN_DIR}/.env"

# Create Flask admin app with settings + disconnect features
cat > "${ADMIN_DIR}/app.py" <<'PY'
from flask import Flask, request, redirect, url_for, send_file, render_template_string, flash
from flask_httpauth import HTTPBasicAuth
import os, subprocess, sqlite3, base64, time, shlex, socket

ENVFILE = '/etc/openvpn-admin/.env'

def load_env():
    env = {}
    try:
        with open(ENVFILE) as f:
            for l in f:
                if '=' in l:
                    k,v = l.strip().split('=',1); env[k]=v
    except:
        pass
    return env

env = load_env()
ADMIN_USER = env.get('ADMIN_USER','admin')
ADMIN_PASS = env.get('ADMIN_PASS','password')
OPENVPN_DIR = env.get('OPENVPN_DIR','/etc/openvpn')
PKI_DIR = env.get('PKI_DIR','/etc/openvpn/easy-rsa')
STATUS_LOG = env.get('STATUS_LOG','/var/log/openvpn-status.log')
OPENVPN_LOG = env.get('OPENVPN_LOG','/var/log/openvpn.log')
SERVER_IP = env.get('SERVER_IP','SERVER_IP_HERE')
DB_PATH = '/etc/openvpn-admin/users.db'
MGMT_HOST='127.0.0.1'
MGMT_PORT=7505

app = Flask(__name__)
app.secret_key = os.urandom(24)
auth = HTTPBasicAuth()

# Dynamic check: read env every login attempt so changes apply without restart
@auth.verify_password
def verify(username, password):
    current = load_env()
    u = current.get('ADMIN_USER','admin')
    p = current.get('ADMIN_PASS','password')
    return username == u and password == p

# Initialize DB
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS clients(name TEXT PRIMARY KEY, created_at TEXT)')
    conn.commit(); conn.close()
init_db()

def write_env(updates: dict):
    current = load_env()
    current.update(updates)
    with open(ENVFILE, 'w') as f:
        for k,v in current.items():
            f.write(f"{k}={v}\n")
    os.chmod(ENVFILE, 0o600)

def create_client(name):
    name = name.replace('..','').replace('/','')
    p = subprocess.run([f"{PKI_DIR}/easyrsa", "build-client-full", name, "nopass"], cwd=PKI_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.returncode==0, p.stdout + p.stderr

def revoke_client(name):
    name = name.replace('..','').replace('/','')
    p = subprocess.run([f"{PKI_DIR}/easyrsa", "revoke", name], cwd=PKI_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, input="yes\n")
    subprocess.run([f"{PKI_DIR}/easyrsa", "gen-crl"], cwd=PKI_DIR)
    subprocess.run(["cp", f"{PKI_DIR}/pki/crl.pem", f"{OPENVPN_DIR}/crl.pem"])
    subprocess.run(["chown", "nobody:nogroup", f"{OPENVPN_DIR}/crl.pem"], check=False)
    return p.returncode==0, p.stdout + p.stderr

def make_ovpn(name):
    name = name.replace('..','').replace('/','')
    ca = open(f"{PKI_DIR}/pki/ca.crt").read()
    cert = open(f"{PKI_DIR}/pki/issued/{name}.crt").read()
    key = open(f"{PKI_DIR}/pki/private/{name}.key").read()
    ta = open(f"{OPENVPN_DIR}/ta.key").read()
    config = f"""client
dev tun
proto udp
remote {load_env().get('SERVER_IP','SERVER_IP_HERE')} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
verb 3
<ca>\n{ca}\n</ca>
<cert>\n{cert}\n</cert>
<key>\n{key}\n</key>
<tls-auth>\n{ta}\n</tls-auth>
key-direction 1
"""
    fn = f"/tmp/{name}.ovpn"
    with open(fn,'w') as f: f.write(config)
    return fn

def mgmt_command(cmd, expect=None, timeout=2):
    """Send command to management socket and return response"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((MGMT_HOST, MGMT_PORT))
        s.sendall((cmd + "\n").encode())
        s.settimeout(timeout)
        data = b''
        while True:
            try:
                part = s.recv(4096)
                if not part:
                    break
                data += part
            except socket.timeout:
                break
        s.close()
        text = data.decode(errors='ignore')
        return text
    except Exception as e:
        return f"ERROR: {e}"

@app.route('/')
@auth.login_required
def index():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT name,created_at FROM clients')
    clients = c.fetchall()
    conn.close()

    # connected clients from status log
    connected=[]
    try:
        with open(STATUS_LOG) as sf:
            lines = sf.read().splitlines()
            for l in lines:
                if l.strip() and not l.startswith('#') and ',' in l:
                    parts = l.split(',')
                    if len(parts)>=6:
                        connected.append(dict(name=parts[0],remote=parts[1],virtual=parts[2],since=parts[5]))
    except Exception as e:
        connected.append({'error':str(e)})

    # tail logs
    logtail=""
    try:
        with open(OPENVPN_LOG) as lf:
            logtail = ''.join(lf.readlines()[-200:])
    except:
        logtail = 'no log yet'

    template = """
    <h2>OpenVPN Admin</h2>
    <p><a href="/add">Add client</a> | <a href="/connected">Connected</a> | <a href="/logs">Logs</a> | <a href="/settings">Settings</a></p>
    <h3>Clients</h3>
    <ul>
    {% for c in clients %}
      <li>{{c[0]}} - created {{c[1]}} - <a href="/download/{{c[0]}}">.ovpn</a> - <a href="/revoke/{{c[0]}}">revoke</a></li>
    {% endfor %}
    </ul>
    <h3>Currently connected</h3>
    <ul>
    {% for c in connected %}
      {% if c.error %}
        <li>Error: {{c.error}}</li>
      {% else %}
        <li>{{c.name}} | {{c.remote}} | {{c.virtual}} | since {{c.since}} - <a href="/disconnect/{{c.name}}">Disconnect</a></li>
      {% endif %}
    {% endfor %}
    </ul>
    """
    return render_template_string(template, clients=clients, connected=connected)

@app.route('/add', methods=['GET','POST'])
@auth.login_required
def add():
    if request.method=='POST':
        name = request.form.get('name','').strip()
        if not name:
            flash('Provide name')
            return redirect(url_for('add'))
        ok,out = create_client(name)
        if not ok:
            flash('Error creating: '+out)
            return redirect(url_for('add'))
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO clients(name,created_at) VALUES (?,?)',(name,time.ctime()))
        conn.commit(); conn.close()
        flash('Client created: '+name)
        return redirect(url_for('index'))
    return render_template_string("""
    <h3>Add client</h3>
    <form method="post">
      Name: <input name="name" /><br/>
      <button type="submit">Create</button>
    </form>
    """)

@app.route('/download/<name>')
@auth.login_required
def download(name):
    fn = make_ovpn(name)
    return send_file(fn, as_attachment=True, download_name=f"{name}.ovpn")

@app.route('/revoke/<name>')
@auth.login_required
def revoke(name):
    ok,out = revoke_client(name)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM clients WHERE name=?',(name,))
    conn.commit(); conn.close()
    flash('Revoked '+name + ('' if ok else ' (error:'+out+')'))
    return redirect(url_for('index'))

@app.route('/connected')
@auth.login_required
def connected():
    clients=[]
    try:
        with open(STATUS_LOG) as f:
            for line in f:
                if line.startswith('#') or line.strip()=='':
                    continue
                parts=line.split(',')
                if len(parts)>=6:
                    clients.append({'name':parts[0],'remote':parts[1],'virtual':parts[2],'since':parts[5]})
    except Exception as e:
        return f"Error reading status: {e}"
    out = "<h3>Connected clients</h3><ul>"
    for c in clients:
        out += f"<li>{c['name']} | {c['remote']} | {c['virtual']} | since {c['since']} - <a href='/disconnect/{c['name']}'>Disconnect</a></li>"
    out += "</ul><p><a href='/'>Back</a></p>"
    return out

@app.route('/disconnect/<name>')
@auth.login_required
def disconnect(name):
    # use management interface 'kill <common_name>'
    res = mgmt_command(f"kill {name}")
    flash(f"Disconnect command issued for {name}: {res[:200]}")
    return redirect(url_for('index'))

@app.route('/logs')
@auth.login_required
def logs():
    try:
        with open(OPENVPN_LOG) as f:
            text = '<pre>' + ''.join(f.readlines()[-500:]) + '</pre>'
    except Exception as e:
        text = f'Error reading log: {e}'
    return text

@app.route('/settings', methods=['GET','POST'])
@auth.login_required
def settings():
    # show form to update ADMIN_USER / ADMIN_PASS
    current = load_env()
    cur_user = current.get('ADMIN_USER','admin')
    if request.method=='POST':
        new_user = request.form.get('admin_user','').strip()
        new_pass = request.form.get('admin_pass','').strip()
        # validation: require username non-empty, password exactly 5 chars (per your request)
        if not new_user:
            flash('Username required'); return redirect(url_for('settings'))
        if len(new_pass) != 5:
            flash('Password must be exactly 5 characters (e.g. GK234)'); return redirect(url_for('settings'))
        # persist
        write_env({'ADMIN_USER': new_user, 'ADMIN_PASS': new_pass})
        flash('Admin credentials updated. Use the new credentials to login next time.')
        return redirect(url_for('index'))
    return render_template_string("""
    <h3>Settings</h3>
    <form method="post">
      Admin username: <input name="admin_user" value="{{cur_user}}" /><br/>
      Admin password (exactly 5 chars): <input name="admin_pass" value="" /><br/>
      <button type="submit">Save</button>
    </form>
    <p><a href="/">Back</a></p>
    """, cur_user=cur_user)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(load_env().get('FLASK_PORT',8080)))
PY

# systemd service for admin app
cat > "${ADMIN_DIR}/openvpn-admin.service" <<EOF
[Unit]
Description=OpenVPN Admin Flask App
After=network.target

[Service]
Type=simple
WorkingDirectory=${ADMIN_DIR}
ExecStart=${ADMIN_DIR}/venv/bin/python3 ${ADMIN_DIR}/app.py
Restart=on-failure
Environment=FLASK_ENV=production
User=root

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "${ADMIN_DIR}/openvpn-admin.service"
systemctl daemon-reload
systemctl enable openvpn-admin.service
systemctl restart openvpn-admin.service || systemctl start openvpn-admin.service

# Ensure status log exists
touch "${STATUS_LOG}"
chown nobody:nogroup "${STATUS_LOG}" || true

echo "Installation complete."
echo "Admin panel: http://${SERVER_IP}:${FLASK_PORT}  (user: ${ADMIN_USER}, password: ${ADMIN_PASS})"
echo "IMPORTANT: The admin password is shown above once. You can change it later at Settings -> Admin password (must be exactly 5 chars)."
