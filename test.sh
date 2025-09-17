#!/bin/bash
set -euo pipefail

# OpenVPN One-Click Installer + Admin Panel
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo)"
  exit 1
fi

# Default admin login
ADMIN_USER="openvpn"
ADMIN_PASS="$(tr -dc 'A-Z0-9' </dev/urandom | fold -w5 | head -n1)"

# Vars
OVPN_PORT=1194
PROTO=udp
SERVER_IP="$(curl -s ifconfig.me)"
VPN_NET="10.8.0.0"
VPN_NET_MASK="255.255.255.0"
OPENVPN_DIR="/etc/openvpn"
PKI_DIR="/etc/openvpn/easy-rsa"
ADMIN_DIR="/etc/openvpn-admin"
STATUS_LOG="/var/log/openvpn-status.log"
OPENVPN_LOG="/var/log/openvpn.log"
FLASK_PORT=8080

echo "[1/6] Installing dependencies..."
apt update -y
DEBIAN_FRONTEND=noninteractive apt install -y openvpn easy-rsa python3 python3-venv python3-pip nginx iptables-persistent curl

echo "[2/6] Setting up PKI..."
mkdir -p "$PKI_DIR"
if [ -d /usr/share/easy-rsa ]; then
  cp -r /usr/share/easy-rsa/* "$PKI_DIR/"
elif [ -d /usr/share/easy-rsa-3 ]; then
  cp -r /usr/share/easy-rsa-3/* "$PKI_DIR/"
fi
cd "$PKI_DIR"

if [ ! -d "$PKI_DIR/pki" ]; then
  ./easyrsa init-pki
  echo "set_var EASYRSA_REQ_CN \"OpenVPN-CA-$(date +%s)\"" > vars
  ./easyrsa --batch build-ca nopass
  ./easyrsa gen-req server nopass
  ./easyrsa sign-req server server <<EOF
yes
EOF
  ./easyrsa gen-dh
  openvpn --genkey --secret "$OPENVPN_DIR/ta.key"
  cp pki/ca.crt "$OPENVPN_DIR/"
  cp pki/issued/server.crt "$OPENVPN_DIR/"
  cp pki/private/server.key "$OPENVPN_DIR/"
  cp pki/dh.pem "$OPENVPN_DIR/dh.pem"
fi

echo "[3/6] Configuring OpenVPN..."
cat > "$OPENVPN_DIR/server.conf" <<EOF
port ${OVPN_PORT}
proto ${PROTO}
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
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
user nobody
group nogroup
persist-key
persist-tun
EOF

sysctl -w net.ipv4.ip_forward=1
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# NAT
IFACE=$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')
iptables -t nat -C POSTROUTING -s ${VPN_NET}/24 -o "$IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s ${VPN_NET}/24 -o "$IFACE" -j MASQUERADE
netfilter-persistent save

systemctl enable openvpn@server
systemctl restart openvpn@server

echo "[4/6] Installing Admin Panel..."
mkdir -p "$ADMIN_DIR"
cd "$ADMIN_DIR"
python3 -m venv venv
. venv/bin/activate
pip install flask flask-httpauth pyyaml

cat > .env <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PASS=${ADMIN_PASS}
FLASK_PORT=${FLASK_PORT}
OPENVPN_DIR=${OPENVPN_DIR}
PKI_DIR=${PKI_DIR}
STATUS_LOG=${STATUS_LOG}
OPENVPN_LOG=${OPENVPN_LOG}
SERVER_IP=${SERVER_IP}
EOF

cat > app.py <<'PY'
from flask import Flask, request, redirect, url_for, send_file, render_template_string, flash
from flask_httpauth import HTTPBasicAuth
import os, subprocess, sqlite3, time, socket

ENVFILE='/etc/openvpn-admin/.env'
def load_env():
    env={}
    with open(ENVFILE) as f:
        for l in f:
            if '=' in l: k,v=l.strip().split('=',1); env[k]=v
    return env

env=load_env()
OPENVPN_DIR=env['OPENVPN_DIR']; PKI_DIR=env['PKI_DIR']
STATUS_LOG=env['STATUS_LOG']; OPENVPN_LOG=env['OPENVPN_LOG']
SERVER_IP=env['SERVER_IP']; DB_PATH='/etc/openvpn-admin/users.db'

app=Flask(__name__); app.secret_key=os.urandom(24); auth=HTTPBasicAuth()
@auth.verify_password
def verify(u,p): e=load_env(); return u==e['ADMIN_USER'] and p==e['ADMIN_PASS']

def init_db():
  conn=sqlite3.connect(DB_PATH); c=conn.cursor()
  c.execute('CREATE TABLE IF NOT EXISTS clients(name TEXT PRIMARY KEY, created_at TEXT)')
  conn.commit(); conn.close()
init_db()

def create_client(name):
  subprocess.run([f"{PKI_DIR}/easyrsa","build-client-full",name,"nopass"],cwd=PKI_DIR)
def revoke_client(name):
  subprocess.run([f"{PKI_DIR}/easyrsa","revoke",name],cwd=PKI_DIR,input="yes\n",text=True)
  subprocess.run([f"{PKI_DIR}/easyrsa","gen-crl"],cwd=PKI_DIR)
  subprocess.run(["cp",f"{PKI_DIR}/pki/crl.pem",f"{OPENVPN_DIR}/crl.pem"])
def make_ovpn(name):
  ca=open(f"{PKI_DIR}/pki/ca.crt").read()
  cert=open(f"{PKI_DIR}/pki/issued/{name}.crt").read()
  key=open(f"{PKI_DIR}/pki/private/{name}.key").read()
  ta=open(f"{OPENVPN_DIR}/ta.key").read()
  return f"""client
dev tun
proto udp
remote {SERVER_IP} 1194
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
<ca>\n{ca}\n</ca>
<cert>\n{cert}\n</cert>
<key>\n{key}\n</key>
<tls-auth>\n{ta}\n</tls-auth>
key-direction 1
"""

@app.route('/')
@auth.login_required
def index():
  clients=[r for r in sqlite3.connect(DB_PATH).execute("SELECT name,created_at FROM clients")]
  connected=[]
  try:
    with open(STATUS_LOG) as f:
      for l in f:
        if l and not l.startswith('#') and ',' in l:
          p=l.split(','); connected.append((p[0],p[1],p[2],p[5]))
  except: pass
  return render_template_string("""
  <h2>OpenVPN Admin</h2>
  <a href='/add'>Add</a> | <a href='/logs'>Logs</a> | <a href='/settings'>Settings</a>
  <h3>Clients</h3><ul>{% for n,t in clients %}<li>{{n}} - {{t}} - <a href='/download/{{n}}'>.ovpn</a> - <a href='/revoke/{{n}}'>Revoke</a></li>{% endfor %}</ul>
  <h3>Connected</h3><ul>{% for n,r,v,s in connected %}<li>{{n}} | {{r}} | {{v}} | since {{s}}</li>{% endfor %}</ul>
  """,clients=clients,connected=connected)

@app.route('/add',methods=['GET','POST'])
@auth.login_required
def add():
  if request.method=='POST':
    n=request.form['name']
    create_client(n)
    sqlite3.connect(DB_PATH).execute("INSERT OR REPLACE INTO clients VALUES(?,?)",(n,time.ctime()))
    sqlite3.connect(DB_PATH).commit()
    return redirect('/')
  return "<form method=post>Name:<input name=name><button>Add</button></form>"

@app.route('/download/<n>')
@auth.login_required
def download(n):
  fn=f"/tmp/{n}.ovpn"
  open(fn,'w').write(make_ovpn(n))
  return send_file(fn,as_attachment=True,download_name=f"{n}.ovpn")

@app.route('/revoke/<n>')
@auth.login_required
def revoke(n):
  revoke_client(n)
  sqlite3.connect(DB_PATH).execute("DELETE FROM clients WHERE name=?",(n,))
  sqlite3.connect(DB_PATH).commit()
  return redirect('/')

@app.route('/logs')
@auth.login_required
def logs(): return "<pre>"+''.join(open(OPENVPN_LOG).read().splitlines()[-200:])+"</pre>"

@app.route('/settings',methods=['GET','POST'])
@auth.login_required
def settings():
  e=load_env()
  if request.method=='POST':
    u=request.form['u']; p=request.form['p']
    if len(p)!=5: return "Password must be 5 chars"
    with open(ENVFILE,'w') as f:
      f.write(f"ADMIN_USER={u}\nADMIN_PASS={p}\n")
    return "Updated, re-login"
  return f"<form method=post>User:<input name=u value='{e['ADMIN_USER']}'><br>Pass(5 chars):<input name=p><button>Save</button></form>"
PY

cat > /etc/systemd/system/openvpn-admin.service <<EOF
[Unit]
Description=OpenVPN Admin Panel
After=network.target

[Service]
WorkingDirectory=${ADMIN_DIR}
ExecStart=${ADMIN_DIR}/venv/bin/python3 ${ADMIN_DIR}/app.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable openvpn-admin
systemctl restart openvpn-admin

echo "----------------------------------------"
echo "INSTALLATION COMPLETE!"
echo "OpenVPN is running on ${PROTO}/${OVPN_PORT}"
echo "Admin panel: http://${SERVER_IP}:${FLASK_PORT}"
echo "Login: ${ADMIN_USER} / ${ADMIN_PASS}"
echo "----------------------------------------"
