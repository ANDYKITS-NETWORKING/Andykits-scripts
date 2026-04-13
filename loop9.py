# ==============================
# FINAL CLEAN SOC IDS (STABLE)
# ==============================

import os
os.environ["FLASK_SOCKETIO_ASYNC_MODE"] = "threading"

from scapy.all import sniff, ARP, Ether, DHCP, srp, get_if_list, get_if_addr
from flask import Flask, render_template_string
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from collections import defaultdict, deque
from mac_vendor_lookup import MacLookup
import threading, time, subprocess, socket, re, smtplib, requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ==============================
# CONFIG
# ==============================
BLOCK_THRESHOLD = 8
ALERT_COOLDOWN = 20

SMTP_USER = "musyimiandrew090@gmail.com"
SMTP_PASS = "kuszxaayhsrhspaq"
ADMIN_EMAIL = "musyimiandrew090@gmail.com"

# ==============================
# FLASK + DB
# ==============================
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///soc.db'
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ==============================
# DATABASE
# ==============================
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    mac = db.Column(db.String(50), unique=True)
    vendor = db.Column(db.String(100))
    location = db.Column(db.String(100))  # ✅ FIXED
    last_seen = db.Column(db.Float)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50))
    message = db.Column(db.String(200))
    timestamp = db.Column(db.Float)

# ==============================
# STATE
# ==============================
mac_activity = defaultdict(lambda: deque(maxlen=20))
ip_mac_map = {}
dhcp_sources = set()
alert_cache = {}
threat_score = defaultdict(int)
blocked_ips = set()

legit_gateway_ip = None
legit_gateway_mac = None

# ==============================
# VENDOR
# ==============================
mac_vendor = MacLookup()
try:
    mac_vendor.update_vendors()
except:
    pass

def vendor(mac):
    try:
        return mac_vendor.lookup(mac)
    except:
        return "Unknown"

# ==============================
# HELPERS
# ==============================
def clean(mac):
    return mac.lower().replace("-", ":")

def iface():
    for i in get_if_list():
        try:
            ip = get_if_addr(i)
            if ip.startswith(("192.", "10.", "172.")):
                return i
        except:
            pass
    return get_if_list()[0]

# ==============================
# GEO IP
# ==============================
def geo_lookup(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        return f"{r.get('country')} - {r.get('city')}"
    except:
        return "Unknown"

# ==============================
# GATEWAY
# ==============================
def get_gateway_ip():
    try:
        result = subprocess.run("ipconfig", capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "Default Gateway" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    return parts[1].strip()
    except:
        pass
    return "0.0.0.0"

def detect_gateway():
    global legit_gateway_ip, legit_gateway_mac
    legit_gateway_ip = get_gateway_ip()

    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=legit_gateway_ip),
            timeout=2,
            iface=iface(),
            verbose=0
        )
        if ans:
            legit_gateway_mac = clean(ans[0][1].hwsrc)
    except:
        pass

# ==============================
# EMAIL
# ==============================
def send_email(subject, body):
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = ADMIN_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP("smtp.gmail.com", 587) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception as e:
        print("Email error:", e)

# ==============================
# ALERT SYSTEM
# ==============================
def alert(key, alert_type, message):
    now = time.time()

    if key in alert_cache and now - alert_cache[key] < ALERT_COOLDOWN:
        return

    alert_cache[key] = now

    try:
        with app.app_context():
            db.session.add(Alert(type=alert_type, message=message, timestamp=now))
            db.session.commit()
    except Exception as e:
        print("DB alert error:", e)

    send_email(alert_type, message)

# ==============================
# BLOCK
# ==============================
def block_ip(ip):
    if ip in blocked_ips:
        return
    blocked_ips.add(ip)
    os.system(f"netsh advfirewall firewall add rule name=block_{ip} dir=in action=block remoteip={ip}")

# ==============================
# DETECTION
# ==============================
def detect_anomalies(mac, ip):
    mac_activity[mac].append(time.time())

    if len(mac_activity[mac]) > 15:
        alert("loop-"+mac, "LOOP DETECTED", mac)

    if mac in ip_mac_map and ip_mac_map[mac] != ip:
        alert("flip-"+mac, "IP FLAPPING", f"{ip_mac_map[mac]} -> {ip}")

    ip_mac_map[mac] = ip

# ==============================
# PACKET PROCESSING
# ==============================
def process(pkt):
    if not pkt.haslayer(Ether):
        return

    mac = clean(pkt[Ether].src)
    ip = pkt[ARP].psrc if pkt.haslayer(ARP) else None

    if not ip:
        return

    detect_anomalies(mac, ip)

    if mac == legit_gateway_mac and ip != legit_gateway_ip:
        alert("gw", "GATEWAY SPOOF", mac)

    if pkt.haslayer(DHCP):
        dhcp_sources.add(mac)
        if len(dhcp_sources) > 1:
            alert("dhcp", "ROGUE DHCP", str(dhcp_sources))

    try:
        with app.app_context():
            dev = Device.query.filter_by(mac=mac).first()

            if not dev:
                dev = Device(
                    ip=ip,
                    mac=mac,
                    vendor=vendor(mac),
                    location=geo_lookup(ip),
                    last_seen=time.time()
                )
                db.session.add(dev)
            else:
                dev.ip = ip
                dev.last_seen = time.time()

            db.session.commit()
    except Exception as e:
        print("DB error:", e)

    threat_score[ip] += 1
    if threat_score[ip] > BLOCK_THRESHOLD:
        alert("attack", "HIGH TRAFFIC", ip)
        block_ip(ip)

# ==============================
# THREADS
# ==============================
def sniffer():
    sniff(iface=iface(), prn=process, store=0)

def push():
    while True:
        try:
            with app.app_context():
                devices = Device.query.all()
                alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()

                socketio.emit("update", {
                    "devices": [f"{d.ip} | {d.mac} | {d.vendor} | {d.location}" for d in devices],
                    "alerts": [f"{a.type}: {a.message}" for a in alerts]
                })
        except Exception as e:
            print("Push error:", e)

        time.sleep(2)

# ==============================
# UI
# ==============================
HTML = """
<html>
<head>
<script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
</head>
<body style="background:#0f172a;color:white;font-family:Arial">
<h2>FINAL SOC DASHBOARD</h2>

<h3>Devices</h3>
<ul id="devices"></ul>

<h3>Alerts</h3>
<ul id="alerts"></ul>

<script>
var socket = io();

socket.on("update", function(data){
    let d = "";
    data.devices.forEach(x => d += `<li>${x}</li>`);
    document.getElementById("devices").innerHTML = d;

    let a = "";
    data.alerts.forEach(x => a += `<li>${x}</li>`);
    document.getElementById("alerts").innerHTML = a;
});
</script>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML)

# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    print("[SOC STARTING]")

    with app.app_context():
        db.create_all()

    detect_gateway()

    threading.Thread(target=sniffer, daemon=True).start()
    threading.Thread(target=push, daemon=True).start()

    socketio.run(app, host="0.0.0.0", port=5000)