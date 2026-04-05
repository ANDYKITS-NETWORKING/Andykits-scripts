from scapy.all import sniff, get_if_list, get_if_addr
from collections import defaultdict
import time
from plyer import notification
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ----------------------------
# SETTINGS
# ----------------------------
TIME_WINDOW = 1        # seconds to measure packet rate
THRESHOLD = 5         # packets/sec to trigger alert
ALERT_COOLDOWN = 60    # seconds between alerts for email

ADMIN_EMAIL = "musyimiandrew090@gmail.com"           # recipient email
SMTP_USER = "musyimiandrew090@gmail.com"   # your Gmail
SMTP_PASS = "kuszxaayhsrhspaq"             # Gmail App Password
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

packet_rate = []
last_alert_time = 0
mac_count = defaultdict(int)

# ----------------------------
# AUTO-DETECT ACTIVE INTERFACE
# ----------------------------
def get_active_interface():
    interfaces = get_if_list()
    for iface in interfaces:
        try:
            ip = get_if_addr(iface)
            if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                return iface
        except Exception:
            continue
    return interfaces[0]

# ----------------------------
# ALERT FUNCTIONS
# ----------------------------
def send_desktop_alert(msg):
    notification.notify(
        title="🚨 Network Storm / Loop Detected",
        message=msg,
        timeout=5
    )

def send_email_alert(msg):
    try:
        # Create HTML email with header, footer, and logo
        email_msg = MIMEMultipart()
        email_msg['From'] = SMTP_USER
        email_msg['To'] = ADMIN_EMAIL
        email_msg['Subject'] = "🚨 ANDYKITS NET SOLUTIONS - Network Loop Detected!"

        # HTML content
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background-color: #fff; border-radius: 10px; overflow: hidden; border: 1px solid #ccc;">
                
                <!-- Header -->
                <div style="background-color: #004aad; color: #fff; padding: 20px; text-align: center;">
                    <img src="https://www.freepik.com/premium-photo/computer-information-technology-networks-telecommunication-ethernet-cables-intricately-connected-internet-switch-symbolizing-backbone-modern-digital-connectivity_246528630.htm#fromView=keyword&page=1&position=23&uuid=a919e9ce-486d-409c-a000-1be70daedad1&query=Network+solution" alt="ANDYKITS NET SOLUTIONS" style="width: 120px; height: auto;">
                    <h2>ANDYKITS NET SOLUTIONS</h2>
                </div>
                
                <!-- Body -->
                <div style="padding: 20px; color: #333;">
                    <h3 style="color: #004aad;">Network Loop / Packet Storm Alert</h3>
                    <p>{msg}</p>
                    <p><b>Time:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><b>Interface:</b> {get_active_interface()}</p>
                </div>
                
                <!-- Footer -->
                <div style="background-color: #f1f1f1; padding: 10px; text-align: center; font-size: 12px; color: #666;">
                    &copy; {time.strftime('%Y')} ANDYKITS NET SOLUTIONS | All rights reserved
                </div>
            </div>
        </body>
        </html>
        """

        email_msg.attach(MIMEText(html, 'html'))

        # Send via SMTP
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(email_msg)

        print(f"✅ Email sent to {ADMIN_EMAIL}")
    except Exception as e:
        print("❌ Failed to send email:", e)

# ----------------------------
# LOOP DETECTION LOGIC
# ----------------------------
def detect_loop(pkt):
    global last_alert_time

    now = time.time()
    packet_rate.append(now)
    packet_rate[:] = [t for t in packet_rate if now - t <= TIME_WINDOW]
    count = len(packet_rate)

    if pkt.haslayer("Ether"):
        mac_count[pkt.src] += 1

    print(f"Packets/sec: {count}", end="\r")

    if count >= THRESHOLD:
        if now - last_alert_time > ALERT_COOLDOWN:
            top_mac = max(mac_count, key=mac_count.get)
            top_count = mac_count[top_mac]

            msg = f"Packet storm detected!\nRate: {count} packets/sec\nTop sender: {top_mac} ({top_count} packets)"
            print("\n🚨 ALERT:", msg)

            # Send notifications
            send_desktop_alert(msg)
            send_email_alert(msg)

            last_alert_time = now
            mac_count.clear()

# ----------------------------
# MAIN
# ----------------------------
if __name__ == "__main__":
    iface = get_active_interface()
    print("Monitoring network traffic rate...")
    print(f"Using interface: {iface}\n")

    sniff(iface=iface, prn=detect_loop, store=0, promisc=True)

    