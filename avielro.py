# ==============================
# NETWORK ASSET DISCOVERY ENGINE (CLEAN v3 + SNMP) - FIXED VERSION
# ==============================

import subprocess
import socket
import ipaddress
import sqlite3
import logging
import threading
import os
import sys
import time
import platform
import urllib.request
import hashlib
import json
from collections import defaultdict
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt, RadioTap
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional (DHCP sniffing)
from scapy.all import sniff, DHCP, ARP, Ether
import datetime

# SNMP
from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd
)

# ==============================
# CONFIGURATION
# ==============================
NETWORKS = [
    "192.168.100.0/24",
    "192.168.200.0/24"
]

DB_NAME = "network_assets.db"
SNMP_COMMUNITY = os.environ.get("SNMP_COMMUNITY", "public")  # Changed from hardcoded
MAX_WORKERS = 50  # For parallel scanning
PING_TIMEOUT = 1  # seconds
ARP_WAIT = 0.5  # seconds after ping before ARP lookup

# ==============================
# LOGGING
# ==============================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ==============================
# DATABASE SETUP WITH THREAD SAFETY
# ==============================
class DatabaseManager:
    def __init__(self, db_name):
        self.db_name = db_name
        self.local = threading.local()
        self.lock = threading.Lock()
        self._init_db()
    
    def _get_connection(self):
        if not hasattr(self.local, 'connection'):
            self.local.connection = sqlite3.connect(self.db_name)
            self.local.connection.row_factory = sqlite3.Row
        return self.local.connection
    
    def _init_db(self):
        with self.lock:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    vendor TEXT,
                    hostname TEXT,
                    device_type TEXT,
                    location TEXT,
                    last_seen TEXT
                )
            """)
            conn.commit()
            conn.close()
    
    def execute_query(self, query, params=None, fetch_one=False, fetch_all=False):
        with self.lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            try:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if fetch_one:
                    result = cursor.fetchone()
                elif fetch_all:
                    result = cursor.fetchall()
                else:
                    result = None
                
                conn.commit()
                return result
            except Exception as e:
                logger.error(f"Database error: {e}")
                conn.rollback()
                raise
    
    def close(self):
        if hasattr(self.local, 'connection'):
            self.local.connection.close()

db = DatabaseManager(DB_NAME)

# ==============================
# MAC NORMALIZATION (IMPROVED)
# ==============================
def normalize_mac(mac):
    """Normalize MAC address to standard format XX-XX-XX-XX-XX-XX"""
    if not mac:
        return None
    
    # Remove common separators and convert to uppercase
    mac = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    
    # Validate MAC length
    if len(mac) != 12:
        return None
    
    # Format with hyphens every 2 characters
    return '-'.join(mac[i:i+2] for i in range(0, 12, 2))

def validate_mac(mac):
    """Validate MAC address format"""
    if not mac:
        return False
    normalized = normalize_mac(mac)
    return normalized is not None and len(normalized) == 17

# ==============================
# DOWNLOAD OUI DATABASE ONLINE

def download_oui_database():
    """Download latest OUI database from IEEE"""
    oui_url = "https://standards-oui.ieee.org/oui/oui.txt"
    oui_file = "oui.txt"
    
    if os.path.exists(oui_file):
        # Check if file is older than 30 days
        file_age = time.time() - os.path.getmtime(oui_file)
        if file_age < 30 * 24 * 3600:
            logger.info(f"Using existing OUI database ({oui_file})")
            return True
    
    try:
        logger.info(f"Downloading OUI database from {oui_url}...")
        urllib.request.urlretrieve(oui_url, oui_file)
        logger.info(f"OUI database downloaded successfully")
        return True
    except Exception as e:
        logger.warning(f"Could not download OUI database: {e}")
        return False
    
# ==============================
# ==============================
# LOAD OUI DATABASE
# ==============================
def load_oui_db(file_path="oui.txt"):
    oui_dict = {}
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) == 2:
                        oui = parts[0].strip().upper()
                        vendor = parts[1].strip()

                        # Normalize OUI to match your MAC format (XX-XX-XX)
                        oui = oui.replace(":", "-")

                        oui_dict[oui] = vendor

        logger.info(f"Loaded {len(oui_dict)} OUI entries")

    except FileNotFoundError:
        logger.warning(f"OUI file not found: {file_path}")
    except Exception as e:
        logger.error(f"OUI load error: {e}")

    return oui_dict

# Load OUI database at module level (GLOBAL)
if not os.path.exists("oui.txt"):
    download_oui_database()
OUI_DATABASE = load_oui_db()  # Add this line

def get_vendor(mac):
    mac = normalize_mac(mac)
    if not mac:
        return "UNKNOWN"
    return OUI_DATABASE.get(mac[:8], "UNKNOWN")  # Use the global variable

# ==============================
# SNMP FUNCTION (IMPROVED)
# ==============================
def snmp_get_multi(ip, community="NMS-RO123!"):
    oids = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "uptime": "1.3.6.1.2.1.1.3.0",
    }

    results = {}

    for key, oid in oids.items():
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, 161), timeout=3, retries=2),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )

            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

            if not errorIndication and not errorStatus:
                results[key] = str(varBinds[0][1])
        except:
            pass

    return results

# ==============================
# ROUTER VENDOR VIA SNMP
# ==============================
def try_snmp(ip):
    return snmp_get_multi(ip)

def detect_router_vendor(ip):
    info = try_snmp(ip)  # Single call only
    if not info:
        return None
    descr = info.get("sysDescr", "").lower()
    if "huawei" in descr:
        return "Huawei Router"
    if "cisco" in descr:
        return "Cisco Device"
    if "mikrotik" in descr:
        return "MikroTik Router"
    if "juniper" in descr:
        return "Juniper Device"
    if "arista" in descr:
        return "Arista Switch"
    return "Network Device"

# ==============================
# ==============================
# SMART VENDOR DETECTION
# ==============================
def detect_device_intelligence(mac, hostname, ip):
    snmp_data = snmp_get_multi(ip)

    if snmp_data:
        info = snmp_data.get("sysDescr", "").lower()  # info is now a string
        
        # Check for known vendors in SNMP description
        if "huawei" in info:
            return "Huawei Router"
        if "cisco" in info:
            return "Cisco Device"
        if "mikrotik" in info:
            return "MikroTik Router"
        if "juniper" in info:
            return "Juniper Device"
        if "arista" in info:
            return "Arista Switch"
        
        return "SNMP Device"

    # fallback logic
    hostname = (hostname or "").lower()

    if "infinix" in hostname or "tecno" in hostname:  # Fixed typo "infin ix"
        return "Transsion"

    if ip.endswith(".1"):
        return "Router/Gateway"

    # Get vendor from MAC OUI - this always returns a string
    vendor = get_vendor(mac)
    return vendor if vendor else "UNKNOWN"
# ==============================
# BANDWIDTH MONITORING
# ==============================
def get_interface_traffic(ip):
    oid_in = "1.3.6.1.2.1.2.2.1.10.1"
    oid_out = "1.3.6.1.2.1.2.2.1.16.1"

    return {
        "in": snmp_get_multi(ip, oid_in),
        "out": snmp_get_multi(ip, oid_out)
    }

# ==============================
# HOSTNAME PATTERNS
# ==============================
def detect_vendor_by_hostname(hostname):
    # Hostname patterns
    vendor_patterns = {
        "Transsion": ["infinix", "tecno", "itel"],
        "Apple": ["iphone", "ipad", "macbook", "apple"],
        "Samsung": ["samsung", "galaxy"],
        "Huawei": ["huawei"],
        "Xiaomi": ["xiaomi", "redmi"],
        "Oppo": ["oppo"],
        "Vivo": ["vivo"],
        "HP": ["hp", "elitebook", "probook"],
        "Dell": ["dell", "latitude", "optiplex"],
        "Lenovo": ["lenovo", "thinkpad"],
        "Google": ["android", "pixel"],
        "Microsoft": ["surface", "windows"]
    }
    
    for vendor, patterns in vendor_patterns.items():
        if any(p in hostname for p in patterns):
            return vendor
    
    return None

# ==============================
# HOSTNAME (IMPROVED)
# ==============================
def get_hostname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None
    except socket.gaierror:
        return None
    except Exception as e:
        logger.debug(f"Hostname lookup failed for {ip}: {e}")
        return None

# ==============================
# OS DETECTION (CROSS-PLATFORM)
# ==============================
def detect_os(ip):
    try:
        # Cross-platform ping command
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout = '-w' if platform.system().lower() == 'windows' else '-W'
        
        output = subprocess.check_output(
            ['ping', param, '1', timeout, '1', ip],
            stderr=subprocess.DEVNULL,
            timeout=2
        ).decode()
        
        # Look for TTL (case-insensitive for cross-platform)
        ttl_match = None
        for line in output.splitlines():
            if 'ttl=' in line.lower():
                ttl_match = line.lower().split('ttl=')[1].split()[0]
                break
        
        if ttl_match:
            ttl = int(ttl_match)
            if ttl >= 120:
                return "Windows"
            elif ttl >= 60:
                return "Linux/Android"
            elif ttl >= 50:
                return "Unix/Linux"
    
    except subprocess.TimeoutExpired:
        logger.debug(f"Ping timeout for {ip}")
    except Exception as e:
        logger.debug(f"OS detection failed for {ip}: {e}")
    
    return "Unknown"

# ==============================
# ==============================
# DEVICE TYPE
# ==============================
def classify_device(ip, hostname, vendor, os_type):
    name = (hostname or "").lower()
    vendor_lower = (vendor or "").lower()
    
    # Router/Gateway detection
    if ip.endswith(".1") or ip.endswith(".254"):
        return "Router/Gateway"
    
    # Printer detection
    if "printer" in name or "print" in name:
        return "Printer"
    
    # Mobile device detection
    mobile_keywords = ["infinix", "tecno", "android", "iphone", "galaxy", "mobile", "phone"]
    if any(x in name for x in mobile_keywords):
        return "Mobile Device"
    
    if "apple" in vendor_lower and ("iphone" in name or "ipad" in name):
        return "Mobile Device"
    
    # Computer detection
    if os_type == "Windows" or os_type == "Linux/Android":
        if "server" in name:
            return "Server"
        return "Computer"
    
    # IoT device detection
    if "iot" in name or "sensor" in name:
        return "IoT Device"
    
    # Default return - ensure we never return None
    if vendor_lower:
        return "Network Device"
    
    return "Unknown"

# ==============================
# GET DEFAULT GATEWAY
# ==============================
def get_default_gateway():
    try:
        output = subprocess.check_output("ipconfig", shell=True).decode()
        for line in output.splitlines():
            if "Default Gateway" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    gw = parts[1].strip()
                    if gw:
                        return gw
    except:
        pass
    return None

# ==============================
# CLASSIFY ROUTER ROLES
# ==============================
def classify_router_roles(devices):
    roles = {}
    default_gw = get_default_gateway()

    for d in devices:
        ip = d['ip']
        if d['device_type'] != "Router/Gateway":
            continue

        if ip == default_gw:
            roles[ip] = "UPSTREAM (INTERNET)"
        else:
            roles[ip] = "DOWNSTREAM"

    return roles

# ==============================
# MAP DEVICES TO THEIR ROUTERS
# ==============================
def map_topology(devices, gateways):
    topology = {}

    for net, gw in gateways.items():
        topology[net] = {
            "gateway": gw,
            "clients": []
        }

    for d in devices:
        ip = d['ip']
        if not ip:
            continue

        network = ".".join(ip.split(".")[:3]) + ".0/24"

        if network in topology:
            if ip != topology[network]["gateway"]["gateway_ip"]:
                topology[network]["clients"].append(d)

    return topology

# ==============================
# DETECT GATEWAYS
# ==============================
def detect_gateways(devices):
    """Identify gateway/router devices"""
    gateways = []

    for d in devices:
        ip = d['ip']
        device_type = d['device_type']

        # Heuristic: gateway IP patterns
        if device_type == "Router/Gateway" or ip.endswith(".1") or ip.endswith(".254"):
            gateways.append(d)

    return gateways

# ==============================
# DISPLAY TOPOLOGY
# ==============================
def show_topology():
    devices = db.execute_query("SELECT * FROM devices", fetch_all=True)

    gateways = detect_gateways(devices)
    roles = classify_router_roles(devices)

    print("\n" + "="*60)
    print("NETWORK TOPOLOGY MAP")
    print("="*60)

    for gw in gateways:
        ip = gw['ip']
        role = roles.get(ip, "UNKNOWN")

        print(f"\n[{role}] {ip}")

        # find devices in same subnet
        subnet = ".".join(ip.split(".")[:3])

        for d in devices:
            if d['ip'].startswith(subnet) and d['ip'] != ip:
                print(f"   └── {d['ip']} ({d['device_type']})")

# ==============================
# EVENT ENGINE
# ==============================
def detect_events(old_devices, new_devices):
    old_set = set(old_devices)
    new_set = set(new_devices)

    # New devices
    for mac in new_set - old_set:
        logging.warning(f"🚨 NEW DEVICE: {mac}")

    # Disconnected devices
    for mac in old_set - new_set:
        logging.warning(f"❌ DEVICE LOST: {mac}")

# ==============================
# LOCATION MAP
# ==============================
LOCATION_MAP = {
    "06-2B-B5-0E-3E-D6": "Basement",
    "46-F0-C0-64-39-55": "Reception",
    "40-62-EA-EB-79-67": "Ground Floor",
    "80-C1-6E-E0-AB-C9": "First Floor"
}

# ==============================
# NETWORK HELPERS (CROSS-PLATFORM)
# ==============================
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def ping(ip):
    """Cross-platform ping check"""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout = '-w' if platform.system().lower() == 'windows' else '-W'
        
        result = subprocess.run(
            ['ping', param, '1', timeout, str(PING_TIMEOUT), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=PING_TIMEOUT + 1
        )
        return result.returncode == 0
    except Exception:
        return False

def get_mac_arp_table(ip):
    """Get MAC address from ARP table (cross-platform)"""
    try:
        system = platform.system().lower()
        
        if system == 'windows':
            output = subprocess.check_output(['arp', '-a', ip], timeout=2).decode()
            for line in output.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        # Windows format: IP address ... MAC ... type
                        for part in parts:
                            if '-' in part and len(part) == 17:
                                return normalize_mac(part)
        else:  # Linux/Unix/Mac
            output = subprocess.check_output(['arp', '-n', ip], timeout=2).decode()
            for line in output.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        # Linux/Unix format: IP address HWtype MAC address
                        if ':' in parts[2] or '-' in parts[2]:
                            return normalize_mac(parts[2])
    except subprocess.TimeoutExpired:
        logger.debug(f"ARP lookup timeout for {ip}")
    except Exception as e:
        logger.debug(f"ARP lookup failed for {ip}: {e}")
    return None

def get_mac(ip):
    """Get MAC address with ARP cache population"""
    # First, try to ping to populate ARP cache
    ping(ip)
    
    # Wait a bit for ARP cache to update
    time.sleep(ARP_WAIT)
    
    # Try multiple times
    for attempt in range(3):
        mac = get_mac_arp_table(ip)
        if mac:
            return mac
        time.sleep(0.2)
    
    return None

# ==============================
# UPDATE DATABASE (THREAD-SAFE)
# ==============================
def update_device(mac, ip):
    mac = normalize_mac(mac)
    if not mac or not ip or ip == "DHCP_INVALID":
        return False
    
    now = datetime.datetime.now().isoformat()  # ← CHANGE THIS LINE
    
    try:
        hostname = get_hostname(ip)
        os_type = detect_os(ip)
        vendor = detect_device_intelligence(mac, hostname, ip)
        device_type = classify_device(ip, hostname, vendor, os_type)
        location = LOCATION_MAP.get(mac, "UNASSIGNED")
        
        existing = db.execute_query("SELECT 1 FROM devices WHERE mac=?", (mac,), fetch_one=True)
        
        if existing:
            db.execute_query("""
                UPDATE devices
                SET ip=?, vendor=?, hostname=?, device_type=?, location=?, last_seen=?
                WHERE mac=?
            """, (ip, vendor, hostname, device_type, location, now, mac))
            status = "UPDATED"
        else:
            db.execute_query("""
                INSERT INTO devices (mac, ip, vendor, hostname, device_type, location, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (mac, ip, vendor, hostname, device_type, location, now))
            status = "NEW"
        
        logger.info(f"{status}: {mac} -> {ip} | {hostname or 'No hostname'} | {vendor} | {device_type}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to update device {mac}: {e}")
        return False

# ==============================
# DHCP SNIFFER (IMPROVED)
# ==============================
def dhcp_fingerprint(pkt):
    """Extract real IP from DHCP packets"""
    if DHCP in pkt:
        try:
            mac = normalize_mac(pkt[Ether].src)
            
            # Try to get assigned IP from DHCP packet
            ip = None
            dhcp_layer = pkt[DHCP]
            
            # Check for DHCP ACK which contains the assigned IP
            if hasattr(dhcp_layer, 'options'):
                for option in dhcp_layer.options:
                    if option[0] == 'yiaddr':
                        ip = option[1]
                        break
                    elif option[0] == 'requested_addr':
                        ip = option[1]
                        break
            
            # Also check the IP layer if available
            if not ip and hasattr(pkt, 'getlayer'):
                ip_layer = pkt.getlayer('IP')
                if ip_layer:
                    ip = ip_layer.dst
            
            if mac and ip:
                update_device(mac, str(ip))
                logger.info(f"DHCP DETECTED: {mac} got IP {ip}")
            elif mac:
                logger.debug(f"DHCP packet from {mac} but no IP found")
                
        except Exception as e:
            logger.debug(f"Error processing DHCP packet: {e}")

def start_dhcp_sniffer():
    """Start DHCP sniffer with error handling"""
    try:
        logger.info("Starting DHCP sniffer (requires admin/root privileges)...")
        sniff(
            filter="udp and (port 67 or 68)", 
            prn=dhcp_fingerprint, 
            store=0,
            timeout=300  # Optional: run for 5 minutes
        )
    except PermissionError:
        logger.error("Permission denied for DHCP sniffing. Run with administrator/root privileges.")
    except Exception as e:
        logger.error(f"DHCP sniffer error: {e}")

# ==============================
# SCAN NETWORK (PARALLEL)
# ==============================
def scan_single_ip(ip):
    """Scan a single IP address"""
    ip_str = str(ip)
    if ping(ip_str):
        mac = get_mac(ip_str)
        if mac:
            update_device(mac, ip_str)
            return True
    return False

# ==============================
# MOBILE DEVICE DETECTION
# ==============================
def detect_mobile_devices():
    found_devices = []

    
    mobile_ouis = {
        # Transsion Holdings (Infinix, Tecno, Itel)
        '00-0E-9E': 'Transsion (Infinix/Tecno/Itel)',
        '00-1A-9E': 'Transsion (Infinix/Tecno/Itel)',
        '08-5A-13': 'Transsion (Infinix/Tecno/Itel)',
        '10-08-B8': 'Transsion (Infinix/Tecno/Itel)',
        '2C-33-7A': 'Transsion (Infinix/Tecno/Itel)',
        '3C-A9-F4': 'Transsion (Infinix/Tecno/Itel)',
        '40-5B-D8': 'Transsion (Infinix/Tecno/Itel)',
        '4C-5E-0C': 'Transsion (Infinix/Tecno/Itel)',
        '50-2B-73': 'Transsion (Infinix/Tecno/Itel)',
        '54-2E-15': 'Transsion (Infinix/Tecno/Itel)',
        '5C-E3-0E': 'Transsion (Infinix/Tecno/Itel)',
        '60-D8-19': 'Transsion (Infinix/Tecno/Itel)',
        '64-CC-2E': 'Transsion (Infinix/Tecno/Itel)',
        '68-3E-34': 'Transsion (Infinix/Tecno/Itel)',
        '6C-3B-6B': 'Transsion (Infinix/Tecno/Itel)',
        '70-3A-0E': 'Transsion (Infinix/Tecno/Itel)',
        '74-4D-28': 'Transsion (Infinix/Tecno/Itel)',
        '78-2B-46': 'Transsion (Infinix/Tecno/Itel)',
        '7C-2A-D1': 'Transsion (Infinix/Tecno/Itel)',
        '80-3F-5D': 'Transsion (Infinix/Tecno/Itel)',
        '84-2A-16': 'Transsion (Infinix/Tecno/Itel)',
        '88-C3-97': 'Transsion (Infinix/Tecno/Itel)',
        '8C-4B-14': 'Transsion (Infinix/Tecno/Itel)',
        '90-2B-34': 'Transsion (Infinix/Tecno/Itel)',
        '94-3C-C9': 'Transsion (Infinix/Tecno/Itel)',
        '98-6C-F5': 'Transsion (Infinix/Tecno/Itel)',
        '9C-5A-9C': 'Transsion (Infinix/Tecno/Itel)',
        'A0-3E-5A': 'Transsion (Infinix/Tecno/Itel)',
        'A4-5E-60': 'Transsion (Infinix/Tecno/Itel)',
        'A8-5B-78': 'Transsion (Infinix/Tecno/Itel)',
        'AC-84-C6': 'Transsion (Infinix/Tecno/Itel)',
        'B0-5A-DA': 'Transsion (Infinix/Tecno/Itel)',
        'B4-0C-25': 'Transsion (Infinix/Tecno/Itel)',
        'B8-9A-2F': 'Transsion (Infinix/Tecno/Itel)',
        'BC-92-6B': 'Transsion (Infinix/Tecno/Itel)',
        'C0-3E-BA': 'Transsion (Infinix/Tecno/Itel)',
        'C4-4F-33': 'Transsion (Infinix/Tecno/Itel)',
        'C8-2A-14': 'Transsion (Infinix/Tecno/Itel)',
        'CC-2E-1B': 'Transsion (Infinix/Tecno/Itel)',
        'D0-5F-B8': 'Transsion (Infinix/Tecno/Itel)',
        'D4-6A-6A': 'Transsion (Infinix/Tecno/Itel)',
        'D8-0D-17': 'Transsion (Infinix/Tecno/Itel)',
        'DC-4A-3E': 'Transsion (Infinix/Tecno/Itel)',
        'E0-5A-1B': 'Transsion (Infinix/Tecno/Itel)',
        'E4-5F-01': 'Transsion (Infinix/Tecno/Itel)',
        'E8-9F-6D': 'Transsion (Infinix/Tecno/Itel)',
        'EC-9B-5C': 'Transsion (Infinix/Tecno/Itel)',
        'F0-2F-74': 'Transsion (Infinix/Tecno/Itel)',
        'F4-6D-04': 'Transsion (Infinix/Tecno/Itel)',
        'F8-6B-8E': 'Transsion (Infinix/Tecno/Itel)',
        'FC-6E-1F': 'Transsion (Infinix/Tecno/Itel)',
        
        # Samsung
        '00-1A-2B': 'Samsung Mobile',
        '08-00-28': 'Samsung Mobile',
        '0C-96-E6': 'Samsung Mobile',
        '10-9A-DD': 'Samsung Mobile',
        '14-AB-DF': 'Samsung Mobile',
        '18-82-64': 'Samsung Mobile',
        '1C-4B-D6': 'Samsung Mobile',
        '20-6B-E7': 'Samsung Mobile',
        '24-5A-4C': 'Samsung Mobile',
        '28-8A-1C': 'Samsung Mobile',
        '2C-0E-3D': 'Samsung Mobile',
        '30-8D-99': 'Samsung Mobile',
        '34-5A-0C': 'Samsung Mobile',
        '38-2C-4A': 'Samsung Mobile',
        '3C-2A-F4': 'Samsung Mobile',
        '40-F4-EC': 'Samsung Mobile',
        '44-46-4F': 'Samsung Mobile',
        '48-0F-CF': 'Samsung Mobile',
        '4C-7B-C4': 'Samsung Mobile',
        '50-15-4A': 'Samsung Mobile',
        '54-2E-15': 'Samsung Mobile',
        '58-1F-AA': 'Samsung Mobile',
        '5C-8D-4E': 'Samsung Mobile',
        '60-3A-4C': 'Samsung Mobile',
        '64-8A-BC': 'Samsung Mobile',
        '68-6B-5A': 'Samsung Mobile',
        '6C-5B-5E': 'Samsung Mobile',
        '70-6A-B6': 'Samsung Mobile',
        '74-6D-66': 'Samsung Mobile',
        '78-6A-2B': 'Samsung Mobile',
        '7C-2D-4B': 'Samsung Mobile',
        '80-5A-04': 'Samsung Mobile',
        '84-3A-4B': 'Samsung Mobile',
        '88-2B-6F': 'Samsung Mobile',
        '8C-7B-9D': 'Samsung Mobile',
        '90-2C-6B': 'Samsung Mobile',
        '94-6E-8A': 'Samsung Mobile',
        '98-7B-5A': 'Samsung Mobile',
        '9C-9C-1D': 'Samsung Mobile',
        'A0-7E-4A': 'Samsung Mobile',
        'A4-9B-19': 'Samsung Mobile',
        'A8-5C-2C': 'Samsung Mobile',
        'AC-2B-6E': 'Samsung Mobile',
        'B0-5C-DA': 'Samsung Mobile',
        'B4-8A-7A': 'Samsung Mobile',
        'B8-8A-5A': 'Samsung Mobile',
        'BC-3A-3A': 'Samsung Mobile',
        'C0-5E-44': 'Samsung Mobile',
        'C4-4F-33': 'Samsung Mobile',
        'C8-7B-5A': 'Samsung Mobile',
        'CC-6E-5A': 'Samsung Mobile',
        'D0-5F-B8': 'Samsung Mobile',
        'D4-6A-6A': 'Samsung Mobile',
        'D8-6C-6B': 'Samsung Mobile',
        'DC-5A-5B': 'Samsung Mobile',
        'E0-5A-6A': 'Samsung Mobile',
        'E4-5F-6A': 'Samsung Mobile',
        'E8-6A-6A': 'Samsung Mobile',
        
        # Xiaomi
        '00-1A-7D': 'Xiaomi Mobile',
        '04-20-5A': 'Xiaomi Mobile',
        '08-5A-6B': 'Xiaomi Mobile',
        '0C-7A-8A': 'Xiaomi Mobile',
        '10-2A-4B': 'Xiaomi Mobile',
        '14-5A-6A': 'Xiaomi Mobile',
        '18-6A-7A': 'Xiaomi Mobile',
        '1C-7A-8A': 'Xiaomi Mobile',
        '20-8A-9A': 'Xiaomi Mobile',
        '24-9A-0A': 'Xiaomi Mobile',
        '28-AA-1A': 'Xiaomi Mobile',
        '2C-BA-2A': 'Xiaomi Mobile',
        '30-CA-3A': 'Xiaomi Mobile',
        '34-DA-4A': 'Xiaomi Mobile',
        '38-EA-5A': 'Xiaomi Mobile',
        '3C-FA-6A': 'Xiaomi Mobile',
        '40-0B-7B': 'Xiaomi Mobile',
        '44-1B-8B': 'Xiaomi Mobile',
        '48-3B-9B': 'Xiaomi Mobile',
    }
    

    
    try:
        output = subprocess.check_output(['arp', '-a'], timeout=5).decode()
        
        for line in output.splitlines():
            if '192.168' in line:
                # Extract MAC address
                parts = line.split()
                mac = None
                ip = None
                
                for part in parts:
                    if '-' in part and len(part) == 17:
                        mac = part.upper()
                    if part.count('.') == 3:
                        ip = part.strip('()')
                
                if mac and ip:
                    oui = mac[:8]
                    
                    if oui in mobile_ouis:
                        vendor = mobile_ouis[oui]
                        logger.info(f"📱 MOBILE DETECTED: {mac} -> {ip} ({vendor})")
                        update_device(mac, ip)
                        found_devices.append((mac, ip, vendor))
                    else:
                        vendor_name = get_vendor(mac)
                        if vendor_name != "UNKNOWN" and any(x in vendor_name.lower() for x in ['mobile', 'phone', 'xiaomi', 'samsung', 'apple', 'huawei', 'oneplus', 'oppo', 'vivo']):
                            logger.info(f"📱 Possible mobile: {mac} -> {ip} ({vendor_name})")
                            update_device(mac, ip)
                            found_devices.append((mac, ip, vendor_name))
        
        # MOVE THIS OUTSIDE the for loop
        if found_devices:
            logger.info(f"Found {len(found_devices)} mobile devices")
        else:
            logger.info("No mobile devices found in ARP cache")
        
        return found_devices
        
    except Exception as e:
        logger.error(f"Mobile device detection failed: {e}")
        return []
    


def refresh_arp_cache():
    """Refresh ARP cache to find all devices including mobiles"""
    logger.info("Refreshing ARP cache...")
    
    # Ping broadcast addresses to populate ARP cache
    broadcast_ips = ['192.168.100.255', '192.168.200.255']
    
    for bcast in broadcast_ips:
        try:
            subprocess.run(
                ['ping', '-n', '2', '-w', '100', bcast],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            time.sleep(0.5)
        except:
            pass
    
    # Also ping common IP ranges where phones often are
    logger.info("Pinging common IP ranges for mobile devices...")
    for i in range(100, 150):  # Phones often get IPs in 100-150 range
        ip1 = f"192.168.100.{i}"
        ip2 = f"192.168.200.{i}"
        
        for ip in [ip1, ip2]:
            subprocess.run(
                ['ping', '-n', '1', '-w', '50', ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
    
    # Now detect mobile devices
    logger.info("Checking ARP cache for mobile devices...")
    mobile_devices = detect_mobile_devices()
    
    if mobile_devices:
        print(f"\n{'='*60}")
        print(f"📱 FOUND {len(mobile_devices)} MOBILE DEVICE(S)!")
        print(f"{'='*60}")
        for mac, ip, vendor in mobile_devices:
            print(f"  {vendor}: {ip} ({mac})")
    else:
        print(f"\n{'='*60}")
        print(f"📱 No mobile devices found.")
        print(f"Make sure your phone:")
        print(f"  1. Has WiFi turned ON")
        print(f"  2. Screen is unlocked")
        print(f"  3. Is connected to the same network")
        print(f"{'='*60}")
    
    return mobile_devices


def scan_network():
    logger.info(f"Starting network scan of {NETWORKS}...")
    
    total_scanned = 0
    total_found = 0

    for net in NETWORKS:
        try:
            network = ipaddress.IPv4Network(net, strict=False)
            logger.info(f"Scanning network: {net}")

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(scan_single_ip, ip): ip for ip in network.hosts()}

                scanned = 0
                found = 0

                for future in as_completed(futures):
                    scanned += 1
                    total_scanned += 1

                    if future.result():
                        found += 1
                        total_found += 1

                    if scanned % 50 == 0:
                        logger.info(f"{net} progress: {scanned}/{network.num_addresses} IPs, {found} devices found")

        except Exception as e:
            logger.error(f"Failed scanning {net}: {e}")

    logger.info(f"TOTAL: {total_scanned} IPs scanned, {total_found} devices found")

# ==============================
# ==============================
# SHOW DATABASE
# ==============================
def show_devices():
    """Display all devices in database"""
    print("\n" + "="*80)
    print("DEVICE DATABASE".center(80))
    print("="*80)
    
    devices = db.execute_query(
        "SELECT * FROM devices ORDER BY last_seen DESC", 
        fetch_all=True
    )
    
    if not devices:
        print("No devices found in database.")
        return
    
    print(f"\n{'MAC Address':<20} {'IP':<15} {'Vendor':<20} {'Type':<15} {'Location':<15}")
    print("-"*80)
    
    for device in devices:
        # Convert None to appropriate string values
        mac = device['mac'] or 'N/A'
        ip = device['ip'] or 'N/A'
        vendor = device['vendor'] or 'UNKNOWN'
        device_type = device['device_type'] or 'UNKNOWN'
        location = device['location'] or 'UNASSIGNED'
        
        print(f"{mac:<20} {ip:<15} {vendor:<20} {device_type:<15} {location:<15}")
    
    print(f"\nTotal devices: {len(devices)}")
    print("="*80)

def show_statistics():
    """Show device statistics"""
    device_types = db.execute_query(
        "SELECT device_type, COUNT(*) FROM devices GROUP BY device_type",
        fetch_all=True
    )
    
    locations = db.execute_query(
        "SELECT location, COUNT(*) FROM devices GROUP BY location",
        fetch_all=True
    )
    
    print("\n" + "="*80)
    print("DEVICE STATISTICS".center(80))
    print("="*80)
    
    print("\nDevice Types:")
    if device_types:
        for d_type, count in device_types:
            type_name = d_type if d_type else "UNKNOWN"
            print(f"  {type_name:<20}: {count}")
    else:
        print("  No device types found")
    
    print("\nLocations:")
    if locations:
        for location, count in locations:
            loc_name = location if location else "UNASSIGNED"
            print(f"  {loc_name:<20}: {count}")
    else:
        print("  No locations found")
    
    print("="*80)


# ==============================
# ARP SCAN (ALTERNATIVE METHOD)
# ==============================
def arp_scan():
    """Use ARP requests to discover devices (more reliable on some networks)"""
    try:
        from scapy.all import ARP, Ether, srp
        
        logger.info("Performing ARP scan...")
        
        total_devices = 0

        for net in NETWORKS:
            logger.info(f"Scanning ARP on network: {net}")
            
            arp = ARP(pdst=net)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            result = srp(packet, timeout=3, verbose=0)[0]

            devices_found = 0

            for sent, received in result:
                mac = normalize_mac(received.hwsrc)
                ip = received.psrc

                if mac and ip:
                    update_device(mac, ip)
                    devices_found += 1
                    total_devices += 1

            logger.info(f"{net} ARP scan: {devices_found} devices found")

        logger.info(f"ARP scan complete: {total_devices} total devices found")
        return total_devices

    except ImportError:
        logger.warning("Scapy not fully available for ARP scan")
        return 0

    except Exception as e:
        logger.error(f"ARP scan failed: {e}")
        return 0

# ==============================
# CONTINUOUS LOOP MONITOR
# ==============================
def soc_loop():
    previous_devices = set()

    while True:
        current_devices = set()

        for net in NETWORKS:
            network = ipaddress.IPv4Network(net)
            for ip in network.hosts():
                ip = str(ip)
                mac = get_mac(ip)
                if mac:
                    update_device(mac, ip)
                    current_devices.add(mac)

        detect_events(previous_devices, current_devices)

        previous_devices = current_devices

        time.sleep(30)

# ==============================
# RISK SCORING 
# ==============================
def risk_score(vendor, device_type):
    if vendor == "UNKNOWN":
        return "HIGH"
    if device_type == "Router/Gateway":
        return "CRITICAL"
    return "NORMAL"

# IMPROVEMENTS
#CDP /LLDP DISCOVERY
# Missing: Discover switch/router neighbors
def discover_neighbors(ip):
    """CDP (Cisco) or LLDP (Vendor-neutral) neighbor discovery"""
    # Need to add SNMP queries for:
    # - cdpCacheTable (1.3.6.1.4.1.9.9.23.1.2)
    # - lldpRemoteSystemsData (1.0.8802.1.1.2.1.4)
    pass
#VLAN DETECTION
# Missing: VLAN topology mapping
def discover_vlans(ip):
    """Discover VLANs from switches"""
    # OIDs needed:
    # - dot1qVlanStaticTable (1.3.6.1.2.1.17.7.1.4.5)
    # - vtpVlanState (1.3.6.1.4.1.9.9.46.1.3.1.1)
    pass
#WIRELESS NETWORK DISCOVERY
# Missing: WiFi AP and client detection
def discover_wireless(ip):
    """Detect wireless access points and connected clients"""
    # OIDs for:
    # - dot11SSID (1.3.6.1.4.1.9.9.272.1.1.1.2)
    # - wlanAPList
    pass
#IP ROUTE TABLE DISCOVERY
# You have router detection but missing routing tables
def get_routing_table(ip):
    """Complete routing table discovery"""
    # Need OIDs:
    # - ipCidrRouteTable (1.3.6.1.2.1.4.24)
    # - ipForwardTable (1.3.6.1.2.1.4.21)
    pass
#SWITCH MAC ADDRESS TABLE 
# Missing from switches
def get_cam_table(ip):
    """Get MAC address tables from switches"""
    # OIDs:
    # - dot1qTpFdbTable (1.3.6.1.2.1.17.7.1.2.2)
    # - dot1dTpFdbTable (1.3.6.1.2.1.17.4.3)
    pass
#PORT TO DEVICE MAPPING
# Missing: Which port a device is connected to
def get_device_port(switch_ip, mac):
    """Find which switch port contains a MAC"""
    # Cross-reference CAM table with device MACs
    pass
# SPANNING TREE ENABLED
# Missing: STP root bridge and topology
def get_stp_topology(ip):
    """Discover spanning tree protocol topology"""
    # OIDs:
    # - dot1dStpRootCost (1.3.6.1.2.1.17.2.4)
    # - dot1dStpRootPort (1.3.6.1.2.1.17.2.5)
    pass
# NETFLOW DETECTION
# Missing: Traffic flow analysis
def detect_netflow():
    """Discover NetFlow/sFlow exporters"""
    # Need to listen for NetFlow packets (UDP 2055)
    # or query SNMP for flow configuration
    pass
#PARTIAL BANDWIDTH UTILIZATION
# You have interface traffic but missing:
def get_bandwidth_utilization(ip, interface):
    """Calculate actual bandwidth usage %"""
    # Need ifSpeed (1.3.6.1.2.1.2.2.1.5)
    # Then calculate (inOctets*8/ifSpeed) * 100
    pass
# COMPLETE OS FINGERPRINTING
# Current: Basic TTL detection
# Missing: nmap-style TCP/IP stack fingerprinting
def advanced_os_fingerprint(ip):
    """TCP window size, options, DF bit analysis"""
    # Need to send crafted TCP packets
    # Analyze responses
    pass
#COMMON PORT DISCOVERY
# Missing: Common port scanning
def scan_services(ip, ports=[22, 80, 443, 445, 3389]):
    """Discover running services"""
    # Socket connects with timeout
    # Service banner grabbing
    pass
# NETWORK LATENCY DISCOVERY
# Missing: Network performance metrics
def measure_latency(ip, samples=5):
    """Measure round trip time and jitter"""
    # Not just ping - but timestamped measurements
    pass
# DNS INFRUSTRUCTURE DETECTION
# Missing: DNS servers and zones
def detect_dns_servers():
    """Find DNS servers via DHCP options or SNMP"""
    # DHCP option 6
    # SNMP dnsServerTable
    pass
#HTTP/HTTPS ASSET  DISCOVERY
# Missing: Web server detection
def discover_web_assets(ip):
    """Find web interfaces on devices"""
    # Try common ports (80, 443, 8080, 8443)
    # Get Server header
    # Detect API endpoints
    pass
# COMPLETE L2/L3 TOPOLOGY DISCOVERY
# Add this to complete L2/L3 topology discovery:
class CompleteTopologyDiscovery:
    def discover_full_topology(self):
        """Complete network discovery in order:"""
        # 1. Find all routers via SNMP/ICMP
        # 2. Get routing tables from each router
        # 3. Find all switches via LLDP/CDP
        # 4. Get CAM tables from switches
        # 5. Map MACs to ports
        # 6. Build complete topology graph
        # 7. Export to Graphviz/JSON
        pass


# ==============================
# ADVANCED FINGERPRINT-BASED TRACKING
# ==============================


# Database schema extension for fingerprint tracking
def extend_database_for_fingerprints():
    """Add fingerprint tracking tables to database"""
    with db.lock:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Table for device fingerprints
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_fingerprints (
                fingerprint_id TEXT PRIMARY KEY,
                device_name TEXT,
                vendor TEXT,
                first_seen TEXT,
                last_seen TEXT,
                confidence REAL,
                fingerprint_data TEXT
            )
        """)
        
        # Table for fingerprint history (track changes over time)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fingerprint_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint_id TEXT,
                current_mac TEXT,
                seen_at TEXT,
                rssi INTEGER,
                channel INTEGER,
                FOREIGN KEY (fingerprint_id) REFERENCES device_fingerprints (fingerprint_id)
            )
        """)
        
        # Add fingerprint_id to devices table
        try:
            cursor.execute("ALTER TABLE devices ADD COLUMN fingerprint_id TEXT")
            cursor.execute("ALTER TABLE devices ADD COLUMN detection_method TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        
        conn.commit()
        conn.close()

# Call this during initialization
extend_database_for_fingerprints()

# ==============================
# INFORMATION ELEMENT EXTRACTORS
# ==============================

def extract_ie_sequence(probe_request):
    """Extract the order of Information Elements (IEs) from probe request"""
    ie_sequence = []
    
    if not probe_request.haslayer(Dot11ProbeReq):
        return ie_sequence
    
    # Get all Dot11Elt layers
    elts = probe_request.getlayer(Dot11Elt)
    current_elt = elts
    
    while current_elt:
        ie_id = current_elt.ID
        ie_name = get_ie_name(ie_id)
        ie_sequence.append(ie_name)
        current_elt = current_elt.getlayer(Dot11Elt, 2)  # Skip current, get next
    
    return ie_sequence

def get_ie_name(ie_id):
    """Convert IE ID to readable name"""
    ie_names = {
        0: 'SSID',
        1: 'Supported_Rates',
        2: 'FH_Parameter_Set',
        3: 'DS_Parameter_Set',  # Channel
        4: 'CF_Parameter_Set',
        5: 'TIM',
        6: 'IBSS_Parameter_Set',
        7: 'Country',
        8: 'Hopping_Pattern',
        9: 'Hopping_Table',
        10: 'Request',
        11: 'BSS_Load',
        12: 'EDCA_Parameter_Set',
        13: 'TSPEC',
        14: 'TCLAS',
        15: 'Schedule',
        16: 'Challenge_Text',
        17: 'Reserved',
        18: 'Power_Constraint',
        19: 'Power_Capability',
        20: 'TPC_Request',
        21: 'TPC_Report',
        22: 'Supported_Channels',
        23: 'Channel_Switch_Announcement',
        24: 'Measurement_Request',
        25: 'Measurement_Report',
        26: 'Quiet',
        27: 'IBSS_DFS',
        28: 'ERP_Info',
        29: 'TS_Delay',
        30: 'TCLAS_Processing',
        31: 'HT_Capabilities',  # Important for fingerprinting
        32: 'QoS_Capability',
        33: 'Reserved',
        34: 'Reserved',
        35: 'Reserved',
        36: 'Reserved',
        37: 'Reserved',
        38: 'Reserved',
        39: 'Reserved',
        40: 'Reserved',
        41: 'Reserved',
        42: 'Reserved',
        43: 'Reserved',
        44: 'Reserved',
        45: 'Reserved',
        46: 'Reserved',
        47: 'Reserved',
        48: 'RSN_Info',  # WPA2
        49: 'BSS_Load',
        50: 'EDCA_Parameter_Set',
        51: 'Reserved',
        52: 'Reserved',
        53: 'Reserved',
        54: 'Reserved',
        55: 'Reserved',
        56: 'Reserved',
        57: 'Reserved',
        58: 'Reserved',
        59: 'Reserved',
        60: 'Reserved',
        61: 'Reserved',
        62: 'Reserved',
        63: 'Reserved',
        64: 'Reserved',
        65: 'Reserved',
        66: 'Reserved',
        67: 'Reserved',
        68: 'Reserved',
        69: 'Reserved',
        70: 'Reserved',
        71: 'Reserved',
        72: 'Reserved',
        73: 'Reserved',
        74: 'Reserved',
        75: 'Reserved',
        76: 'Reserved',
        77: 'Reserved',
        78: 'Reserved',
        79: 'Reserved',
        80: 'Reserved',
        81: 'Reserved',
        82: 'Reserved',
        83: 'Reserved',
        84: 'Reserved',
        85: 'Reserved',
        86: 'Reserved',
        87: 'Reserved',
        88: 'Reserved',
        89: 'Reserved',
        90: 'Reserved',
        91: 'Reserved',
        92: 'Reserved',
        93: 'Reserved',
        94: 'Reserved',
        95: 'Reserved',
        96: 'Reserved',
        97: 'Reserved',
        98: 'Reserved',
        99: 'Reserved',
        100: 'Reserved',
        101: 'Reserved',
        102: 'Reserved',
        103: 'Reserved',
        104: 'Reserved',
        105: 'Reserved',
        106: 'Reserved',
        107: 'Reserved',
        108: 'Reserved',
        109: 'Reserved',
        110: 'Reserved',
        111: 'Reserved',
        112: 'Reserved',
        113: 'Reserved',
        114: 'Reserved',
        115: 'Reserved',
        116: 'Reserved',
        117: 'Reserved',
        118: 'Reserved',
        119: 'Reserved',
        120: 'Reserved',
        121: 'Reserved',
        122: 'Reserved',
        123: 'Reserved',
        124: 'Reserved',
        125: 'Reserved',
        126: 'Reserved',
        127: 'Reserved',
        128: 'Reserved',
        129: 'Reserved',
        130: 'Reserved',
        131: 'Reserved',
        132: 'Reserved',
        133: 'Reserved',
        134: 'Reserved',
        135: 'Reserved',
        136: 'Reserved',
        137: 'Reserved',
        138: 'Reserved',
        139: 'Reserved',
        140: 'Reserved',
        141: 'Reserved',
        142: 'Reserved',
        143: 'Reserved',
        144: 'Reserved',
        145: 'Reserved',
        146: 'Reserved',
        147: 'Reserved',
        148: 'Reserved',
        149: 'Reserved',
        150: 'Reserved',
        151: 'Reserved',
        152: 'Reserved',
        153: 'Reserved',
        154: 'Reserved',
        155: 'Reserved',
        156: 'Reserved',
        157: 'Reserved',
        158: 'Reserved',
        159: 'Reserved',
        160: 'Reserved',
        161: 'Reserved',
        162: 'Reserved',
        163: 'Reserved',
        164: 'Reserved',
        165: 'Reserved',
        166: 'Reserved',
        167: 'Reserved',
        168: 'Reserved',
        169: 'Reserved',
        170: 'Reserved',
        171: 'Reserved',
        172: 'Reserved',
        173: 'Reserved',
        174: 'Reserved',
        175: 'Reserved',
        176: 'Reserved',
        177: 'Reserved',
        178: 'Reserved',
        179: 'Reserved',
        180: 'Reserved',
        181: 'Reserved',
        182: 'Reserved',
        183: 'Reserved',
        184: 'Reserved',
        185: 'Reserved',
        186: 'Reserved',
        187: 'Reserved',
        188: 'Reserved',
        189: 'Reserved',
        190: 'Reserved',
        191: 'Reserved',
        192: 'Vendor_Specific',  # Important for fingerprinting
        193: 'Vendor_Specific',
        194: 'Vendor_Specific',
        195: 'Vendor_Specific',
        196: 'Vendor_Specific',
        197: 'Vendor_Specific',
        198: 'Vendor_Specific',
        199: 'Vendor_Specific',
        200: 'Vendor_Specific',
        201: 'Vendor_Specific',
        202: 'Vendor_Specific',
        203: 'Vendor_Specific',
        204: 'Vendor_Specific',
        205: 'Vendor_Specific',
        206: 'Vendor_Specific',
        207: 'Vendor_Specific',
        208: 'Vendor_Specific',
        209: 'Vendor_Specific',
        210: 'Vendor_Specific',
        211: 'Vendor_Specific',
        212: 'Vendor_Specific',
        213: 'Vendor_Specific',
        214: 'Vendor_Specific',
        215: 'Vendor_Specific',
        216: 'Vendor_Specific',
        217: 'Vendor_Specific',
        218: 'Vendor_Specific',
        219: 'Vendor_Specific',
        220: 'Vendor_Specific',
        221: 'Vendor_Specific',  # Most vendor-specific IEs
    }
    
    return ie_names.get(ie_id, f'Unknown_{ie_id}')

def extract_supported_rates(probe_request):
    """Extract supported data rates from probe request"""
    rates = []
    
    if not probe_request.haslayer(Dot11ProbeReq):
        return rates
    
    elts = probe_request.getlayer(Dot11Elt)
    current_elt = elts
    
    while current_elt:
        if current_elt.ID == 1:  # Supported Rates
            rate_bytes = bytes(current_elt.info)
            for rate_byte in rate_bytes:
                rate_mbps = (rate_byte & 0x7F) * 0.5  # Mask out basic rate bit
                rates.append(rate_mbps)
        current_elt = current_elt.getlayer(Dot11Elt, 2)
    
    return sorted(set(rates))  # Unique sorted rates

def extract_ht_capabilities(probe_request):
    """Extract HT (802.11n) capabilities"""
    ht_caps = {}
    
    if not probe_request.haslayer(Dot11ProbeReq):
        return ht_caps
    
    elts = probe_request.getlayer(Dot11Elt)
    current_elt = elts
    
    while current_elt:
        if current_elt.ID == 45:  # HT Capabilities (sometimes 45)
            info = bytes(current_elt.info)
            if len(info) >= 2:
                ht_caps['supported_mcs'] = extract_mcs_from_ht(info)
                ht_caps['ampdu_factor'] = (info[0] >> 0) & 0x03
                ht_caps['ampdu_density'] = (info[0] >> 2) & 0x07
                ht_caps['ht_supported'] = True
        current_elt = current_elt.getlayer(Dot11Elt, 2)
    
    return ht_caps

def extract_mcs_from_ht(ht_info):
    """Extract MCS (Modulation Coding Scheme) from HT info"""
    mcs = []
    if len(ht_info) >= 12:  # MCS info is at offset 12
        mcs_bytes = ht_info[12:16]
        for i, byte in enumerate(mcs_bytes):
            for bit in range(8):
                if byte & (1 << bit):
                    mcs.append(i * 8 + bit)
    return mcs

def extract_vendor_ies(probe_request):
    """Extract vendor-specific Information Elements"""
    vendor_ies = []
    
    if not probe_request.haslayer(Dot11ProbeReq):
        return vendor_ies
    
    elts = probe_request.getlayer(Dot11Elt)
    current_elt = elts
    
    while current_elt:
        if current_elt.ID == 221:  # Vendor Specific
            info = bytes(current_elt.info)
            if len(info) >= 3:
                # Extract OUI (first 3 bytes)
                oui = '-'.join(f'{b:02X}' for b in info[:3])
                vendor_ies.append({
                    'oui': oui,
                    'data': info[3:].hex() if len(info) > 3 else '',
                    'length': len(info)
                })
        current_elt = current_elt.getlayer(Dot11Elt, 2)
    
    return vendor_ies

# ==============================
# FINGERPRINT GENERATION
# ==============================

def generate_device_fingerprint(probe_request, mac=None):
    """Generate a stable fingerprint from probe request"""
    fingerprint = {
        'ie_sequence': extract_ie_sequence(probe_request),
        'supported_rates': extract_supported_rates(probe_request),
        'ht_capabilities': extract_ht_capabilities(probe_request),
        'vendor_ies': extract_vendor_ies(probe_request),
        'timestamp': datetime.datetime.now().isoformat(),
    }
    
    # Add RSSI if available (from RadioTap)
    if probe_request.haslayer(RadioTap):
        fingerprint['rssi'] = probe_request.dBm_AntSignal if hasattr(probe_request, 'dBm_AntSignal') else None
    
    # Generate hash for the fingerprint (for quick comparison)
    fingerprint_hash = generate_fingerprint_hash(fingerprint)
    
    return fingerprint, fingerprint_hash

def generate_fingerprint_hash(fingerprint):
    """Generate a stable hash from fingerprint data"""
    # Create a string representation of key components
    fingerprint_str = json.dumps({
        'ie_sequence': fingerprint['ie_sequence'],
        'supported_rates': fingerprint['supported_rates'],
        'ht_capabilities': fingerprint.get('ht_capabilities', {}),
        'vendor_oui': [v['oui'] for v in fingerprint.get('vendor_ies', [])]
    }, sort_keys=True)
    
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

# ==============================
# FINGERPRINT MATCHING AND STORAGE
# ==============================

class FingerprintDatabase:
    def __init__(self):
        self.fingerprints = {}  # hash -> fingerprint data
        self.mac_to_fingerprint = defaultdict(list)  # MAC -> list of hashes
        self.fingerprint_to_mac = defaultdict(set)  # hash -> set of MACs seen with this fingerprint
        
    def add_fingerprint(self, fingerprint_hash, fingerprint, mac):
        """Add or update fingerprint in database"""
        now = datetime.datetime.now().isoformat()
        
        # Check if we've seen this fingerprint before
        if fingerprint_hash in self.fingerprints:
            # Update existing fingerprint
            existing = self.fingerprints[fingerprint_hash]
            existing['last_seen'] = now
            existing['seen_count'] = existing.get('seen_count', 0) + 1
            
            # Track MAC association
            self.fingerprint_to_mac[fingerprint_hash].add(mac)
        else:
            # New fingerprint
            fingerprint['fingerprint_hash'] = fingerprint_hash
            fingerprint['first_seen'] = now
            fingerprint['last_seen'] = now
            fingerprint['seen_count'] = 1
            self.fingerprints[fingerprint_hash] = fingerprint
            self.fingerprint_to_mac[fingerprint_hash] = {mac}
        
        # Track MAC to fingerprint mapping
        self.mac_to_fingerprint[mac].append(fingerprint_hash)
        
        # Keep only last 10 fingerprints per MAC
        if len(self.mac_to_fingerprint[mac]) > 10:
            self.mac_to_fingerprint[mac].pop(0)
        
        return fingerprint_hash
    
    def find_matching_device(self, fingerprint_hash, current_mac):
        """Find if this fingerprint matches a known device"""
        if fingerprint_hash in self.fingerprints:
            # Get all MACs associated with this fingerprint
            associated_macs = self.fingerprint_to_mac.get(fingerprint_hash, set())
            
            # If this fingerprint has been seen with multiple MACs, it's likely the same device with randomization
            if len(associated_macs) > 1:
                logger.info(f"Fingerprint {fingerprint_hash} associated with {len(associated_macs)} MACs - likely same device")
                return True, list(associated_macs)
            
            # Single MAC association
            return True, list(associated_macs)
        
        return False, None
    
    def get_device_identity(self, fingerprint_hash):
        """Get the most likely device identity from fingerprint"""
        if fingerprint_hash not in self.fingerprints:
            return None
        
        fp = self.fingerprints[fingerprint_hash]
        associated_macs = self.fingerprint_to_mac.get(fingerprint_hash, set())
        
        # Try to determine vendor from vendor IEs
        vendor = None
        for vendor_ie in fp.get('vendor_ies', []):
            oui = vendor_ie.get('oui', '')
            if oui:
                # Look up OUI in our database
                vendor_candidate = OUI_DATABASE.get(oui, '')
                if vendor_candidate and vendor_candidate != 'UNKNOWN':
                    vendor = vendor_candidate
                    break
        
        # Try to infer device type from capabilities
        device_type = infer_device_type_from_fingerprint(fp)
        
        return {
            'fingerprint_hash': fingerprint_hash,
            'associated_macs': list(associated_macs),
            'vendor': vendor or 'Unknown',
            'device_type': device_type,
            'first_seen': fp.get('first_seen'),
            'last_seen': fp.get('last_seen'),
            'seen_count': fp.get('seen_count', 0),
            'ie_sequence': fp.get('ie_sequence', []),
            'supported_rates': fp.get('supported_rates', []),
        }

def infer_device_type_from_fingerprint(fingerprint):
    """Infer device type from fingerprint characteristics"""
    ie_sequence = fingerprint.get('ie_sequence', [])
    rates = fingerprint.get('supported_rates', [])
    
    # Mobile devices often have specific IE patterns
    if 'HT_Capabilities' in ie_sequence and 'Vendor_Specific' in ie_sequence:
        # Check for typical mobile rates (1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54 Mbps)
        mobile_rates = {1, 2, 5.5, 6, 9, 11, 12, 18, 24, 36, 48, 54}
        if set(rates).intersection(mobile_rates):
            return "Mobile Device"
    
    # IoT devices often have simpler IE sequences
    if len(ie_sequence) < 5 and 'HT_Capabilities' not in ie_sequence:
        return "IoT Device"
    
    # Laptops typically have more complete IE sets
    if 'HT_Capabilities' in ie_sequence and 'RSN_Info' in ie_sequence:
        return "Computer"
    
    return "Unknown"

# ==============================
# MONITOR MODE FINGERPRINT SNIFFER
# ==============================

fingerprint_db = FingerprintDatabase()

def fingerprint_sniffer(packet):
    """Sniff and fingerprint probe requests"""
    if packet.haslayer(Dot11ProbeReq):
        try:
            # Get the source MAC (could be randomized)
            mac = packet.addr2 if hasattr(packet, 'addr2') else None
            
            if mac:
                # Normalize MAC
                mac = normalize_mac(mac)
                
                # Generate fingerprint
                fingerprint, fp_hash = generate_device_fingerprint(packet, mac)
                
                # Check if this fingerprint matches a known device
                matched, associated_macs = fingerprint_db.find_matching_device(fp_hash, mac)
                
                if matched:
                    # This device has been seen before with potentially different MACs
                    logger.info(f"🔍 FINGERPRINT MATCH: {fp_hash}")
                    logger.info(f"   Current MAC: {mac}")
                    logger.info(f"   Previously seen MACs: {associated_macs}")
                    
                    # Get device identity
                    identity = fingerprint_db.get_device_identity(fp_hash)
                    if identity:
                        logger.info(f"   Device Vendor: {identity['vendor']}")
                        logger.info(f"   Device Type: {identity['device_type']}")
                        logger.info(f"   Seen {identity['seen_count']} times since {identity['first_seen']}")
                    
                    # Store in main database with fingerprint
                    update_device_with_fingerprint(mac, fp_hash, fingerprint)
                else:
                    # New device
                    logger.info(f"🆕 NEW FINGERPRINT: {fp_hash} from MAC {mac}")
                    
                    # Try to infer device info from fingerprint
                    device_info = fingerprint_db.get_device_identity(fp_hash) or {}
                    
                    # Store in database
                    update_device_with_fingerprint(mac, fp_hash, fingerprint, is_new=True)
                
                # Add to fingerprint database
                fingerprint_db.add_fingerprint(fp_hash, fingerprint, mac)
                
        except Exception as e:
            logger.debug(f"Fingerprint error: {e}")

def update_device_with_fingerprint(mac, fingerprint_hash, fingerprint, is_new=False):
    """Update device database with fingerprint information"""
    now = datetime.datetime.now().isoformat()
    
    # Get device info from fingerprint
    device_info = fingerprint_db.get_device_identity(fingerprint_hash) or {}
    
    # Try to get IP from ARP
    ip = None
    try:
        # Check ARP table for this MAC
        output = subprocess.check_output(['arp', '-a'], timeout=2).decode()
        for line in output.splitlines():
            if mac.lower() in line.lower() or mac.upper() in line.upper():
                parts = line.split()
                for part in parts:
                    if part.count('.') == 3:
                        ip = part.strip('()')
                        break
    except:
        pass
    
    vendor = device_info.get('vendor') or get_vendor(mac)
    device_type = device_info.get('device_type') or classify_device(ip or '', None, vendor, None)
    
    # Check if device exists by fingerprint (more reliable than MAC)
    existing = db.execute_query(
        "SELECT * FROM devices WHERE fingerprint_id=? OR mac=?", 
        (fingerprint_hash, mac), 
        fetch_one=True
    )
    
    if existing:
        # Update existing device
        db.execute_query("""
            UPDATE devices
            SET ip=?, vendor=?, hostname=?, device_type=?, location=?, last_seen=?, 
                fingerprint_id=?, detection_method=?
            WHERE mac=? OR fingerprint_id=?
        """, (ip, vendor, None, device_type, "UNASSIGNED", now, 
              fingerprint_hash, "fingerprint", mac, fingerprint_hash))
        status = "UPDATED (fingerprint matched)"
    else:
        # Insert new device
        db.execute_query("""
            INSERT INTO devices (mac, ip, vendor, hostname, device_type, location, last_seen, fingerprint_id, detection_method)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (mac, ip, vendor, None, device_type, "UNASSIGNED", now, fingerprint_hash, "fingerprint"))
        status = "NEW (fingerprint created)"
    
    logger.info(f"{status}: {mac} (FP: {fingerprint_hash[:8]}) -> {ip or 'no IP'} | {vendor} | {device_type}")

def start_fingerprint_sniffer(interface=None, timeout=0):
    """Start fingerprint-based device tracking"""
    try:
        logger.info("Starting fingerprint sniffer (requires monitor mode)...")
        
        # On Windows, monitor mode might not work - fallback to promiscuous
        if platform.system().lower() == 'windows':
            logger.warning("Monitor mode may not work on Windows - using promiscuous mode")
            # Try to get available interfaces
            interfaces = get_wireless_interfaces()
            if interfaces:
                interface = interfaces[0]
                logger.info(f"Using interface: {interface}")
        
        sniff(
            iface=interface,
            prn=fingerprint_sniffer,
            store=0,
            timeout=timeout if timeout > 0 else None
        )
    except PermissionError:
        logger.error("Permission denied. Run as administrator/root.")
    except Exception as e:
        logger.error(f"Fingerprint sniffer error: {e}")

def get_wireless_interfaces():
    """Get list of wireless interfaces on Windows"""
    interfaces = []
    try:
        output = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], timeout=5).decode()
        for line in output.splitlines():
            if 'Name' in line and ':' in line:
                iface = line.split(':')[1].strip()
                if iface:
                    interfaces.append(iface)
    except:
        pass
    return interfaces

# ==============================
# FINGERPRINT ANALYSIS AND REPORTING
# ==============================

def analyze_fingerprints():
    """Analyze collected fingerprints and identify devices"""
    print("\n" + "="*80)
    print("FINGERPRINT ANALYSIS REPORT".center(80))
    print("="*80)
    
    fingerprints = fingerprint_db.fingerprints
    
    if not fingerprints:
        print("\nNo fingerprints collected yet. Run fingerprint sniffer first.")
        return
    
    print(f"\nTotal unique fingerprints: {len(fingerprints)}")
    
    # Group by vendor/type
    by_vendor = defaultdict(list)
    by_type = defaultdict(list)
    
    for fp_hash, fp_data in fingerprints.items():
        identity = fingerprint_db.get_device_identity(fp_hash)
        if identity:
            by_vendor[identity['vendor']].append(fp_hash)
            by_type[identity['device_type']].append(fp_hash)
    
    print("\nDevices by vendor:")
    for vendor, hashes in sorted(by_vendor.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {vendor}: {len(hashes)} device(s)")
    
    print("\nDevices by type:")
    for dtype, hashes in sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {dtype}: {len(hashes)} device(s)")
    
    print("\nDetailed device information:")
    for fp_hash, fp_data in list(fingerprints.items())[:10]:  # Show first 10
        identity = fingerprint_db.get_device_identity(fp_hash)
        if identity:
            print(f"\n  Fingerprint: {fp_hash[:16]}...")
            print(f"    Associated MACs: {len(identity['associated_macs'])}")
            if identity['associated_macs']:
                print(f"    MAC examples: {', '.join(identity['associated_macs'][:3])}")
            print(f"    Vendor: {identity['vendor']}")
            print(f"    Type: {identity['device_type']}")
            print(f"    Seen: {identity['seen_count']} times")
            print(f"    First: {identity['first_seen']}")
            print(f"    Last: {identity['last_seen']}")
            print(f"    IE Sequence: {' → '.join(identity['ie_sequence'][:10])}")

# ==============================
# QUICK TEST FUNCTION
# ==============================

def test_fingerprint_on_phone():
    """Test function to specifically look for your Infinix phone"""
    print("\n" + "="*60)
    print("TESTING: Looking for Infinix Hot 60i")
    print("="*60)
    print("\nMake sure your phone:")
    print("1. Has WiFi ON and screen unlocked")
    print("2. Is not in airplane mode")
    print("3. Is within range of your computer")
    print("\nListening for probe requests for 30 seconds...")
    
    # Known Infinix/Transsion OUIs
    infinix_ouis = [
        '00-0E-9E', '00-1A-9E', '08-5A-13', '10-08-B8', '2C-33-7A',
        '3C-A9-F4', '40-5B-D8', '4C-5E-0C', '50-2B-73', '54-2E-15',
        '5C-E3-0E', '60-D8-19', '64-CC-2E', '68-3E-34', '6C-3B-6B'
    ]
    
    def check_packet(pkt):
        if pkt.haslayer(Dot11ProbeReq):
            mac = pkt.addr2 if hasattr(pkt, 'addr2') else None
            if mac:
                mac_norm = normalize_mac(mac)
                oui = mac_norm[:8] if mac_norm else ''
                
                if oui in infinix_ouis:
                    print(f"\n🎯 FOUND POTENTIAL INFINIX DEVICE!")
                    print(f"   MAC: {mac_norm}")
                    print(f"   OUI: {oui} (Infinix/Transsion range)")
                    
                    # Generate fingerprint
                    fp, fp_hash = generate_device_fingerprint(pkt, mac_norm)
                    print(f"   Fingerprint: {fp_hash}")
                    print(f"   IE Sequence: {fp['ie_sequence']}")
                    print(f"   Supported Rates: {fp['supported_rates']}")
                    
                    return True
            return False
    
    # Sniff for 30 seconds
    sniff(timeout=30, prn=check_packet, store=0)
    print("\nTest complete.")

# Add to your main menu
def add_fingerprint_menu():
    """Add fingerprint scanning to main menu"""
    print("\n" + "="*60)
    print("FINGERPRINT TRACKING MENU")
    print("="*60)
    print("1. Test for Infinix Hot 60i (quick test)")
    print("2. Start fingerprint sniffer (continuous)")
    print("3. Analyze collected fingerprints")
    print("4. Return to main menu")
    
    choice = input("\nSelect option: ").strip()
    
    if choice == "1":
        test_fingerprint_on_phone()
    elif choice == "2":
        print("\nStarting fingerprint sniffer. Press Ctrl+C to stop.")
        start_fingerprint_sniffer()
    elif choice == "3":
        analyze_fingerprints()
    else:
        return


# debug network 192.168.100.0
def debug_network_scan():
    """Debug function to check 192.168.100.x network"""
    print("\n" + "="*60)
    print("DEBUGGING 192.168.100.X NETWORK")
    print("="*60)
    
    # Check if gateway responds
    gateway = "192.168.100.1"
    if ping(gateway):
        print(f"✅ Gateway {gateway} is responding to ping")
        mac = get_mac_arp_table(gateway)
        if mac:
            print(f"   Gateway MAC: {mac}")
            update_device(mac, gateway)
    else:
        print(f"❌ Gateway {gateway} not responding to ping")
    
    # Check ARP table for 192.168.100.x devices
    print("\nChecking ARP table for 192.168.100.x devices...")
    try:
        output = subprocess.check_output(['arp', '-a']).decode()
        for line in output.splitlines():
            if '192.168.100.' in line:
                print(f"  {line}")
                # Extract and update
                parts = line.split()
                for part in parts:
                    if '-' in part and len(part) == 17:
                        mac = part
                        for p in parts:
                            if p.count('.') == 3:
                                ip = p.strip('()')
                                update_device(mac, ip)
    except Exception as e:
        print(f"Error: {e}")

# Add this to main() before refresh_arp_cache()
debug_network_scan()

# Store fingerprint instead of MAC as device identifier
# ==============================
# MAIN
# ==============================
def main():
    """Main execution function"""
    print("\n" + "="*80)
    print("NETWORK ASSET DISCOVERY ENGINE v3.1".center(80))
    print("="*80)
    
    logger.info(f"Local machine IP: {get_local_ip()}")
    logger.info(f"Target network: {NETWORKS}")
    logger.info(f"Database: {DB_NAME}")
    
    # Start DHCP sniffer in background (if possible)
    dhcp_thread = None
    try:
        dhcp_thread = threading.Thread(target=start_dhcp_sniffer, daemon=True)
        dhcp_thread.start()
        logger.info("DHCP sniffer started in background")
    except Exception as e:
        logger.warning(f"Could not start DHCP sniffer: {e}")
    
    # Choose scan method
    print("\nScan options:")
    print("1. ICMP Ping Scan (faster, may miss some devices)")
    print("2. ARP Scan (more reliable, may need root)")
    print("3. Both (recommended)")
    
    choice = input("\nSelect option (1-3) [default: 3]: ").strip() or "3"
    
    if choice in ["1", "3"]:
        scan_network()
    
    if choice in ["2", "3"]:
        arp_scan()
    

    mobile_devices = refresh_arp_cache()
    # Display results
    show_devices()
    show_statistics()
    # Cleanup
    db.close()
    logger.info("Scan completed successfully")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
        db.close()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        db.close()