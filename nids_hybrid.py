#!/usr/bin/env python3
"""
NIDS - Hybrid Active+Passive ARP Spoofing Detector
Scan interval: 5 minutes | Auto vendor detection
"""
from scapy.all import sniff, ARP, Ether, srp
from datetime import datetime, timedelta
import sqlite3
import json
import requests
import threading
import socket

class NIDSHybridDetector:
    def __init__(self, scan_interval_minutes=5):
        self.arp_table = {}
        self.alerted_ips = set()
        self.scan_interval = timedelta(minutes=scan_interval_minutes)
        
        self.gateway_ip = None
        self.network_range = None
        
        # Vendor database
        self.vendors = {
            '000C29': 'VMware',
            '005056': 'VMware',
            '001B21': 'VMware',
            '080027': 'VirtualBox',
            '525400': 'QEMU/KVM',
            '00163E': 'Xen',
            'FCA667': 'Apple',
            'B827EB': 'Raspberry Pi',
            '3C22FB': 'Apple',
            'A483E7': 'Apple',
            '001302': 'Intel',
            '001422': 'Dell',
            '0017A4': 'HP',
            '00000C': 'Cisco',
            '001882': 'Huawei',
            '009E1C': 'Xiaomi',
            '001A11': 'Google',
            '001247': 'Samsung',
        }
        
        try:
            from config import TELEGRAM_TOKEN, CHAT_ID
            self.TELEGRAM_TOKEN = TELEGRAM_TOKEN
            self.CHAT_ID = CHAT_ID
        except ImportError:
            print("[!] config.py not found. Using default values.")
            self.TELEGRAM_TOKEN = "YOUR_TOKEN_HERE"
            self.CHAT_ID = "YOUR_CHAT_ID_HERE"
        
        self.db_path = 'nids.db'
        self.init_db()
        
        self.stop_scanning = threading.Event()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS arp_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip TEXT,
                mac TEXT,
                event_type TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS spoofing_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target_ip TEXT,
                conflicting_macs TEXT,
                severity TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS baseline (
                ip TEXT PRIMARY KEY,
                mac TEXT NOT NULL,
                vendor TEXT,
                hostname TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_vendor(self, mac):
        """Get vendor from MAC OUI"""
        oui = mac.replace(':', '')[:6].upper()
        return self.vendors.get(oui, 'Unknown')
    
    def get_network_info(self):
        """Tự động phát hiện network range"""
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f:
                    fields = line.strip().split()
                    if fields[1] == '00000000':
                        dest = fields[2]
                        self.gateway_ip = f"{int(dest[6:8], 16)}.{int(dest[4:6], 16)}.{int(dest[2:4], 16)}.{int(dest[0:2], 16)}"
                        break
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.gateway_ip, 80))
            my_ip = s.getsockname()[0]
            s.close()
            
            ip_parts = my_ip.split('.')
            self.network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            print(f"[*] My IP: {my_ip}")
            print(f"[*] Gateway: {self.gateway_ip}")
            print(f"[*] Network: {self.network_range}")
            
            return True
        except Exception as e:
            print(f"[!] Error getting network info: {e}")
            return False
    
    def active_scan(self):
        """Quét chủ động toàn bộ subnet"""
        print("\n" + "="*70)
        print("  ACTIVE NETWORK SCAN")
        print("="*70)
        print(f"[*] Scanning {self.network_range}...")
        print("[*] This may take 30-60 seconds...\n")
        
        arp_request = ARP(pdst=self.network_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        answered_list = srp(arp_request_broadcast, timeout=5, retry=1, verbose=False)[0]
        
        devices = []
        print(f"{'IP Address':<20} {'MAC Address':<20} {'Vendor':<15}")
        print("-"*70)
        
        for element in answered_list:
            client = {'ip': element[1].psrc, 'mac': element[1].hwsrc.upper()}
            vendor = self.get_vendor(client['mac'])
            client['vendor'] = vendor
            devices.append(client)
            
            print(f"{client['ip']:<20} {client['mac']:<20} {vendor:<15}")
            
            self.update_baseline(client['ip'], client['mac'], client['vendor'])
        
        print("-"*70)
        print(f"[*] Found {len(devices)} devices")
        print("="*70 + "\n")
        
        return devices
    
    def update_baseline(self, ip, mac, vendor, hostname=None):
        """Update baseline database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO baseline (ip, mac, vendor, hostname, last_seen, is_active)
                VALUES (?, ?, ?, ?, ?, 1)
            ''', (ip, mac, vendor, hostname, datetime.now()))
            
            conn.commit()
            conn.close()
            
            if ip not in self.arp_table:
                self.arp_table[ip] = []
            
            existing_macs = [entry['mac'] for entry in self.arp_table[ip]]
            if mac not in existing_macs:
                self.arp_table[ip].append({
                    'mac': mac,
                    'vendor': vendor,
                    'time': datetime.now().strftime('%H:%M:%S')
                })
                
        except Exception as e:
            print(f"[!] Error updating baseline: {e}")
    
    def send_telegram_alert(self, ip, macs):
        """Gửi alert qua Telegram"""
        try:
            message = f"ARP SPOOFING DETECTED!\n\n"
            message += f"Target IP: {ip}\n\n"
            message += f"Conflicting MACs:\n"
            
            for i, mac in enumerate(macs, 1):
                if i == 1:
                    status = "LEGITIMATE"
                else:
                    status = "SPOOFED"
                
                vendor = self.get_vendor(mac)
                message += f"{status}: {mac} ({vendor})\n"
            
            message += f"\nStatus: ARP Spoofing Attack\n"
            message += f"Risk: Traffic interception possible\n"
            message += f"\nTime: {datetime.now().strftime('%H:%M:%S')}\n"
            message += f"Total Alerts: {len(self.alerted_ips)}"
            
            url = f"https://api.telegram.org/bot{self.TELEGRAM_TOKEN}/sendMessage"
            data = {
                "chat_id": self.CHAT_ID,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(url, json=data, timeout=10)
            
            if response.status_code == 200:
                print("[Telegram] Alert sent successfully!")
            else:
                print(f"[Telegram] Failed: {response.status_code}")
                
        except Exception as e:
            print(f"[Telegram] Error: {e}")
    
    def print_header(self):
        print("\n" + "-"*90)
        print(f"{'Time':<20} {'IP Address':<18} {'MAC Address':<20} {'Device/Vendor':<15}")
        print("-"*90)
    
    def print_alert_header(self, ip):
        print("\n" + "="*90)
        print(f"  ARP SPOOFING DETECTED - Target IP: {ip}")
        print("="*90)
        self.print_header()
    
    def process_arp_packet(self, packet):
        """Xử lý ARP packet (passive monitoring)"""
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc.upper()
            vendor = self.get_vendor(mac)
            timestamp = datetime.now().strftime('%H:%M:%S')
            
            self.log_event(ip, mac, 'ARP_REPLY')
            
            if ip not in self.arp_table:
                self.arp_table[ip] = []
                self.arp_table[ip].append({
                    'mac': mac,
                    'vendor': vendor,
                    'time': timestamp
                })
                self.update_baseline(ip, mac, vendor)
                print(f"[+] New device detected: {ip} -> {mac} ({vendor})")
                return
            
            existing_macs = [entry['mac'] for entry in self.arp_table[ip]]
            
            if mac not in existing_macs:
                self.arp_table[ip].append({
                    'mac': mac,
                    'vendor': vendor,
                    'time': timestamp
                })
                
                if ip not in self.alerted_ips:
                    self.alerted_ips.add(ip)
                    self.show_alert(ip)
    
    def show_alert(self, ip):
        self.print_alert_header(ip)
        
        for entry in self.arp_table[ip]:
            print(f"{entry['time']:<20} {ip:<18} {entry['mac']:<20} {entry['vendor']:<15}")
        
        print("-"*90)
        print(f"  Analysis: Multiple MAC addresses claiming IP {ip}")
        print(f"  Status: ARP Spoofing/Poisoning Attack")
        print(f"  Risk: Traffic interception possible")
        print("="*90)
        
        print("\n[Telegram] Sending alert...")
        self.send_telegram_alert(ip, [entry['mac'] for entry in self.arp_table[ip]])
        
        self.log_alert(ip, [entry['mac'] for entry in self.arp_table[ip]])
    
    def log_event(self, ip, mac, event_type):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO arp_events (ip, mac, event_type) VALUES (?, ?, ?)',
                (ip, mac, event_type)
            )
            conn.commit()
            conn.close()
        except:
            pass
    
    def log_alert(self, ip, macs):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO spoofing_alerts (target_ip, conflicting_macs, severity) VALUES (?, ?, ?)',
                (ip, json.dumps(macs), 'CRITICAL')
            )
            conn.commit()
            conn.close()
        except:
            pass
    
    def periodic_scanner(self):
        """Thread để quét định kỳ"""
        while not self.stop_scanning.is_set():
            self.stop_scanning.wait(self.scan_interval.total_seconds())
            
            if not self.stop_scanning.is_set():
                print(f"\n[*] Periodic scan at {datetime.now().strftime('%H:%M:%S')}")
                print("[*] Scanning for new/changed devices...")
                self.active_scan()
    
    def start(self):
        print("="*90)
        print("  NIDS - Hybrid Active+Passive ARP Spoofing Detector")
        print("="*90)
        print(f"\n[*] Scan interval: {self.scan_interval} minutes")
        print("[*] Telegram alerts: ENABLED")
        print()
        
        if not self.get_network_info():
            print("[!] Cannot detect network. Exiting...")
            return
        
        devices = self.active_scan()
        
        scanner_thread = threading.Thread(target=self.periodic_scanner, daemon=True)
        scanner_thread.start()
        
        print("\n" + "="*90)
        print("  PASSIVE MONITORING STARTED")
        print("="*90)
        print("[*] Listening for ARP traffic...")
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            sniff(prn=self.process_arp_packet, filter="arp", store=0)
        except KeyboardInterrupt:
            print("\n\n[!] Stopping NIDS...")
            self.stop_scanning.set()
            print(f"[*] Total alerts: {len(self.alerted_ips)}")
            print("[*] Goodbye!\n")

if __name__ == "__main__":
    detector = NIDSHybridDetector(scan_interval_minutes=5)
    detector.start()
