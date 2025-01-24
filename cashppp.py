import os
import re
import logging
import time
from scapy.all import *
from tkinter import Tk, Button, Listbox, Label, messagebox, ttk
import netifaces
from concurrent.futures import ThreadPoolExecutor
from netaddr import IPAddress, IPNetwork


class ATMExploitTool:
    def __init__(self, master):
        self.master = master
        self.master.title("ATM Exploit Tool")
        self.master.geometry("600x400")
        
        self.scan_button = tk.Button(self.master, text="Scan for ATMs", command=self.scan_for_atms)
        self.scan_button.pack(pady=20)

        self.atm_listbox = tk.Listbox(self.master)
        self.atm_listbox.pack(pady=20, fill=tk.BOTH, expand=True)

        self.exploit_button = tk.Button(self.master, text="Exploit ATM", command=self.exploit_atm)
        self.exploit_button.pack(pady=20)

        self.progress_label = tk.Label(self.master, text="")
        self.progress_label.pack(pady=10)

        self.atms = []

    def update_ui_progress(self, message):
        self.progress_label.config(text=message)

    def scan_for_atms(self):
        """Scan a given network range for ATMs."""
        self.update_ui_progress("Scanning network 100.115.92.0/24 for ATMs...")
        network = "100.115.92.0/24"
        self.atms.clear()
        self.atm_listbox.delete(0, tk.END)

        # Run Nmap scan for open ports (simplified example)
        nmap_command = f"nmap -p 80,443,21,22,23,53 {network}"
        result = subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.update_ui_progress("Scan complete. Parsing results...")

        # Parse Nmap results
        output = result.stdout.decode('utf-8')
        lines = output.splitlines()

        for line in lines:
            if "open" in line:
                ip = self.extract_ip_from_line(line)
                if self.is_atm_device(ip):
                    self.atms.append({"ip": ip, "port": self.extract_port_from_line(line)})
                    self.atm_listbox.insert(tk.END, ip)

        self.update_ui_progress("ATM Scan complete.")

    def exploit_atm(self):
        """Exploit selected ATM."""
        selected_atm = self.atm_listbox.curselection()
        if not selected_atm:
            messagebox.showwarning("Selection Error", "No ATM selected.")
            return
        
        atm_ip = self.atms[selected_atm[0]]["ip"]
        self.update_ui_progress(f"Exploiting ATM at {atm_ip}...")

        # Exploit selected ATM
        result = self.atm_exploit(atm_ip)
        self.update_ui_progress(result)

    def atm_exploit(self, ip):
        """Simulate exploiting the ATM."""
        # Placeholder for ATM exploit logic
        # In a real-world case, you would perform the attack here.
        # For now, we'll just simulate a successful exploit:
        return f"ATM at {ip} exploited successfully! Dispensing cash..."

    def extract_ip_from_line(self, line):
        """Extract the IP address from the Nmap line."""
        parts = line.split()
        return parts[0]

    def extract_port_from_line(self, line):
        """Extract the port number from the Nmap line."""
        parts = line.split()
        return parts[1]

    def is_atm_device(self, ip):
        """Use various methods to determine if the device is an ATM."""
        if self.check_known_atm_manufacturer(ip):
            return True
        if self.identify_atm_service(ip):
            return True
        if self.detect_atm_protocol(ip):
            return True
        return False

    def check_known_atm_manufacturer(self, ip):
        """Check if the IP belongs to a known ATM manufacturer."""
        known_manufacturers = ["100.115.92.0/24"]
        for cidr in known_manufacturers:
            if IPAddress(ip) in IPNetwork(cidr):
                return True
        return False

    def identify_atm_service(self, ip):
        """Identify ATM services based on HTTP/FTP/etc."""
        try:
            response = requests.get(f"http://{ip}")
            if "ATM" in response.text or "ATM Service" in response.headers.get('Server', ''):
                return True
            return False
        except requests.RequestException:
            return False

    def detect_atm_protocol(self, ip):
        """Detect ATM-specific protocols."""
        try:
            pkt = IP(dst=ip) / TCP(dport=80) / Raw(b"ATM protocol probe")
            response = sr1(pkt, timeout=2, verbose=0)
            if response and b"ATM_RESPONSE" in response.load:
                return True
            return False
        except Exception as e:
            logging.error(f"Error during ATM protocol detection for {ip}: {e}")
            return False

    def capture_atm_traffic(self, iface):
        """Capture packets to detect ATM-related traffic."""
        sniff(iface=iface, filter="tcp", prn=self.analyze_packet, store=0)

    def analyze_packet(self, packet):
        """Analyze captured packet for ATM-related traffic."""
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet.getlayer(Raw).load.decode(errors="ignore")
            if "ATM" in payload or "ATM_TRANSACTION" in payload:
                print(f"ATM traffic detected: {packet.summary()}")
                self.atms.append({"ip": packet.src, "port": packet.dport})


if __name__ == "__main__":
    root = tk.Tk()
    app = ATMExploitTool(root)
    root.mainloop()
