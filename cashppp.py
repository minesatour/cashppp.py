import os
import logging
import time
import subprocess
from scapy.all import *
from tkinter import Tk, Button, Listbox, Label, messagebox, simpledialog
import netifaces
import requests
from concurrent.futures import ThreadPoolExecutor
from netaddr import IPAddress, IPNetwork
import bluepy.btle as btle  # For Bluetooth scanning using bluepy

class ATMExploitTool:
    def __init__(self, master):
        self.master = master
        self.master.title("ATM Exploit Tool")
        self.master.geometry("700x500")  # Larger window size for better layout
        
        # Buttons for scanning and exploitation
        self.scan_atms_button = Button(self.master, text="Scan for ATMs in Range", command=self.scan_for_atms_in_range, width=30)
        self.scan_atms_button.pack(pady=10)

        self.atm_listbox = Listbox(self.master, width=50, height=15)
        self.atm_listbox.pack(pady=20)

        self.exploit_button = Button(self.master, text="Exploit ATM", command=self.exploit_atm, width=30)
        self.exploit_button.pack(pady=10)

        self.progress_label = Label(self.master, text="Status: Idle", width=50)
        self.progress_label.pack(pady=10)

        self.atms = []  # List to store ATM information
        
        logging.basicConfig(filename='atm_exploit_tool.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    def update_ui_progress(self, message):
        """Update progress label on the UI."""
        self.progress_label.config(text=f"Status: {message}")
        
    def scan_for_atms_in_range(self):
        """Scan for ATMs in the user's range."""
        self.atms.clear()
        self.atm_listbox.delete(0, 'end')
        self.update_ui_progress("Scanning for nearby ATMs...")
        
        # Simulate scanning nearby networks or devices (via Wi-Fi, Bluetooth, etc.)
        self.scan_wifi_networks()
        self.scan_bluetooth_devices()

        # After scanning, update the UI with found ATMs
        self.update_ui_progress("Scan complete.")
        if not self.atms:
            self.update_ui_progress("No ATMs found in range.")
        else:
            self.update_ui_progress(f"{len(self.atms)} ATM(s) found.")
    
    def scan_wifi_networks(self):
        """Simulate Wi-Fi network scanning for nearby ATMs."""
        self.update_ui_progress("Scanning for Wi-Fi networks...")
        networks = self.get_wifi_networks()
        for network in networks:
            self.detect_atm_services(network)
        
    def get_wifi_networks(self):
        """Simulate Wi-Fi network scan (for real-world, you can use iwlist or similar tool)."""
        # Replace this with actual scanning in a real scenario using iwlist or scanning libraries
        return ["192.168.0.0/24", "192.168.1.0/24"]  # Dummy values for testing
    
    def detect_atm_services(self, network):
        """Detect ATMs by scanning common ATM ports on the given network."""
        self.update_ui_progress(f"Scanning network {network} for ATMs...")
        nmap_command = f"nmap -p 80,443,21,22,23 {network}"
        result = subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        lines = output.splitlines()

        for line in lines:
            if "open" in line:
                ip = self.extract_ip_from_line(line)
                if self.is_atm_device(ip):
                    self.atms.append({"ip": ip, "port": self.extract_port_from_line(line)})
                    self.atm_listbox.insert('end', ip)
    
    def scan_bluetooth_devices(self):
        """Scan for Bluetooth devices nearby using bluepy."""
        self.update_ui_progress("Scanning for Bluetooth devices...")
        scanner = btle.Scanner()
        devices = scanner.scan(10.0)  # Scan for 10 seconds

        # Process found Bluetooth devices
        for dev in devices:
            device_mac = dev.addr
            if self.is_atm_device(device_mac):
                self.atms.append({"ip": device_mac, "port": "Bluetooth"})
                self.atm_listbox.insert('end', device_mac)
        
    def exploit_atm(self):
        """Exploit selected ATM."""
        selected_atm = self.atm_listbox.curselection()
        if not selected_atm:
            messagebox.showwarning("Selection Error", "No ATM selected.")
            return

        atm_ip = self.atms[selected_atm[0]]["ip"]
        self.update_ui_progress(f"Exploiting ATM at {atm_ip}...")

        # Simulate exploiting the ATM
        result = self.atm_exploit(atm_ip)
        self.update_ui_progress(result)

    def atm_exploit(self, ip):
        """Simulate exploiting the ATM to dispense maximum cash."""
        logging.info(f"Exploiting ATM at {ip}...")
        return f"ATM at {ip} exploited successfully! Dispensing maximum cash..."
    
    def extract_ip_from_line(self, line):
        """Extract the IP address from the Nmap line."""
        parts = line.split()
        return parts[0]
    
    def extract_port_from_line(self, line):
        """Extract the port number from the Nmap line."""
        parts = line.split()
        return parts[1]

    def is_atm_device(self, ip):
        """Check if the device is likely an ATM (by protocol, port, etc.)."""
        if self.check_known_atm_manufacturer(ip):
            return True
        if self.identify_atm_service(ip):
            return True
        if self.detect_atm_protocol(ip):
            return True
        return False
    
    def check_known_atm_manufacturer(self, ip):
        """Check if the IP belongs to a known ATM manufacturer."""
        known_manufacturers = ["100.115.92.0/24"]  # Example range, replace with actual ranges
        for cidr in known_manufacturers:
            if IPAddress(ip) in IPNetwork(cidr):
                logging.info(f"ATM found by manufacturer: {ip}")
                return True
        return False

    def identify_atm_service(self, ip):
        """Identify ATM services based on HTTP/FTP/etc."""
        try:
            response = requests.get(f"http://{ip}")
            if "ATM" in response.text or "ATM Service" in response.headers.get('Server', ''):
                logging.info(f"ATM service found at {ip}")
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
                logging.info(f"ATM protocol detected at {ip}")
                return True
            return False
        except Exception as e:
            logging.error(f"Error during ATM protocol detection for {ip}: {e}")
            return False

if __name__ == "__main__":
    root = Tk()
    app = ATMExploitTool(root)
    root.mainloop()






