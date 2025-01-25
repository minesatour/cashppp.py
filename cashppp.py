import os
import logging
import time
import subprocess
from scapy.all import *
from tkinter import Tk, Button, Listbox, Label, messagebox, simpledialog, Text, Scrollbar
import netifaces
import requests
from concurrent.futures import ThreadPoolExecutor
from netaddr import IPAddress, IPNetwork
import bluepy.btle as btle  # For Bluetooth scanning (using bluepy)

class ATMExploitTool:
    def __init__(self, master):
        self.master = master
        self.master.title("ATM Exploit Tool")
        self.master.geometry("800x600")
        
        # Adding Exit Button functionality
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

        # Buttons for scanning and exploitation
        self.scan_atms_button = Button(self.master, text="Scan for ATMs in Range", command=self.scan_for_atms_in_range)
        self.scan_atms_button.pack(pady=10)

        self.atm_listbox = Listbox(self.master, height=10, width=50)
        self.atm_listbox.pack(pady=20, fill='both', expand=True)

        self.exploit_button = Button(self.master, text="Exploit ATM", command=self.exploit_atm)
        self.exploit_button.pack(pady=10)

        self.status_label = Label(self.master, text="Status Updates:", font=("Helvetica", 14))
        self.status_label.pack(pady=10)

        # Adding the Text widget for continuous updates
        self.text_box = Text(self.master, height=10, width=80, wrap='word', state='normal', bg='lightgrey')
        self.text_box.pack(padx=20, pady=10, fill='both', expand=True)

        self.scrollbar = Scrollbar(self.master, command=self.text_box.yview)
        self.scrollbar.pack(side='right', fill='y')
        self.text_box.config(yscrollcommand=self.scrollbar.set)

        self.atms = []

        logging.basicConfig(filename='atm_exploit_tool.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    def on_close(self):
        """Close the application properly when the user clicks the X button."""
        self.master.quit()

    def update_ui_progress(self, message):
        """Update progress text box on the UI."""
        self.text_box.insert('end', message + '\n')
        self.text_box.yview('end')

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
        """Scan for Bluetooth devices nearby (if applicable)."""
        self.update_ui_progress("Scanning for Bluetooth devices...")
        nearby_devices = self.scan_bluetooth()
        for device in nearby_devices:
            if self.is_atm_device(device):
                self.atms.append({"ip": device, "port": "Bluetooth"})
                self.atm_listbox.insert('end', device)

    def scan_bluetooth(self):
        """Simulate Bluetooth scanning."""
        nearby_devices = btle.Scanner().scan(8.0)  # Using bluepy Scanner
        return [device.addr for device in nearby_devices]

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
        known_manufacturers = ["100.115.92.0/24"]
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







