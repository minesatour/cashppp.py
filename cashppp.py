import os
import logging
import subprocess
from scapy.all import *
from tkinter import Tk, Button, Listbox, Label, messagebox
import requests
from netaddr import IPAddress, IPNetwork


class ATMExploitTool:
    def __init__(self, master):
        self.master = master
        self.master.title("ATM Exploit Tool")
        self.master.geometry("600x400")

        self.scan_button = Button(self.master, text="Scan for ATMs", command=self.scan_for_atms)
        self.scan_button.pack(pady=10)

        self.atm_listbox = Listbox(self.master)
        self.atm_listbox.pack(pady=10, fill='both', expand=True)

        self.exploit_button = Button(self.master, text="Exploit ATM", command=self.exploit_atm)
        self.exploit_button.pack(pady=10)

        self.progress_label = Label(self.master, text="Status: Idle")
        self.progress_label.pack(pady=10)

        self.atms = []  # List to store detected ATMs

    def update_ui_progress(self, message):
        """Update progress label on the UI."""
        self.progress_label.config(text=f"Status: {message}")
        self.master.update_idletasks()

    def scan_for_atms(self):
        """Scan a given network range for ATMs."""
        self.update_ui_progress("Scanning network 100.115.92.0/24 for ATMs...")
        network = "100.115.92.0/24"
        self.atms.clear()
        self.atm_listbox.delete(0, 'end')

        try:
            # Run Nmap scan for open ports
            nmap_command = f"nmap -p 80,443,21,22,23,53 {network}"
            result = subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            self.update_ui_progress("Parsing scan results...")
            output = result.stdout.decode('utf-8')
            lines = output.splitlines()

            for line in lines:
                if "open" in line:
                    ip = self.extract_ip_from_line(line)
                    if ip and self.is_atm_device(ip):
                        self.atms.append(ip)
                        self.atm_listbox.insert('end', ip)

            self.update_ui_progress("Scan complete.")
        except Exception as e:
            self.update_ui_progress("Error during scan.")
            messagebox.showerror("Error", f"Failed to scan network: {e}")

    def exploit_atm(self):
        """Exploit selected ATM."""
        selected_atm = self.atm_listbox.curselection()
        if not selected_atm:
            messagebox.showwarning("Selection Error", "No ATM selected.")
            return

        atm_ip = self.atms[selected_atm[0]]
        self.update_ui_progress(f"Exploiting ATM at {atm_ip}...")

        try:
            result = self.atm_exploit(atm_ip)
            self.update_ui_progress("Exploit complete.")
            messagebox.showinfo("Exploit Success", result)
        except Exception as e:
            self.update_ui_progress("Exploit failed.")
            messagebox.showerror("Error", f"Failed to exploit ATM: {e}")

    def atm_exploit(self, ip):
        """Simulate exploiting the ATM."""
        # Placeholder for ATM exploit logic
        # Replace with actual exploit logic if needed
        return f"ATM at {ip} exploited successfully! Dispensing cash..."

    def extract_ip_from_line(self, line):
        """Extract the IP address from the Nmap line."""
        try:
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            if ip_match:
                return ip_match.group(1)
        except Exception as e:
            logging.error(f"Failed to extract IP from line: {line}. Error: {e}")
        return None

    def is_atm_device(self, ip):
        """Determine if the device is an ATM."""
        try:
            if self.check_known_atm_manufacturer(ip):
                return True
            if self.identify_atm_service(ip):
                return True
        except Exception as e:
            logging.error(f"Error identifying ATM device: {ip}. Error: {e}")
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
            response = requests.get(f"http://{ip}", timeout=3)
            if "ATM" in response.text or "ATM Service" in response.headers.get('Server', ''):
                return True
        except requests.RequestException:
            pass
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    root = Tk()
    app = ATMExploitTool(root)
    root.mainloop()


