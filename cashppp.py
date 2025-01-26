import os
import logging
import subprocess
import threading
import time
from tkinter import Tk, Button, Listbox, Label, messagebox, Toplevel, Frame, Text, Scrollbar, Scale, StringVar, Menu
from tkinter.ttk import Notebook, Treeview
from netaddr import IPAddress, IPNetwork
from scapy.all import IP, TCP, sr1, Raw
import requests
import bluepy.btle as btle  # For Bluetooth scanning

class ATMExploitTool:
    def __init__(self, master):
        self.master = master
        self.master.title("ATM Exploit Tool")
        self.master.geometry("900x700")
        self.master.protocol("WM_DELETE_WINDOW", self.confirm_exit)

        # Tabbed interface
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

        # Home tab
        Label(self.home_tab, text="Welcome to the ATM Exploit Tool", font=("Helvetica", 18)).pack(pady=20)
        Label(self.home_tab, text="For educational purposes only.", font=("Helvetica", 14)).pack(pady=10)

        # Scan tab
        self.scan_button = Button(self.scan_tab, text="Start Scan", command=self.scan_for_atms)
        self.scan_button.pack(pady=10)

        self.scan_progress_label = Label(self.scan_tab, text="Scan Progress:", font=("Helvetica", 14))
        self.scan_progress_label.pack(pady=10)

        self.tree = Treeview(self.scan_tab, columns=("IP", "Port", "Protocol"), show="headings")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Port", text="Port")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.pack(fill="both", expand=True)

        # Exploit tab
        self.exploit_button = Button(self.exploit_tab, text="Exploit Selected ATM", command=self.exploit_atm)
        self.exploit_button.pack(pady=10)

        self.result_box = Text(self.exploit_tab, height=10, bg="lightgrey", state="normal")
        self.result_box.pack(fill="both", expand=True)

        # Logs tab
        self.logs_box = Text(self.logs_tab, wrap="word", state="normal", bg="lightgrey")
        self.logs_box.pack(fill="both", expand=True)
        self.scrollbar = Scrollbar(self.logs_tab, command=self.logs_box.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.logs_box.config(yscrollcommand=self.scrollbar.set)

        # Menu
        self.menu = Menu(self.master)
        self.master.config(menu=self.menu)
        self.menu.add_command(label="Settings", command=self.open_settings)
        self.menu.add_command(label="About", command=self.show_about)

        # Variables
        self.atms = []
        self.scan_duration = 8
        self.current_theme = StringVar(value="Light")
        self.logging_file = "atm_exploit_tool.log"

        logging.basicConfig(filename=self.logging_file, level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

    def confirm_exit(self):
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            self.master.quit()

    def update_ui(self, message, widget=None):
        if widget is None:
            widget = self.logs_box
        widget.insert("end", message + "\n")
        widget.yview("end")

    def open_settings(self):
        settings_window = Toplevel(self.master)
        settings_window.title("Settings")
        settings_window.geometry("400x300")

        Label(settings_window, text="Scan Duration (seconds):").pack(pady=10)
        duration_slider = Scale(settings_window, from_=5, to=30, orient="horizontal")
        duration_slider.set(self.scan_duration)
        duration_slider.pack()

        Label(settings_window, text="Select Theme:").pack(pady=10)
        theme_dropdown = StringVar(value=self.current_theme.get())
        theme_menu = Button(settings_window, text="Apply Theme", command=lambda: self.apply_theme(theme_dropdown.get()))
        theme_menu.pack(pady=10)

        Button(settings_window, text="Save Settings", command=settings_window.destroy).pack(pady=10)

    def apply_theme(self, theme):
        self.current_theme.set(theme)
        # Theme logic can be added here

    def show_about(self):
        messagebox.showinfo("About", "ATM Exploit Tool\nVersion 1.0\nFor educational purposes only.")

    def scan_for_atms(self):
        threading.Thread(target=self.run_scans).start()

    def run_scans(self):
        self.atms.clear()
        self.update_ui("Scanning for ATMs...", self.logs_box)
        self.scan_bluetooth()
        self.scan_wifi()
        self.update_ui(f"Scan completed. {len(self.atms)} ATM(s) found.", self.logs_box)

        for atm in self.atms:
            self.tree.insert("", "end", values=(atm["ip"], atm["port"], atm["protocol"]))

    def scan_bluetooth(self):
        try:
            scanner = btle.Scanner()
            devices = scanner.scan(self.scan_duration)
            for dev in devices:
                self.atms.append({"ip": dev.addr, "port": "Bluetooth", "protocol": "BLE"})
        except Exception as e:
            logging.error(f"Bluetooth scan failed: {e}")

    def scan_wifi(self):
        try:
            result = subprocess.run(["iwlist", "wlan0", "scan"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode("utf-8")
            for line in output.split("\n"):
                if "ESSID" in line:
                    self.atms.append({"ip": line.split('"')[1], "port": "Wi-Fi", "protocol": "802.11"})
        except Exception as e:
            logging.error(f"Wi-Fi scan failed: {e}")

    def exploit_atm(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Error", "No ATM selected.")
            return

        atm = self.tree.item(selected[0])["values"]
        ip = atm[0]
        self.update_ui(f"Exploiting ATM at {ip}...", self.result_box)

        result = self.atm_exploit(ip)
        self.update_ui(result, self.result_box)

    def atm_exploit(self, ip):
        try:
            return f"ATM at {ip} exploited successfully!"
        except Exception as e:
            logging.error(f"Exploit failed for {ip}: {e}")
            return f"Exploit failed for {ip}."

if __name__ == "__main__":
    root = Tk()
    app = ATMExploitTool(root)
    root.mainloop()











