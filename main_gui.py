import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from modules.email_osint import EmailOSINT
from modules.domain_osint import DomainOSINT
from modules.ip_osint import IPOSINT
from modules.social_osint import SocialOSINT
from modules.breach_osint import BreachOSINT
from modules.graph_visualizer import GraphVisualizer
from reports.report_generator import ReportGenerator

class OSINTToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("OSINT Intelligence Automation Tool")
        self.root.geometry("800x600")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.create_dashboard()
        self.create_email_tab()
        self.create_domain_tab()
        self.create_ip_tab()
        self.create_social_tab()
        self.create_breach_tab()
        self.create_graph_tab()
        self.create_report_tab()

        self.progress = ttk.Progressbar(root, orient="horizontal", mode="determinate")
        self.progress.pack(fill=tk.X, padx=10, pady=5)

    def create_dashboard(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Dashboard")

        ttk.Label(frame, text="Input:").grid(row=0, column=0, padx=10, pady=10)
        self.input_entry = ttk.Entry(frame, width=50)
        self.input_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(frame, text="Type:").grid(row=1, column=0, padx=10, pady=10)
        self.type_var = tk.StringVar()
        self.type_combo = ttk.Combobox(frame, textvariable=self.type_var, values=["Email", "Domain", "IP", "Username"])
        self.type_combo.grid(row=1, column=1, padx=10, pady=10)

        self.start_button = ttk.Button(frame, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=2, column=0, columnspan=2, pady=10)

        self.results_text = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.results_text.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    def create_email_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Email Intelligence")

        ttk.Label(frame, text="Email:").grid(row=0, column=0, padx=10, pady=10)
        self.email_entry = ttk.Entry(frame, width=50)
        self.email_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Button(frame, text="Scan Email", command=self.scan_email).grid(row=1, column=0, columnspan=2, pady=10)

        self.email_results = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.email_results.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def create_domain_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Domain Intelligence")

        ttk.Label(frame, text="Domain:").grid(row=0, column=0, padx=10, pady=10)
        self.domain_entry = ttk.Entry(frame, width=50)
        self.domain_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Button(frame, text="Scan Domain", command=self.scan_domain).grid(row=1, column=0, columnspan=2, pady=10)

        self.domain_results = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.domain_results.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def create_ip_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="IP Intelligence")

        ttk.Label(frame, text="IP Address:").grid(row=0, column=0, padx=10, pady=10)
        self.ip_entry = ttk.Entry(frame, width=50)
        self.ip_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Button(frame, text="Scan IP", command=self.scan_ip).grid(row=1, column=0, columnspan=2, pady=10)

        self.ip_results = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.ip_results.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def create_social_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Social Profile Search")

        ttk.Label(frame, text="Username:").grid(row=0, column=0, padx=10, pady=10)
        self.social_entry = ttk.Entry(frame, width=50)
        self.social_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Button(frame, text="Search Profiles", command=self.search_social).grid(row=1, column=0, columnspan=2, pady=10)

        self.social_results = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.social_results.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def create_breach_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Breach Analysis")

        ttk.Label(frame, text="Email:").grid(row=0, column=0, padx=10, pady=10)
        self.breach_entry = ttk.Entry(frame, width=50)
        self.breach_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Button(frame, text="Check Breaches", command=self.check_breaches).grid(row=1, column=0, columnspan=2, pady=10)

        self.breach_results = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.breach_results.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def create_graph_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Graph Visualization")

        ttk.Button(frame, text="Generate Graph", command=self.generate_graph).grid(row=0, column=0, pady=10)

        self.graph_canvas = tk.Canvas(frame, width=600, height=400, bg="white")
        self.graph_canvas.grid(row=1, column=0, padx=10, pady=10)

    def create_report_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Report Generator")

        ttk.Label(frame, text="Report Format:").grid(row=0, column=0, padx=10, pady=10)
        self.report_format = tk.StringVar(value="JSON")
        ttk.Combobox(frame, textvariable=self.report_format, values=["JSON", "HTML", "PDF"]).grid(row=0, column=1, padx=10, pady=10)

        ttk.Button(frame, text="Generate Report", command=self.generate_report).grid(row=1, column=0, columnspan=2, pady=10)

        self.report_results = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.report_results.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def start_scan(self):
        input_val = self.input_entry.get().strip()
        scan_type = self.type_var.get()

        if not input_val or not scan_type:
            messagebox.showerror("Error", "Please enter input and select type.")
            return

        self.progress['value'] = 0
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Scanning...\n")

        threading.Thread(target=self.run_scan, args=(input_val, scan_type)).start()

    def run_scan(self, input_val, scan_type):
        try:
            if scan_type == "Email":
                osint = EmailOSINT()
                results = osint.scan(input_val)
            elif scan_type == "Domain":
                osint = DomainOSINT()
                results = osint.scan(input_val)
            elif scan_type == "IP":
                osint = IPOSINT()
                results = osint.scan(input_val)
            elif scan_type == "Username":
                osint = SocialOSINT()
                results = osint.scan(input_val)
            else:
                results = "Invalid scan type"

            self.progress['value'] = 100
            self.results_text.insert(tk.END, str(results))
        except Exception as e:
            self.results_text.insert(tk.END, f"Error: {str(e)}")

    def scan_email(self):
        email = self.email_entry.get().strip()
        if not email:
            messagebox.showerror("Error", "Please enter an email.")
            return

        self.email_results.delete(1.0, tk.END)
        self.email_results.insert(tk.END, "Scanning...\n")

        threading.Thread(target=self.run_email_scan, args=(email,)).start()

    def run_email_scan(self, email):
        try:
            osint = EmailOSINT()
            results = osint.scan(email)
            self.email_results.insert(tk.END, str(results))
        except Exception as e:
            self.email_results.insert(tk.END, f"Error: {str(e)}")

    def scan_domain(self):
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain.")
            return

        self.domain_results.delete(1.0, tk.END)
        self.domain_results.insert(tk.END, "Scanning...\n")

        threading.Thread(target=self.run_domain_scan, args=(domain,)).start()

    def run_domain_scan(self, domain):
        try:
            osint = DomainOSINT()
            results = osint.scan(domain)
            self.domain_results.insert(tk.END, str(results))
        except Exception as e:
            self.domain_results.insert(tk.END, f"Error: {str(e)}")

    def scan_ip(self):
        ip = self.ip_entry.get().strip()
        if not ip:
            messagebox.showerror("Error", "Please enter an IP address.")
            return

        self.ip_results.delete(1.0, tk.END)
        self.ip_results.insert(tk.END, "Scanning...\n")

        threading.Thread(target=self.run_ip_scan, args=(ip,)).start()

    def run_ip_scan(self, ip):
        try:
            osint = IPOSINT()
            results = osint.scan(ip)
            self.ip_results.insert(tk.END, str(results))
        except Exception as e:
            self.ip_results.insert(tk.END, f"Error: {str(e)}")

    def search_social(self):
        username = self.social_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Please enter a username.")
            return

        self.social_results.delete(1.0, tk.END)
        self.social_results.insert(tk.END, "Searching...\n")

        threading.Thread(target=self.run_social_search, args=(username,)).start()

    def run_social_search(self, username):
        try:
            osint = SocialOSINT()
            results = osint.scan(username)
            self.social_results.insert(tk.END, str(results))
        except Exception as e:
            self.social_results.insert(tk.END, f"Error: {str(e)}")

    def check_breaches(self):
        email = self.breach_entry.get().strip()
        if not email:
            messagebox.showerror("Error", "Please enter an email.")
            return

        self.breach_results.delete(1.0, tk.END)
        self.breach_results.insert(tk.END, "Checking...\n")

        threading.Thread(target=self.run_breach_check, args=(email,)).start()

    def run_breach_check(self, email):
        try:
            osint = BreachOSINT()
            results = osint.scan(email)
            self.breach_results.insert(tk.END, str(results))
        except Exception as e:
            self.breach_results.insert(tk.END, f"Error: {str(e)}")

    def generate_graph(self):
        # Placeholder for graph generation
        self.graph_canvas.create_text(300, 200, text="Graph visualization placeholder")

    def generate_report(self):
        format_type = self.report_format.get()
        # Placeholder for report generation
        self.report_results.delete(1.0, tk.END)
        self.report_results.insert(tk.END, f"Report generated in {format_type} format.\nPlaceholder content.")
