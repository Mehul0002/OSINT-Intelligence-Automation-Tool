🔍 OSINT Intelligence Automation Tool

The OSINT Intelligence Automation Tool is a Python-based GUI application designed to automate the collection and analysis of open-source intelligence (OSINT) data.
It helps security researchers, students, and analysts gather publicly available information in a legal, ethical, and structured manner.

✨ Features

📧 Email Intelligence

Email format validation

Domain extraction

MX record lookup

Data breach exposure check (HaveIBeenPwned API)

🌐 Domain Intelligence

WHOIS lookup

DNS record analysis

SSL certificate information

Passive subdomain enumeration

🌍 IP Intelligence

IP geolocation

ASN and ISP details

Open ports and services (Shodan API)

👤 Social Profile OSINT

Username availability checks

Public profile discovery (no login bypass)

🔗 Graph Visualization

Relationship mapping between emails, domains, IPs, and breaches

Interactive graph generation

📄 Report Generator

Export findings as PDF, HTML, or JSON

Structured and timestamped reports

🖥️ GUI Interface

User-friendly desktop GUI built with Tkinter / PyQt

Tab-based navigation

Real-time progress indicators

Structured result panels

🛠️ Tech Stack

Python 3

Tkinter / PyQt5

Requests & Asyncio

NetworkX & Matplotlib

Shodan API

HaveIBeenPwned API

python-whois

📂 Project Structure
OSINT-Intelligence-Automation-Tool/
│
├── gui/
│   └── main_gui.py
├── modules/
│   ├── email_osint.py
│   ├── domain_osint.py
│   ├── ip_osint.py
│   ├── social_osint.py
│   └── breach_osint.py
├── api/
│   ├── shodan_api.py
│   └── hibp_api.py
├── reports/
│   └── generated_reports/
├── utils/
│   └── graph_visualizer.py
├── .env.example
├── requirements.txt
└── README.md

⚙️ Installation
git clone https://github.com/your-username/OSINT-Intelligence-Automation-Tool.git
cd OSINT-Intelligence-Automation-Tool
pip install -r requirements.txt


Create a .env file and add your API keys:

SHODAN_API_KEY=your_key_here
HIBP_API_KEY=your_key_here


Run the application:

python gui/main_gui.py

⚠️ Legal & Ethical Disclaimer

This tool is intended only for educational, research, and defensive security purposes.
It gathers publicly available data only and does not perform hacking, exploitation, credential harvesting, or unauthorized access.

The user is fully responsible for complying with applicable laws and API terms of service.

🎓 Use Cases

Cybersecurity learning & research

Blue team & SOC investigations

Digital footprint analysis

Academic projects & demonstrations

⭐ Future Improvements

Web-based interface

Additional OSINT APIs

Dark mode GUI

Database storage

Timeline analysis
