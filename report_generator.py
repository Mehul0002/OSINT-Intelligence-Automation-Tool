import json
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        pass

    def generate_json(self, data, filename):
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

    def generate_html(self, data, filename):
        html_content = f"""
        <html>
        <head><title>OSINT Report</title></head>
        <body>
        <h1>OSINT Intelligence Report</h1>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <pre>{json.dumps(data, indent=4)}</pre>
        </body>
        </html>
        """
        with open(filename, 'w') as f:
            f.write(html_content)

    def generate_pdf(self, data, filename):
        c = canvas.Canvas(filename, pagesize=letter)
        c.drawString(100, 750, "OSINT Intelligence Report")
        c.drawString(100, 730, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y = 700
        for key, value in data.items():
            c.drawString(100, y, f"{key}: {value}")
            y -= 20
        c.save()
