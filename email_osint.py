import re
import dns.resolver
import requests
from api.haveibeenpwned_api import HaveIBeenPwnedAPI
from api.dns_api import DNSAPI

class EmailOSINT:
    def __init__(self):
        self.hibp_api = HaveIBeenPwnedAPI()
        self.dns_api = DNSAPI()

    def scan(self, email):
        results = {}
        results['email'] = email

        # Validate email format
        if not self.validate_email(email):
            return "Invalid email format."

        # Extract domain
        domain = email.split('@')[1]
        results['domain'] = domain

        # MX record lookup
        try:
            mx_records = self.dns_api.get_mx_records(domain)
            results['mx_records'] = mx_records
        except Exception as e:
            results['mx_records'] = f"Error: {str(e)}"

        # Breach check
        try:
            breaches = self.hibp_api.check_breaches(email)
            results['breaches'] = breaches
        except Exception as e:
            results['breaches'] = f"Error: {str(e)}"

        return results

    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
