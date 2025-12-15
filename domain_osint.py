import whois
from api.dns_api import DNSAPI

class DomainOSINT:
    def __init__(self):
        self.dns_api = DNSAPI()

    def scan(self, domain):
        results = {}
        results['domain'] = domain

        # WHOIS information
        try:
            w = whois.whois(domain)
            results['whois'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers
            }
        except Exception as e:
            results['whois'] = f"Error: {str(e)}"

        # DNS records
        try:
            a_records = self.dns_api.get_a_records(domain)
            results['a_records'] = a_records
        except Exception as e:
            results['a_records'] = f"Error: {str(e)}"

        try:
            ns_records = self.dns_api.get_ns_records(domain)
            results['ns_records'] = ns_records
        except Exception as e:
            results['ns_records'] = f"Error: {str(e)}"

        return results
