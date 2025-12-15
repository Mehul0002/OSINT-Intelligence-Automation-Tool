import dns.resolver

class DNSAPI:
    def __init__(self):
        pass

    def get_mx_records(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = [str(rdata.exchange) for rdata in answers]
            return mx_records
        except Exception as e:
            raise Exception(f"DNS MX lookup failed: {str(e)}")

    def get_a_records(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            a_records = [str(rdata) for rdata in answers]
            return a_records
        except Exception as e:
            raise Exception(f"DNS A lookup failed: {str(e)}")

    def get_ns_records(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            ns_records = [str(rdata) for rdata in answers]
            return ns_records
        except Exception as e:
            raise Exception(f"DNS NS lookup failed: {str(e)}")
