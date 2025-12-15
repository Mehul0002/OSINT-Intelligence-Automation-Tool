import shodan
import os
from dotenv import load_dotenv

load_dotenv()

class ShodanAPI:
    def __init__(self):
        self.api_key = os.getenv('SHODAN_API_KEY')
        self.api = shodan.Shodan(self.api_key) if self.api_key else None

    def get_ip_info(self, ip):
        if not self.api:
            raise Exception("Shodan API key not set")
        try:
            result = self.api.host(ip)
            return {
                'ip': result.get('ip_str'),
                'ports': result.get('ports', []),
                'hostnames': result.get('hostnames', []),
                'org': result.get('org'),
                'isp': result.get('isp'),
                'asn': result.get('asn'),
                'country': result.get('country_name'),
                'city': result.get('city'),
                'latitude': result.get('latitude'),
                'longitude': result.get('longitude')
            }
        except shodan.APIError as e:
            raise Exception(f"Shodan API Error: {str(e)}")
