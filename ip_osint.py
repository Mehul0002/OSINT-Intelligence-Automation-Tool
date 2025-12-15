import requests
from api.shodan_api import ShodanAPI

class IPOSINT:
    def __init__(self):
        self.shodan_api = ShodanAPI()

    def scan(self, ip):
        results = {}
        results['ip'] = ip

        # Geolocation
        try:
            geo = self.get_geolocation(ip)
            results['geolocation'] = geo
        except Exception as e:
            results['geolocation'] = f"Error: {str(e)}"

        # Shodan info
        try:
            shodan_info = self.shodan_api.get_ip_info(ip)
            results['shodan'] = shodan_info
        except Exception as e:
            results['shodan'] = f"Error: {str(e)}"

        return results

    def get_geolocation(self, ip):
        response = requests.get(f'http://ip-api.com/json/{ip}')
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country'),
                'region': data.get('regionName'),
                'city': data.get('city'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'asn': data.get('as')
            }
        else:
            raise Exception("Failed to get geolocation data")
