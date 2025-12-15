import requests
import os
from dotenv import load_dotenv

load_dotenv()

class HaveIBeenPwnedAPI:
    def __init__(self):
        self.api_key = os.getenv('HAVEIBEENPWNED_API_KEY')
        self.base_url = 'https://haveibeenpwned.com/api/v3'

    def check_breaches(self, email):
        headers = {
            'hibp-api-key': self.api_key,
            'User-Agent': 'OSINT-Tool'
        }
        response = requests.get(f'{self.base_url}/breachedaccount/{email}', headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return "No breaches found"
        else:
            raise Exception(f"API Error: {response.status_code}")
