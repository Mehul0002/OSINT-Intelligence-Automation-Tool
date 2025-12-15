import requests

class SocialOSINT:
    def __init__(self):
        self.platforms = {
            'GitHub': 'https://api.github.com/users/{}',
            'Twitter': 'https://twitter.com/{}',  # Note: Public profile check only, no scraping
            'Instagram': 'https://www.instagram.com/{}',  # Note: Public profile check only
            'LinkedIn': 'https://www.linkedin.com/in/{}',  # Note: Public profile check only
        }

    def scan(self, username):
        results = {}
        results['username'] = username

        for platform, url_template in self.platforms.items():
            try:
                url = url_template.format(username)
                response = requests.head(url, timeout=5)
                if response.status_code == 200:
                    results[platform] = f"Profile found: {url}"
                else:
                    results[platform] = "Profile not found or private"
            except Exception as e:
                results[platform] = f"Error: {str(e)}"

        return results
