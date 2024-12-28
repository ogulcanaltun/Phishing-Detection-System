import requests
from urllib.parse import urlparse
from colorama import Fore, Style
import socket



def is_shortened_url(url):
    """
    Check if the given URL is a shortened URL by analyzing its domain.
    """
    shortened_domains = [
        "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", 
        "is.gd", "buff.ly", "adf.ly", "lnkd.in"
    ]
    parsed_url = urlparse(url)
    return parsed_url.netloc in shortened_domains

def check_redirection(url):
    """
    Check if the URL redirects to another URL by following HTTP headers.
    """
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        return response.url != url
    except requests.RequestException:
        return False

def track_ip_domain(url):
    """
    Retrieve the IP address of the URL's domain.
    """
    try:
        parsed_url = urlparse(url)
        ip = socket.gethostbyname(parsed_url.netloc)
        return ip
    except socket.gaierror:
        return "Could not resolve IP"

def google_safe_browsing_check(url, api_key):
    """
    Check if the URL is flagged by Google Safe Browsing.
    """
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    headers = {"Content-Type": "application/json"}
    payload = {
        "client": {
            "clientId": "phishing-detection-system",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(api_url, headers=headers, json=payload, params={"key": api_key}, timeout=10)
        if response.status_code == 200:
            result = response.json()
            return "Unsafe" if result.get("matches") else "Safe"
        else:
            return f"Error: {response.status_code}"
    except requests.RequestException:
        return "Check Failed"

def perform_url_checks(url, google_api_key):
    """
    Perform all the necessary checks for the given URL.
    """
    print(f"{Fore.CYAN}Performing checks for URL: {Fore.YELLOW}{url}{Style.RESET_ALL}\n")
    
    checks = {}

    # Shortened URL Check
    checks["Shortened URL"] = "Yes" if is_shortened_url(url) else "No"
    print(f"{Fore.MAGENTA}Shortened URL Check: {Fore.GREEN if checks['Shortened URL'] == 'No' else Fore.RED}{checks['Shortened URL']}{Style.RESET_ALL}")
    
    # Redirection Check
    checks["Redirection"] = "Yes" if check_redirection(url) else "No"
    print(f"{Fore.MAGENTA}Redirection Check: {Fore.GREEN if checks['Redirection'] == 'No' else Fore.RED}{checks['Redirection']}{Style.RESET_ALL}")
    
    # Tracking IP Domain Check
    ip = track_ip_domain(url)
    checks["Tracking IP Domain"] = ip
    print(f"{Fore.MAGENTA}Tracking IP Domain: {Fore.YELLOW}{ip}{Style.RESET_ALL}")
    
    # Google Safe Browsing Check
    checks["Google Safe Browsing"] = google_safe_browsing_check(url, google_api_key)
    print(f"{Fore.MAGENTA}Google Safe Browsing Check: {Fore.GREEN if checks['Google Safe Browsing'] == 'Safe' else Fore.RED}{checks['Google Safe Browsing']}{Style.RESET_ALL}")
    
    return checks
