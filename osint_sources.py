import urllib.parse
import re
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, carrier
import requests

def analyze_email(email):
    """
    Analyzes an email address for syntax and deliverability.
    """
    results = {}

    # Syntax check
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    results['valid_syntax'] = bool(re.match(email_regex, email))

    # MX record check
    if results['valid_syntax']:
        domain = email.split('@')[1]
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            results['has_mx_records'] = len(mx_records) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            results['has_mx_records'] = False
    else:
        results['has_mx_records'] = False

    return results

def analyze_phone(phone):
    """
    Analyzes a phone number for validity, country, and carrier.
    """
    results = {}
    try:
        parsed_number = phonenumbers.parse(phone, None)
        results['is_valid'] = phonenumbers.is_valid_number(parsed_number)

        if results['is_valid']:
            results['country'] = geocoder.description_for_number(parsed_number, "en")
            results['carrier'] = carrier.name_for_number(parsed_number, "en")
        else:
            results['country'] = "Unknown"
            results['carrier'] = "Unknown"

    except phonenumbers.phonenumberutil.NumberParseException:
        results['is_valid'] = False
        results['country'] = "Unknown"
        results['carrier'] = "Unknown"

    return results

def generate_google_dorks(name, email, phone):
    """
    Generates a list of Google dork URLs for the given name, email, and phone.
    """
    dorks = []

    if name:
        query = f'"{name}"'
        dorks.append(f'https://www.google.com/search?q={urllib.parse.quote_plus(query)}')

        query = f'filetype:pdf "{name}"'
        dorks.append(f'https://www.google.com/search?q={urllib.parse.quote_plus(query)}')

        query = f'site:linkedin.com "{name}"'
        dorks.append(f'https://www.google.com/search?q={urllib.parse.quote_plus(query)}')

    if email:
        query = f'"{email}"'
        dorks.append(f'https://www.google.com/search?q={urllib.parse.quote_plus(query)}')

        query = f'intext:"{email}"'
        dorks.append(f'https://www.google.com/search?q={urllib.parse.quote_plus(query)}')

    if phone:
        query = f'"{phone}"'
        dorks.append(f'https://www.google.com/search?q={urllib.parse.quote_plus(query)}')

    return dorks

def search_open_sanctions(name, api_key):
    """
    Searches the Open Sanctions API for a given name.
    """
    url = f"https://api.opensanctions.org/search/default?q={urllib.parse.quote_plus(name)}"
    headers = {
        "Authorization": f"ApiKey {api_key}"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error calling Open Sanctions API: {e}")
        return None

def search_shodan(ip_address, api_key):
    """
    Searches the Shodan API for a given IP address.
    """
    url = f"https://api.shodan.io/shodan/host/{ip_address}?key={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error calling Shodan API: {e}")
        return None
