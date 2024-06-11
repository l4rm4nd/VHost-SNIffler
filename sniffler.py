import ssl
import socket
import http.client
import argparse
import json
import requests
from collections import defaultdict
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from ipwhois import IPWhois

# Initialize colorama
init(autoreset=True)

def extract_title(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    title_tag = soup.find('title')
    return title_tag.string if title_tag else 'No Title'

def get_certificate_info(cert):
    try:
        issuer = dict(x[0] for x in cert['issuer'])
        return issuer.get('organizationName', 'Unknown')
    except Exception as e:
        return f"Error extracting certificate info: {e}"

def get_as_info(ip_address):
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap()
        asn = results.get('asn', 'Unknown ASN')
        asn_description = results.get('asn_description', 'Unknown AS Description')
        return f"AS{asn}, {asn_description}"
    except Exception as e:
        return f"Error retrieving AS info: {e}"

def print_colored_output(protocol, hostname, status_code, title, cert_info, as_info, ip_address, redirect_location=None):
    if status_code in [401, 403]:
        color = Fore.YELLOW
    elif 200 <= status_code < 300:
        color = Fore.GREEN
    elif 300 <= status_code < 400:
        color = Fore.BLUE
    elif 400 <= status_code < 500:
        color = Fore.MAGENTA
    else:
        color = Fore.RED

    redirect_info = f" [Redirects to: {redirect_location}]" if redirect_location else ""
    print(f"{color}{protocol}://{hostname} [{status_code}] [{title}] [{cert_info}] [{as_info}] [{ip_address}]{redirect_info}{Style.RESET_ALL}")

def is_port_open(ip, port):
    try:
        sock = socket.create_connection((ip, port), timeout=4)
        sock.close()
        return True
    except (socket.timeout, socket.error):
        return False

def test_vhosts(ip_address, hostnames):
    results = []

    for hostname in hostnames:
        try:
            # Handle HTTPS manually to extract certificate info
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_OPTIONAL

            conn = socket.create_connection((ip_address, 443), timeout=4)
            ssl_conn = context.wrap_socket(conn, server_hostname=hostname)

            cert = ssl_conn.getpeercert()
            cert_info = get_certificate_info(cert)

            http_conn = http.client.HTTPSConnection(ip_address, context=context)
            http_conn.sock = ssl_conn
            http_conn.request("GET", "/", headers={"Host": hostname})
            response = http_conn.getresponse()
            html_content = response.read().decode('utf-8')
            title = extract_title(html_content)

            as_info = get_as_info(ip_address)
            redirect_location = response.getheader('Location') if 300 <= response.status < 400 else None
            print_colored_output('https', hostname, response.status, title, cert_info, as_info, ip_address, redirect_location)

            results.append({
                "protocol": 'https',
                "hostname": hostname,
                "status_code": response.status,
                "title": title,
                "cert_info": cert_info,
                "as_info": as_info,
                "ip_address": ip_address,
                "redirect_location": redirect_location
            })

        except (ssl.SSLError, socket.timeout, http.client.HTTPException) as e:
            results.append({
                "protocol": 'https',
                "hostname": hostname,
                "error": f"Error: {e}"
            })

    return results

def main():
    parser = argparse.ArgumentParser(description="Test for virtual hosts on IPv4 addresses using a wordlist.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="The target IPv4 address.")
    group.add_argument("--ip_file", help="The file containing the target IPv4 addresses.")
    domain_group = parser.add_mutually_exclusive_group(required=True)
    domain_group.add_argument("--domain", help="The target domain.")
    domain_group.add_argument("--domain_file", help="The file containing the target domains.")
    parser.add_argument("--wordlist", required=True, help="The path to the wordlist file.")
    args = parser.parse_args()

    with open(args.wordlist, 'r') as wordlist_file:
        words = wordlist_file.read().splitlines()

    if args.domain_file:
        with open(args.domain_file, 'r') as domain_file:
            domains = domain_file.read().splitlines()
    else:
        domains = [args.domain]

    if args.ip_file:
        with open(args.ip_file, 'r') as ip_file:
            ip_addresses = ip_file.read().splitlines()
    else:
        ip_addresses = [args.ip]

    # Check if port 443 is open on the IPs
    valid_ips = [ip for ip in ip_addresses if is_port_open(ip, 443)]
    
    all_results = defaultdict(list)
    
    for ip_address in valid_ips:
        for domain in domains:
            hostnames = []
            for word in words:
                try:
                    hostname = f"{word}.{domain}"
                    if not hostname or hostname.startswith('.') or len(hostname) > 255:
                        raise ValueError("Invalid hostname")
                    hostnames.append(hostname)
                except ValueError:
                    continue

            results = test_vhosts(ip_address, hostnames)
            for result in results:
                status_code = result.get("status_code", "error")
                all_results[status_code].append(result)

    # Print results grouped by status codes as JSON
    print("------------------------------------------------------------")
    print()
    print(json.dumps(all_results, indent=4))

if __name__ == "__main__":
    main()
