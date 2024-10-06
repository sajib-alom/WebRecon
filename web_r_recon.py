import requests
import whois
import socket
import ssl
from bs4 import BeautifulSoup
import dns.resolver  # For DNS lookups

def whois_lookup(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        return f"WHOIS lookup error: {e}"

def dns_lookup(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')  # A records
        return [ip.address for ip in result]
    except Exception as e:
        return f"Error in DNS lookup: {e}"

def get_headers(url):
    response = requests.get(url)
    return dict(response.headers)

def crawl_website(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    return [link.get('href') for link in soup.find_all('a')]

def ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert()
    except Exception as e:
        return f"SSL Info Error: {e}"

def port_scan(domain):
    open_ports = []
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return f"Unable to resolve domain: {domain}"
    
    for port in range(1, 1025):  # Scan first 1024 ports
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    return open_ports

def measure_response_time(url):
    response = requests.get(url)
    return response.elapsed.total_seconds()

def check_security_headers(url):
    headers = get_headers(url)
    return {header: headers.get(header) for header in ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]}

def domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info.creation_date
    except Exception as e:
        return f"Domain Age Error: {e}"

def image_scraper(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    return [img.get('src') for img in soup.find_all('img')]

def generate_html_report(domain, results):
    with open(f"{domain}_report.html", "w") as f:
        f.write("<html><body>")
        f.write(f"<h1>Scan Report for {domain}</h1>")
        for key, value in results.items():
            f.write(f"<h2>{key}</h2>")
            f.write(f"<pre>{value}</pre>")
        f.write("</body></html>")

def run_scans(domain):
    url = f"http://{domain}"
    print(f"[*] Running scans for: {url}")

    # Initialize results dictionary
    results = {}

    try:
        results["WHOIS"] = whois_lookup(domain)
    except Exception as e:
        print(f"[!] WHOIS lookup error: {e}")

    try:
        results["DNS Lookup"] = dns_lookup(domain)
    except Exception as e:
        print(f"[!] DNS lookup error: {e}")

    try:
        results["HTTP Headers"] = get_headers(url)
    except Exception as e:
        print(f"[!] HTTP headers error: {e}")

    try:
        results["Crawl Results"] = crawl_website(url)
    except Exception as e:
        print(f"[!] Crawl error: {e}")

    try:
        results["SSL Info"] = ssl_info(domain)
    except Exception as e:
        print(f"[!] SSL info error: {e}")

    try:
        results["Open Ports"] = port_scan(domain)
    except Exception as e:
        print(f"[!] Port scan error: {e}")

    try:
        results["Response Time"] = measure_response_time(url)
    except Exception as e:
        print(f"[!] Response time error: {e}")

    try:
        results["Security Headers"] = check_security_headers(url)
    except Exception as e:
        print(f"[!] Security headers error: {e}")

    try:
        results["Domain Age"] = domain_age(domain)
    except Exception as e:
        print(f"[!] Domain age error: {e}")

    try:
        results["Image Links"] = image_scraper(url)
    except Exception as e:
        print(f"[!] Image scraper error: {e}")

    # Generate HTML report
    generate_html_report(domain, results)
    print(f"[+] Scanning completed for {domain}.")

def main():
    domains = []
    while True:
        domain = input("Enter a domain to scan (or 'done' to finish): ")
        if domain.lower() == 'done':
            break
        domains.append(domain)

    for domain in domains:
        run_scans(domain)

if __name__ == "__main__":
    main()
