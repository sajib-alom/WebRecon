# Web Recon Tool

## Overview

Web Recon Tool is a Python-based script designed for domain reconnaissance. It gathers various information about a specified domain, including WHOIS data, DNS records, SSL certificates, open ports, response times, and more. The results are presented in a visually appealing HTML report, making it easier to understand the data collected.

## Features

- **WHOIS Lookup**: Retrieves registration information about the domain.
- **DNS Lookup**: Resolves the domain to its corresponding IP address.
- **SSL Information**: Displays SSL certificate details.
- **Port Scanning**: Identifies open ports on the server.
- **Response Time Measurement**: Measures the time taken to get a response from the server.
- **Security Headers Check**: Checks for common security headers.
- **Image Links Extraction**: Gathers image links from the website.
- **HTML Report Generation**: Outputs the results in an easy-to-read HTML format.

## Requirements

Make sure to have the following Python packages installed:

```bash
pip install requests python-whois beautifulsoup4 dnspython
