# Web Recon Tool

## Overview

The **Web Recon Tool** is a Python-based script designed to perform a comprehensive analysis of a given domain. It includes functionalities for WHOIS lookups, DNS resolution, HTTP header analysis, SSL certificate inspection, port scanning, response time measurement, security header checks, and domain age verification. This tool is useful for web security assessments and educational purposes.

## Features

- **WHOIS Lookup**: Retrieve registration details of the domain.
- **DNS Lookup**: Find the IP addresses associated with the domain.
- **HTTP Header Analysis**: Inspect HTTP response headers for security and performance-related information.
- **Website Crawling**: Extract all hyperlinks from the target website.
- **SSL Certificate Information**: Get details about the SSL certificate for the domain.
- **Open Port Scanning**: Identify open ports on the server.
- **Response Time Measurement**: Measure the time taken to respond to HTTP requests.
- **Security Header Checks**: Check for essential security headers.
- **Domain Age Verification**: Determine the creation date of the domain.
- **Image Scraping**: Extract image sources from the website.

## Requirements

- Python 3.x
- Libraries:
  - `requests`
  - `python-whois`
  - `beautifulsoup4`
  - `dnspython`

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/web_r_recon.git
   cd web_r_recon


2. Install the required libraries:

   ```bash
   pip install requests python-whois beautifulsoup4 dnspython
   ```

## Usage

Run the script:

```bash
python3 web_r_recon.py
```

Enter a domain to scan when prompted. Type `done` when you finish entering domains.

An HTML report will be generated for each domain scanned, containing the results of the analysis.

## Example

```bash
Enter a domain to scan (or 'done' to finish): example.com
Enter a domain to scan (or 'done' to finish): done
```

## Output

The output will be saved in an HTML file named `example.com_report.html` in the current directory, containing detailed information about the scans performed.

## Contributing

Feel free to fork the repository and submit pull requests for any improvements or new features.
```

### How to Use This
1. Replace `yourusername` in the clone URL with your actual GitHub username.
2. Save this content as `README.md` in your repository.
3. Commit and push the changes to GitHub.

If you need any further modifications or additions, just let me know!
