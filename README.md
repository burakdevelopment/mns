# MNS: Multi Network & Web Security Scanner Tool

![Version](https://img.shields.io/badge/version-v2.0-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![Python](https://img.shields.io/badge/python-3.8+-brightgreen.svg) ![Platform](https://img.shields.io/badge/platform-Linux%20|%20Windows%20(WSL)-orange.svg)

**MNS** is a comprehensive multi-purpose tool for scanning websites and networks to identify a wide range of security vulnerabilities including WAFs, SSL issues, SQL Injection, XSS, CSRF, IDOR, Command Injection, and File Inclusion. It supports modern web applications with AJAX, DOM/JS crawling, and advanced WAF bypass techniques.

---

## 📑 Table of Contents
- [Purpose of the Tool](#-purpose-of-the-tool)
- [Key Features](#-key-features)
- [Legal and Ethical Disclaimer](#️-legal-and-ethical-disclaimer)
- [Installation](#-installation)
  - [Prerequisites](#prerequisites)
  - [Installation on Linux (Debian/Ubuntu)](#installation-on-linux-debianubuntu)
  - [Installation on Windows (Recommended via WSL)](#installation-on-windows-recommended-via-wsl)
- [Usage](#️-usage)
  - [First Run](#first-run)
  - [Command-Line Options](#command-line-options)
- [Example Output](#example-output)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Purpose of the Tool
MNS is designed for penetration testers, cybersecurity enthusiasts, and developers to comprehensively assess website and network security. It identifies:

- Web Application Firewalls (WAF) and supports bypass techniques
- SSL/TLS certificate issues
- SQL Injection (including Blind Boolean & Time-based)
- Cross-Site Scripting (Reflected, Stored, DOM)
- CSRF weaknesses
- IDOR / Insecure Direct Object References
- Command Injection
- Local & Remote File Inclusion (LFI/RFI)

The tool also handles modern web applications with AJAX endpoints, JS-generated DOM elements, and API responses, providing detailed reports for analysis.

---

## ✨ Key Features
- ⚡ **WAF Detection & Bypass:** Detects common WAFs like Cloudflare, Akamai, ModSecurity, Sucuri, and Fortinet. Includes bypass methods such as URL encoding, case tampering, and SQL comment injection.  
- 🔐 **SSL Certificate Analysis:** Retrieves SSL certificate details (issuer, validity, serial number, signature algorithm, expiration).  
- 💥 **SQL Injection Detection:** Supports error-based, union-based, blind boolean, and blind time-based SQL injection. Intelligent parameter typing improves payload selection.  
- 💻 **XSS Detection:** Tests for Reflected, Stored, and DOM-based XSS vulnerabilities in forms, inputs, and headers.  
- 🕸️ **AJAX & DOM Crawling:** Selenium-powered crawling to handle JS-generated links, forms, and dynamic content.  
- 🛡️ **CSRF & IDOR Testing:** Automatic CSRF token verification and IDOR testing via parameter manipulation.  
- 🖥️ **Command Injection & File Inclusion:** Tests for system command injection and local/remote file inclusion vulnerabilities.  
- 🌐 **Proxy & Anonymity Support:** Supports HTTP/SOCKS proxies, Tor, User-Agent rotation, and rate-limit bypass.  
- 💾 **Report Generation:** Outputs detailed JSON, HTML, and CSV reports with graphs for vulnerability counts.  
- 🏗️ **Extensible & Modular:** Payloads and security tests can easily be extended via `payloads.json`.  
- ⚡ **Multi-threading:** ThreadPoolExecutor for fast, concurrent vulnerability testing.  
- 🖌️ **CLI & Colored Output:** Interactive command-line interface with `colorama` for enhanced readability.

---

## ⚠️ Legal and Ethical Disclaimer
> **DISCLAIMER:** This tool is intended for **educational purposes only** and for performing security audits on websites and networks you are **legally authorized to test**. Using this tool on systems without permission is illegal and may lead to serious legal consequences. The developer is **not responsible for any misuse**. **Use responsibly.**

---

## 🚀 Installation

### Prerequisites
- Python 3.8+
- Google Chrome or Chromium (for Selenium DOM crawling)
- `pip` for Python package management
- Required Python packages: `requests`, `selenium`, `beautifulsoup4`, `colorama`, `pandas`, `matplotlib`

### Installation on Linux (Debian/Ubuntu)
```bash
sudo apt update && sudo apt install -y python3 python3-pip git chromium-driver
git clone https://github.com/burakdevelopment/mns
cd mns
pip install -r requirements.txt
```
## 🛠️ Usage
```bash
python3 mns.py --url https://target.com --waf --ssl --report
```

### Command-Line Options

Option,Description
--url,Target URL (required)
--tests,"Comma-separated tests: sql,xss,csrf,idor,command,file (default: all)"
--waf,Detect WAF and attempt bypass
--ssl,Scan SSL certificate info
--proxy,Set proxy URL (HTTP/SOCKS)
--depth,Crawl depth (default: 2)
--threads,Number of concurrent threads (default: 5)
--report,"Generate report in JSON, HTML, CSV formats"

## 🤝 Contributing
Contributions make the open-source community an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**. Feel free to fork the repo and submit a pull request. For bug reports or feature requests, please open an "Issue".

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License
This project is distributed under the MIT License. See the `LICENSE` file for more information.
