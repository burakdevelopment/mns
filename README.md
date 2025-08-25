# MNS: Web Vulnerability Scanner

![Version](https://img.shields.io/badge/version-v2.0-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![Python](https://img.shields.io/badge/python-3.8+-brightgreen.svg) ![Platform](https://img.shields.io/badge/platform-Linux%20|%20Windows%20(WSL)-orange.svg)

**MNS** is a lightweight, fast, and driverless web vulnerability scanner for identifying security issues in websites, including WAF detection, SQL Injection, Reflected XSS, and File Inclusion. It uses requests-based crawling to discover forms and links, supports WAF bypass techniques, and generates detailed reports.

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
MNS is designed for penetration testers, cybersecurity enthusiasts, and developers to assess website security. It identifies:

- Web Application Firewalls (WAF)
- SQL Injection (including Error-based, Union-based, and Blind Time-based)
- Reflected Cross-Site Scripting (XSS)
- Local & Remote File Inclusion (LFI/RFI)

The tool focuses on static and dynamic form discovery via crawling, payload testing with WAF bypass variants, and report generation for analysis.

---

## ✨ Key Features
- ⚡ **WAF Detection & Bypass:** Detects common WAFs with basic tests and applies bypass methods such as URL encoding, double encoding, case tampering, and SQL comment injection.  
- 💥 **SQL Injection Detection:** Supports error-based, union-based, and blind time-based SQL injection with intelligent payload variants.  
- 💻 **XSS Detection:** Tests for Reflected XSS vulnerabilities in forms and parameters.  
- 🕸️ **Crawling:** Requests and BeautifulSoup-powered crawling to discover forms and links without Selenium.  
- 🖥️ **File Inclusion Testing:** Checks for local and remote file inclusion vulnerabilities.  
- 🌐 **Proxy Support:** Supports HTTP proxies for anonymity.  
- 💾 **Report Generation:** Outputs detailed JSON, HTML, and CSV reports with graphs for vulnerability counts (requires `pandas` and `matplotlib`).  
- 🏗️ **Extensible & Modular:** Payloads can be extended via `payloads.json`.  
- ⚡ **Multi-threading:** ThreadPoolExecutor for fast, concurrent vulnerability testing.  
- 🖌️ **CLI & Colored Output:** Interactive command-line interface with `colorama` for enhanced readability.  

---

## ⚠️ Legal and Ethical Disclaimer
> **DISCLAIMER:** This tool is intended for **educational purposes only** and for performing security audits on websites and networks you are **legally authorized to test**. Using this tool on systems without permission is illegal and may lead to serious legal consequences. The developer is **not responsible for any misuse**. **Use responsibly.**

---

## 🚀 Installation

### Prerequisites
- Python 3.8+
- `pip` for Python package management
- Required Python packages: `requests`, `beautifulsoup4`, `colorama`, `pandas` *(optional for reports)*, `matplotlib` *(optional for graphs)*

### Installation on Linux (Debian/Ubuntu)
```bash
sudo apt update && sudo apt install -y python3 python3-pip git
git clone https://github.com/burakdevelopment/mns
cd mns
pip install -r requirements.txt
```
### Command-Line Options

Option,Description
- --url,Target URL (required)
- --tests,"Comma-separated tests: sql,xss,csrf,idor,command,file (default: all)"
- --waf,Detect WAF and attempt bypass
- --ssl,Scan SSL certificate info
- --proxy,Set proxy URL (HTTP/SOCKS)
- --depth,Crawl depth (default: 2)
- --threads,Number of concurrent threads (default: 5)
- --report,"Generate report in JSON, HTML, CSV formats"

## 🛠️ Usage
```bash
python mns.py --url https://yourttargetrizz.com --waf --tests sql,xss,file --report 
```

## 🤝 Contributing
Contributions make the open-source community an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**. Feel free to fork the repo and submit a pull request. For bug reports or feature requests, please open an "Issue".

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License
This project is distributed under the MIT License. See the `LICENSE` file for more information.
