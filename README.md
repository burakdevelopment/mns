# MNS: Multi Network & Web Security Scanner Tool

![Version](https://img.shields.io/badge/version-v2.0-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg) ![Python](https://img.shields.io/badge/python-3.8+-brightgreen.svg) ![Platform](https://img.shields.io/badge/platform-Linux%20|%20Windows%20(WSL)-orange.svg)

**MNS** is a multi-purpose tool for scanning websites and networks to identify security vulnerabilities, including WAFs, SSL issues, SQL Injection, and XSS.

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
  - [Menu Options](#menu-options)
- [Example Output](#example-output)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Purpose of the Tool
MNS is developed for penetration testers, cybersecurity enthusiasts, and developers to assess website and network security. It detects:

- Web Application Firewalls (WAF)
- SSL certificate issues
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)

It allows quick detection of security issues and provides clear reports for further analysis.

---

## ✨ Key Features
- ⚡ **WAF Detection:** Identifies popular WAFs such as Cloudflare, Akamai, Sucuri, ModSecurity, Fortinet, and more by analyzing HTTP headers and response content.
- 🔐 **SSL Certificate Analysis:** Retrieves SSL certificate details including issuer, validity period, serial number, signature algorithm, and days until expiration.
- 💥 **SQL Injection Detection:** Tests URLs with common SQL payloads and reports potential vulnerabilities.
- 💻 **XSS Testing:** Checks for reflected XSS vulnerabilities using standard payloads in input parameters.
- 🖥️ **Command-Line Interface:** Easy-to-use prompts with colored outputs using the `colorama` library.
- 💾 **Extensible:** Additional payloads or security tests can be added easily.

---

## ⚠️ Legal and Ethical Disclaimer
> **DISCLAIMER:** This tool is intended for **educational purposes only** and for performing security audits on websites and networks you are **legally authorized to test**. Using this tool on systems without permission is illegal and may lead to serious legal consequences. The developer is not responsible for any misuse. **Use responsibly.**

---

## 🚀 Installation

### Prerequisites
- Python 3.8+
- `pip`
- `requests`
- `colorama`

### Installation on Linux (Debian/Ubuntu)
```bash
sudo apt update && sudo apt install -y python3 python3-pip git
git clone https://github.com/burakdevelopment/mns
cd mns
pip install -r requirements.txt

## 🤝 Contributing
Contributions make the open-source community an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**. Feel free to fork the repo and submit a pull request. For bug reports or feature requests, please open an "Issue".

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License
This project is distributed under the MIT License. See the `LICENSE` file for more information.
