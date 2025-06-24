# 🔍 Rebel OSINT Suite - Elite Intelligence Edition

Rebel OSINT Suite is a powerful, modular open-source intelligence (OSINT) platform built with Python and Flask. Designed for cyber security professionals, ethical hackers, and investigators, it allows deep investigation of usernames, domains, IPs, and profile images — all from a sleek web dashboard.

> 🧠 Built for investigation. Powered by automation. Inspired by rebels.

---

## 🚀 Features

- **Username Investigation** across 15+ social media platforms with advanced profile parsing
- **Data Breach Checks** via HaveIBeenPwned API
- **Email Discovery** using Hunter.io & domain scraping
- **Domain Intelligence**:
  - WHOIS, DNS, SSL Certificate, Tech Stack (BuiltWith)
  - Shodan/IPInfo/AbuseIPDB integration
- **Reputation Analysis** via VirusTotal & Google Safe Browsing
- **Security Headers Audit**
- **Reverse Image Search** using Google, Bing, and TinEye
- **Real-time Logs** & investigation timeline
- **Export Options**: JSON, CSV, TXT reports

---

## 🛠️ Tech Stack

- **Backend**: Python 3.10+, Flask
- **Frontend**: HTML, CSS (Retro Hacker Style)
- **Dependencies**: `shodan`, `whois`, `builtwith`, `tldextract`, `Pillow`, `exifread`, `requests`, `dnspython`, `beautifulsoup4`

---

## ⚙️ Installation

```bash
git clone https://github.com/Abdelrahmaneala/rebel_osint.git
cd rebel_osint
pip install -r requirements.txt
python app.py
```

Access the dashboard at: [https://localhost:5000](https://localhost:5000)

Default login:
```
Username: rebel
Password: hunter123
```

---

## 🔐 API Keys Setup

Set the following environment variables before launching the tool:

- `SHODAN_API_KEY`
- `VIRUSTOTAL_API_KEY`
- `GOOGLE_SAFE_BROWSING_API_KEY`
- `HUNTERIO_API_KEY`
- `HIBP_API_KEY`
- `IPINFO_API_KEY`
- `GOOGLE_API_KEY` and `GOOGLE_CSE_ID` *(for reverse image search)*

You can use a `.env` file or export them manually in your terminal.

---

## 📦 Output Examples

- **Social Media Profile Detection**
- **Detailed Breach Info & Impact Score**
- **SSL Certificate Validity & Domain Age**
- **Reverse Image Matches from Multiple Engines**
- **Security Headers Status**

---

## 📁 Export Formats

You can export your investigation results into:
- `JSON`: Full structured data
- `CSV`: Tabular summary
- `TXT`: Readable text report

---

## 🧪 Disclaimer

This tool is provided for **educational** and **authorized security testing** only.  
⚠️ **Do not use it without proper authorization.**

---

## 📫 Contact

Made with 💻 by [Abdelrahmaneala](https://github.com/Abdelrahmaneala)  
Feel free to fork, contribute, or open issues.

---

## 🧠 Inspired By

The power of OSINT, ethical hacking, and the curiosity to know more 🔎
