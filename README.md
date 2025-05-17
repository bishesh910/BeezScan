# 🐝 BeezScan — Cross-Platform Local Vulnerability Scanner

BeezScan is a lightweight, vulnerability scanner that matches locally installed software against the official NIST CVE database (NVD). It supports Linux (Debian, RedHat, etc.), Windows, and macOS systems — with patch-aware intelligence to eliminate false positives.

---

## ✨ Features

- ✅ CVE database from NIST (JSON feeds)
- ✅ Package detection for:
  - Debian/Ubuntu (`dpkg`)
  - RHEL/CentOS/Rocky (`rpm`)
  - macOS (Homebrew + system apps)
  - Windows (KB updates)
- ✅ Patch-aware filtering:
  - Ubuntu (via Ubuntu CVE Tracker)
  - RedHat (via RedHat OVAL feeds)
  - Windows (via MSRC CVE-KB map)
- 📄 Beautiful PDF reports with:
  - Pie chart by severity
  - Vulnerability summary
  - Detailed grouped findings
- 🧪 Triage-ready: JSON output for future dashboard integration

---

## 📦 Installation

```bash
git clone https://github.com/bishesh910/BeezScan.git
cd BeezScan
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
````

---

## 🚀 Usage

### ✅ Step 1: Download & Import the Latest CVE Database

```bash
python update_cve_db.py
```

This downloads all NVD CVE JSON files, extracts them, and imports them into a local SQLite database (`data/cves.db`).

Manually download from [MSRC Export](https://msrc.microsoft.com/update-guide/export) and place it at `data/ms_kb_cve_map.csv`

---

### ✅ Step 2: Run the Scan

```bash
python run_beezscan.py
```

This:

* Detects your OS and installed packages
* Matches them against known CVEs
* Applies patch-awareness to reduce false positives
* Saves results to:

  * `results/scan_TIMESTAMP.json`
  * `results/BeezScan_Report_TIMESTAMP.pdf`

---

## 📊 Output

* **JSON**: Machine-readable scan results for automation
* **PDF**: Clean human-friendly report with:

  * Executive summary
  * Severity chart
  * Vulnerability breakdown by software

---

## 📁 Project Structure

```
beez_scanner/             → Core scanning logic (OS detection, CPE matching)
data/                     → CVE database, OVAL feeds, KB mappings
results/                  → Scan results (PDF, JSON)
scripts/                  → CLI utilities (reporter, scanner, importers)
templates/                → PDF report template + logo
run_beezscan.py           → Main user entrypoint
update_cve_db.py          → NVD download + SQLite import
requirements.txt          → Python dependencies
```

---

## 💡 Roadmap

* [ ] HTML / CSV / Excel report export
* [ ] Dashboard UI (React or Streamlit)
* [ ] Tag-based triage, comments per CVE
* [ ] Automatic scheduler (cron, systemd)

---

## 🤝 Credits

Created by [bishesh910]
🐝 Project: [BeezLab](https://github.com/bishesh910)
CVE data from: [NIST NVD](https://nvd.nist.gov/), [Ubuntu CVE Tracker](https://people.canonical.com/~ubuntu-security/cve/), [RedHat OVAL](https://www.redhat.com/security/data/oval/), [Microsoft MSRC](https://msrc.microsoft.com/)

---

## 🔐 Disclaimer

This tool has only been tested on Ubuntu environment as would need to test it further on other OS (I will update once its tested on every OS that it supports).

This tool performs **local enumeration only**. It does not exploit or probe remote systems. It is intended for vulnerability awareness and personal use.
