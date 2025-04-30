# Automated Risk Register Generator

Python workflow that turns a simple asset list into:

* **risk_register.md** – a Confluence-ready table
* **jira_import.csv**  – bulk-upload file for JIRA tickets

### How it Works
1. Reads `assets.json`
2. Pulls the most recent, highest-severity CVE for each operating system via NVD API
3. Ranks risk by CVSS
4. Runs automatically on every push (GitHub Actions)

### Tech
* Python 3 · Requests · NVD CVE API  
* GitHub Actions CI

See **Actions tab** for the latest build artefacts.

