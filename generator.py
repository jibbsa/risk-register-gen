import csv
import json
import os
import datetime
import requests

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY   = os.getenv("NVD_API_KEY") or "YOUR_NVD_API_KEY"

HEADERS = {
    "apiKey":     API_KEY,
    "User-Agent": "risk-register-gen/0.2",
}

def fetch_top_cve(keyword: str) -> tuple[str, str]:
    """Return (CVE-ID, CVSS-score) or graceful fallback strings."""
    params = {"keywordSearch": keyword, "resultsPerPage": 1}
    try:
        r = requests.get(BASE_URL, params=params, headers=HEADERS, timeout=15)
    except requests.RequestException:
        return "N/A", "network-error"

    if r.status_code != 200:
        return "N/A", f"http-{r.status_code}"

    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        return "N/A", "not-found"

    cve   = vulns[0]["cve"]
    score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
    return cve["id"], str(score)

def decide_priority(cvss: str) -> str:
    """High if numeric ≥7; Medium otherwise."""
    try:
        return "High" if float(cvss) >= 7 else "Medium"
    except ValueError:
        return "Medium"

def build_register() -> None:
    with open("assets.json", encoding="utf-8") as fh:
        assets = json.load(fh)

    os.makedirs("output", exist_ok=True)

    md_lines = ["|Asset|OS|CVE|CVSS|", "|---|---|---|---|"]

    with open("output/jira_import.csv", "w", newline="", encoding="utf-8") as csv_out:
        writer = csv.writer(csv_out)
        writer.writerow(["Summary", "Description", "Priority"])

        for asset in assets:
            cve_id, cvss = fetch_top_cve(asset["os"])
            md_lines.append(f"|{asset['name']}|{asset['os']}|{cve_id}|{cvss}|")

            priority = decide_priority(cvss)
            writer.writerow(
                [
                    f"Remediate {cve_id} on {asset['name']}",
                    f"Generated {datetime.date.today()} — CVSS {cvss}",
                    priority,
                ]
            )

    with open("output/risk_register.md", "w", encoding="utf-8") as md_out:
        md_out.write("\n".join(md_lines))

if __name__ == "__main__":
    build_register()
