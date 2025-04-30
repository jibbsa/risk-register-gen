import csv
import json
import os
import datetime
import requests

NVD_API_KEY = os.getenv("NVD_API_KEY") or "YOUR_NVD_API_KEY"
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {
    "apiKey": NVD_API_KEY,
    "User-Agent": "risk-register-gen/0.1"
}


def pull_cve(keyword: str) -> tuple[str, str]:
    params = {"keywordSearch": keyword, "resultsPerPage": 1}
    r = requests.get(BASE_URL, params=params, headers=HEADERS, timeout=15)

    if r.status_code != 200:
        return "N/A", "API error"

    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        return "N/A", "none found"

    cve = vulns[0]["cve"]
    score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
    return cve["id"], score


def build_register() -> None:
    with open("assets.json", encoding="utf-8") as f:
        assets = json.load(f)

    os.makedirs("output", exist_ok=True)

    md_rows = ["|Asset|OS|CVE|CVSS|", "|---|---|---|---|"]

    with open("output/jira_import.csv", "w", newline="", encoding="utf-8") as out_csv:
        w = csv.writer(out_csv)
        w.writerow(["Summary", "Description", "Priority"])

        for asset in assets:
            cve_id, cvss = pull_cve(asset["os"])
            md_rows.append(f"|{asset['name']}|{asset['os']}|{cve_id}|{cvss}|")

            priority = "High" if cvss != "N/A" and float(cvss) >= 7 else "Medium"
            w.writerow(
                [
                    f"Remediate {cve_id} on {asset['name']}",
                    f"Generated {datetime.date.today()} — CVSS {cvss}",
                    priority,
                ]
            )

    with open("output/risk_register.md", "w", encoding="utf-8") as out_md:
        out_md.write("\n".join(md_rows))


if __name__ == "__main__":
    build_register()
