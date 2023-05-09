import argparse
import json
import os
import requests
from datetime import datetime, timedelta
from github import Github

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/"
GITHUB_TOKEN = os.environ["GITHUB_API_TOKEN"]

def get_cve_by_cpe23_uri(cpe23_uri, results_per_page=20):
    url = f"{NVD_API_BASE_URL}cves/1.0?cpeMatchString={cpe23_uri}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Error: {response.status_code}")

def find_cve_by_software_name(software_name, results_per_page=2000):
    cpe23_uri = f"cpe:2.3:a:*:{software_name}:*:*:*:*:*:*:*"
    results = get_cve_by_cpe23_uri(cpe23_uri, results_per_page)
    if results.get("totalResults", 0) == 0:
        raise ValueError("Invalid software name or no vulnerabilities found.")
    return results

def find_latest_cve_by_software_name(software_name):
    results = find_cve_by_software_name(software_name, results_per_page=1)
    if results.get("result", {}).get("CVE_Items"):
        return results["result"]["CVE_Items"][0]
    else:
        return None

def create_github_issue(repo_name, title, body, labels=None):
    g = Github(GITHUB_TOKEN)
    repo = g.get_repo(repo_name)
    issue = repo.create_issue(title=title, body=body, labels=labels)
    return issue

def create_issue_for_vulnerability(repo_name, product_name, cve, description, severity, due_date, has_cert_alerts, has_cert_notes, has_kev):
    issue_title = f"PSIRT Vulnerability - {product_name} - {cve} - {due_date.strftime('%Y-%m-%d')}"
    issue_body = f"**Description:** {description}\n\n**Severity:** {severity}\n\n**Due Date:** {due_date.strftime('%Y-%m-%d')}\n\n**Has CERT Alerts:** {has_cert_alerts}\n\n**Has CERT Notes:** {has_cert_notes}\n\n**Has Key Event:** {has_kev}"
    label_due_date = f"due_date:{due_date.strftime('%Y-%m-%d')}"
    labels = [label_due_date]
    issue = create_github_issue(repo_name, issue_title, issue_body, labels)
    return issue

def calculate_due_date(severity):
    now = datetime.now()
    if severity in ["HIGH", "CRITICAL"]:
        due_date = now + timedelta(days=15)
    else:  # "LOW" or "MEDIUM"
        due_date = now + timedelta(days=45)
    return due_date

def main(software_name, latest_only=False, repo_name=None):
    if latest_only:
        try:
            result = find_latest_cve_by_software_name(software_name)
            if result:
                if repo_name:
                    product_name = software_name
                    description = result["cve"]["description"]["description_data"][0]["value"]
                    cve = result["cve"]["CVE_data_meta"]["ID"]
                    severity = result["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                    due_date = calculate_due_date(severity)
                    has_cert_alerts = result.get("hasCertAlerts", False)
                    has_cert_notes = result.get("hasCertNotes", False)
                    result.get("hasCertNotes", False)
                    has_kev = result.get("hasKeyEvent", False)
                    issue = create_issue_for_vulnerability(repo_name, product_name, cve, description, severity, due_date, has_cert_alerts, has_cert_notes, has_kev)
                    print(f"Issue created: {issue.html_url}")
                else:
                    print(json.dumps(result, indent=2))
            else:
                print("No vulnerabilities found.")
        except ValueError as e:
            print(f"Error: {e}")
    else:
        try:
            results = find_cve_by_software_name(software_name)
            print(json.dumps(results, indent=2))
        except ValueError as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find vulnerabilities for given software in NIST NVD database")
    parser.add_argument("software_name", help="Software name to search vulnerabilities for")
    parser.add_argument("--latest", action="store_true", help="Show only the latest vulnerability")
    parser.add_argument("--repo", type=str, help="GitHub repository to create an issue in (e.g. 'username/repo')")
    args = parser.parse_args()

    main(args.software_name, args.latest, args.repo)
