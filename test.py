import requests
import json

API_KEY = "f3819cd1-bef9-4133-a9e5-530a39255a31"
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

params = {
    "startIndex": 0,
    "resultsPerPage": 1  # just one result for inspection
}

headers = {
    "apiKey": API_KEY
}

response = requests.get(API_URL, headers=headers, params=params)

if response.status_code == 200:
    data = response.json()
    cve = data["vulnerabilities"][0]["cve"]
    print("\n🎯 CVE ID:", cve.get("id"))
    print("📅 Published:", cve.get("published"))
    print("🔧 Status:", cve.get("vulnStatus"))
    print("🧱 Configuration Nodes:\n")

    configurations = cve.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            print("Operator:", node.get("operator"))
            for match in node.get("cpeMatch", []):
                print(f" - Criteria: {match.get('criteria')}")
                print(f"   Vulnerable: {match.get('vulnerable')}")
                print(f"   MatchCriteriaId: {match.get('matchCriteriaId')}")
                print("---")
else:
    print("❌ Error:", response.status_code)
    print("Details:", response.text)
