import requests
import time
from datetime import datetime
from models import CVE, CPE, SessionLocal

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = "f3819cd1-bef9-4133-a9e5-530a39255a31"
PAGE_SIZE = 1000

def parse_and_store(data):
    db = SessionLocal()
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        description = cve["descriptions"][0]["value"]
        published = cve.get("published")
        modified = cve.get("lastModified")
        status = cve.get("vulnStatus") 

        # Defaults
        v2 = {}
        cvss_v2_score = None
        cvss_v2_vector = None
        access_vector = None
        access_complexity = None
        authentication = None
        confidentiality_impact = None
        integrity_impact = None
        availability_impact = None
        exploitability_score = None
        impact_score = None

        metrics_v2 = cve.get("metrics", {}).get("cvssMetricV2", [])
        if metrics_v2 and "cvssData" in metrics_v2[0]:
            v2 = metrics_v2[0]["cvssData"]
            cvss_v2_score = v2.get("baseScore")
            cvss_v2_vector = v2.get("vectorString")
            access_vector = v2.get("accessVector")
            access_complexity = v2.get("accessComplexity")
            authentication = v2.get("authentication")
            confidentiality_impact = v2.get("confidentialityImpact")
            integrity_impact = v2.get("integrityImpact")
            availability_impact = v2.get("availabilityImpact")
            exploitability_score = metrics_v2[0].get("exploitabilityScore")
            impact_score = metrics_v2[0].get("impactScore")

        cve_obj = CVE(
            id=cve_id,
            published_date=datetime.fromisoformat(published.replace("Z", "+00:00")),
            last_modified_date=datetime.fromisoformat(modified.replace("Z", "+00:00")),
            description=description,
            cvss_v2_score=cvss_v2_score,
            cvss_v2_vector=cvss_v2_vector,
            status=status,
            access_vector=access_vector,
            access_complexity=access_complexity,
            authentication=authentication,
            confidentiality_impact=confidentiality_impact,
            integrity_impact=integrity_impact,
            availability_impact=availability_impact,
            exploitability_score=exploitability_score,
            impact_score=impact_score,
        )

        db.merge(cve_obj)

        db.query(CPE).filter(CPE.cve_id == cve_id).delete()
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    db.add(CPE(
                        cve_id=cve_id,
                        criteria=match["criteria"],
                        match_criteria_id=match.get("matchCriteriaId"),
                        vulnerable=match.get("vulnerable", False)
                    ))

    db.commit()
    db.close()

def fetch_all():
    start = 0

    while True:
        print(f"Fetching from index {start}")
        params = {"startIndex": start, "resultsPerPage": PAGE_SIZE}
        headers = {"apiKey": API_KEY}

        response = requests.get(API_URL, params=params, headers=headers)

        if response.status_code != 200:
            print(f"Error fetching data at index {start}: {response.status_code}")
            print("Response content:", response.text)
            break

        try:
            data = response.json()
        except Exception as e:
            print(f"Failed to parse JSON at index {start}: {e}")
            break

        parse_and_store(data)

        total = data.get("totalResults", 0)
        start += PAGE_SIZE

        if start >= total:
            break

        time.sleep(1.5)

if __name__ == "__main__":
    fetch_all()
