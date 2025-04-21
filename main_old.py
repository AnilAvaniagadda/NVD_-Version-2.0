from fastapi import FastAPI, Depends, Request, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from models import CVE, CPE, SessionLocal
from datetime import datetime
from deduplicate import deduplicate_cves
from fetch_cve_data import fetch_all
import threading
import time

app = FastAPI()

# Templates & static
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# DB Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Home
@app.get("/")
def home():
    return {"message": "FastAPI is working!"}

# UI
@app.get("/ui", response_class=HTMLResponse)
def serve_ui(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Detail page
@app.get("/cve-detail/{cve_id}", response_class=HTMLResponse)
def cve_detail_page(cve_id: str, request: Request, db: Session = Depends(get_db)):
    cve = db.query(CVE).filter(CVE.id == cve_id).first()
    cpes = db.query(CPE).filter(CPE.cve_id == cve_id).all()
    return templates.TemplateResponse("cve_detail.html", {
        "request": request,
        "cve": cve,
        "cpes": cpes
    })

# JSON details
@app.get("/cves/{cve_id}/json")
def get_cve_data(cve_id: str, db: Session = Depends(get_db)):
    cve = db.query(CVE).filter(CVE.id == cve_id).first()
    if not cve:
        return {}
    return {
        "id": cve.id,
        "description": cve.description,
        "cvss_v2_score": cve.cvss_v2_score,
        "metrics": {
            "cvssMetricV2": [{
                "baseSeverity": "LOW" if (cve.cvss_v2_score or 0) <= 3.9 else "MEDIUM" if (cve.cvss_v2_score or 0) <= 6.9 else "HIGH",
                "vectorString": cve.cvss_v2_vector,
                "accessVector": cve.access_vector,
                "accessComplexity": cve.access_complexity,
                "authentication": cve.authentication,
                "confidentialityImpact": cve.confidentiality_impact,
                "integrityImpact": cve.integrity_impact,
                "availabilityImpact": cve.availability_impact,
                "exploitabilityScore": cve.exploitability_score,
                "impactScore": cve.impact_score,
            }]
        },
        "configurations": {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "criteria": c.criteria,
                            "matchCriteriaId": c.match_criteria_id,
                            "vulnerable": c.vulnerable,
                        }
                        for c in cve.cpes
                    ]
                }
            ]
        }
    }

# CVE list with filters
@app.get("/cves/list")
def get_cves(
    skip: int = 0,
    limit: int = 10,
    sort_by: str = "published_date",
    sort_order: str = "asc",
    min_score: float = Query(None),
    max_score: float = Query(None),
    start_date: str = Query(None),
    end_date: str = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(CVE)

    if min_score is not None:
        query = query.filter((CVE.cvss_v2_score >= min_score) | (CVE.cvss_v3_score >= min_score))
    if max_score is not None:
        query = query.filter((CVE.cvss_v2_score <= max_score) | (CVE.cvss_v3_score <= max_score))
    if start_date:
        try:
            query = query.filter(CVE.published_date >= datetime.fromisoformat(start_date))
        except:
            pass
    if end_date:
        try:
            query = query.filter(CVE.published_date <= datetime.fromisoformat(end_date))
        except:
            pass

    if sort_by not in ["published_date", "last_modified_date"]:
        sort_by = "published_date"

    order_column = getattr(CVE, sort_by)
    if sort_order == "desc":
        order_column = order_column.desc()

    query = query.order_by(order_column)
    total = query.count()
    records = query.offset(skip).limit(limit).all()

    return {
        "records": [
            {
                "id": cve.id,
                "published_date": cve.published_date.isoformat() if cve.published_date else None,
                "last_modified_date": cve.last_modified_date.isoformat() if cve.last_modified_date else None,
                "description": cve.description,
                "cvss_v2_score": cve.cvss_v2_score,
                "cvss_v3_score": cve.cvss_v3_score,
                "status": cve.status
            } for cve in records
        ],
        "total": total
    }

# Sync scheduler
def schedule_fetch():
    while True:
        try:
            print("🕒 Running scheduled fetch...")
            fetch_all()
            db = SessionLocal()
            deduplicate_cves(db)
            db.close()
            print("✅ Sync + deduplication done.")
        except Exception as e:
            print("❌ Error during sync:", e)
        time.sleep(86400)  # 24 hrs

# Start background thread
threading.Thread(target=schedule_fetch, daemon=True).start()