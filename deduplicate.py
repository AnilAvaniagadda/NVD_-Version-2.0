# deduplicate.py
from sqlalchemy import func
from models import CVE

def deduplicate_cves(db):
    print("🧹 Running deduplication...")

    duplicates = (
        db.query(CVE.id)
        .group_by(CVE.id)
        .having(func.count(CVE.id) > 1)
        .all()
    )

    for (cve_id,) in duplicates:
        cves = db.query(CVE).filter(CVE.id == cve_id).order_by(CVE.last_modified_date.desc()).all()
        for cve in cves[1:]:
            db.delete(cve)

    db.commit()
    print("✅ Deduplication complete")
