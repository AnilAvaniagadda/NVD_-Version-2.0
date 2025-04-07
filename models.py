from sqlalchemy import create_engine, Column, String, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy import Integer  # add this to the imports

DATABASE_URL = "sqlite:///./cve_database.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class CVE(Base):
    __tablename__ = "cves"

    id = Column(String, primary_key=True, index=True)
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    description = Column(String)
    cvss_v2_score = Column(Float, nullable=True)
    cvss_v3_score = Column(Float, nullable=True)
    status = Column(String, nullable=True)

    # ✅ Newly added CVSS V2 Vector and Metric fields
    cvss_v2_vector = Column(String, nullable=True)
    access_vector = Column(String, nullable=True)
    access_complexity = Column(String, nullable=True)
    authentication = Column(String, nullable=True)
    confidentiality_impact = Column(String, nullable=True)
    integrity_impact = Column(String, nullable=True)
    availability_impact = Column(String, nullable=True)
    exploitability_score = Column(Float, nullable=True)
    impact_score = Column(Float, nullable=True)

    cpes = relationship("CPE", back_populates="cve", cascade="all, delete-orphan")





class CPE(Base):
    __tablename__ = "cpes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String, ForeignKey("cves.id"))
    criteria = Column(String)
    match_criteria_id = Column(String, nullable=True)
    vulnerable = Column(Boolean)

    cve = relationship("CVE", back_populates="cpes")



# ✅ Create tables in database
Base.metadata.create_all(bind=engine)
