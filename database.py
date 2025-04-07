from sqlalchemy import create_engine, Column, String, Float, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base

# Define the SQLite database URL (for PostgreSQL, change this later)
DATABASE_URL = "sqlite:///./cve_database.db"

# Create an engine that connects to SQLite
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Create a session maker
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a base class for ORM models
Base = declarative_base()

# Define the CVE Model (Schema)
class CVE(Base):
    __tablename__ = "cves"

    id = Column(String, primary_key=True, index=True)
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    description = Column(String)
    cvss_v2_score = Column(Float, nullable=True)
    cvss_v3_score = Column(Float, nullable=True)

# Create the database and tables
Base.metadata.create_all(bind=engine)
