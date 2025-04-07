# drop_table.py
from models import engine, Base, CPE

# Drop the cpes table only
CPE.__table__.drop(engine)
print("------------------Dropped 'cpes' table------------------------")
