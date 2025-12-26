from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import os

Base = declarative_base()
tidb_url = os.getenv("TIDB_DATABASE_URL", "mysql+pymysql://user:password@localhost/jobs_dunia")
# Convert mysql:// to mysql+pymysql:// if needed
if tidb_url.startswith("mysql://"):
    DATABASE_URL = tidb_url.replace("mysql://", "mysql+pymysql://", 1)
else:
    DATABASE_URL = tidb_url
engine = create_engine(DATABASE_URL, echo=False)

class Employer(Base):
    __tablename__ = "employers"
    id = Column(Integer, primary_key=True, index=True)
    employer_name = Column(String)
    mobile = Column(String)
    email = Column(String, unique=True)
    password = Column(String)
    jobs = relationship("JobPost", back_populates="employer")

class JobPost(Base):
    __tablename__ = "jobposts"
    id = Column(Integer, primary_key=True, index=True)
    employer_id = Column(Integer, ForeignKey("employers.id"))
    hiring_profile = Column(String)
    qualification = Column(String)
    experience = Column(Integer)
    positions = Column(Integer)
    skills = Column(String)
    location = Column(String)
    ctc = Column(String)
    responsibilities = Column(String)
    employer = relationship("Employer", back_populates="jobs")

class Employee(Base):
    __tablename__ = "employees"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    mobile = Column(String)
    email = Column(String, unique=True)
    qualification = Column(String)
    experience = Column(Integer)
    current_profile = Column(String)
    current_org = Column(String)
    current_ctc = Column(String)
    notice_period = Column(String)
    cv = Column(String)
    applications = relationship("JobApplication", back_populates="employee")

class JobApplication(Base):
    __tablename__ = "job_applications"
    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("jobposts.id"))
    employee_id = Column(Integer, ForeignKey("employees.id"))
    cover_letter = Column(String)
    expected_ctc = Column(String)
    available_from = Column(String)
    why_interested = Column(String)
    additional_info = Column(String)
    status = Column(String, default="Applied")  # Applied, Reviewing, Interview, Rejected, Selected
    applied_date = Column(String)
    
    job = relationship("JobPost")
    employee = relationship("Employee", back_populates="applications")
