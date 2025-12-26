from sqlalchemy import Column, Integer, String, ForeignKey, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import os

Base = declarative_base()

# TiDB Cloud connection configuration
TIDB_HOST = os.getenv("TIDB_HOST",
                      "gateway01.ap-southeast-1.prod.aws.tidbcloud.com")
TIDB_PORT = int(os.getenv("TIDB_PORT", "4000"))
TIDB_USER = os.getenv("TIDB_USER", "35V1p44dnfZWLPW.root")
TIDB_PASSWORD = os.getenv("TIDB_PASSWORD", "9So0jsaVVAHJ5Il5")
TIDB_DATABASE = os.getenv("TIDB_DATABASE", "test")
TIDB_CA_PATH = os.getenv("TIDB_CA_PATH", "./ca_cert.pem")

# SQLAlchemy MySQL connection string with mysql+pymysql driver
DATABASE_URL = f"mysql+pymysql://{TIDB_USER}:{TIDB_PASSWORD}@{TIDB_HOST}:{TIDB_PORT}/{TIDB_DATABASE}"
engine = create_engine(DATABASE_URL,
                       echo=False,
                       connect_args={
                           "ssl_ca": TIDB_CA_PATH,
                           "ssl_verify_cert": True,
                           "ssl_verify_identity": True,
                       })


class Employer(Base):
    __tablename__ = "employers"
    id = Column(Integer, primary_key=True, index=True)

    employer_name = Column(String(255))
    mobile = Column(String(20))
    email = Column(String(255), unique=True)
    password = Column(String(255))
    jobs = relationship("JobPost", back_populates="employer")


class JobPost(Base):
    __tablename__ = "jobposts"
    id = Column(Integer, primary_key=True, index=True)
    employer_id = Column(Integer, ForeignKey("employers.id"))
    hiring_profile = Column(String(255))
    qualification = Column(String(255))
    experience = Column(Integer)
    positions = Column(Integer)
    skills = Column(String(1000))
    location = Column(String(255))
    ctc = Column(String(100))
    responsibilities = Column(String(2000))
    employer = relationship("Employer", back_populates="jobs")


class Employee(Base):
    __tablename__ = "employees"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255))
    mobile = Column(String(20))
    email = Column(String(255), unique=True)
    qualification = Column(String(255))
    experience = Column(Integer)
    current_profile = Column(String(255))
    current_org = Column(String(255))
    current_ctc = Column(String(100))
    notice_period = Column(String(100))
    cv_filename = Column(String(255))
    cv_data = Column(LargeBinary)
    applications = relationship("JobApplication", back_populates="employee")


class JobApplication(Base):
    __tablename__ = "job_applications"
    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("jobposts.id"))
    employee_id = Column(Integer, ForeignKey("employees.id"))
    cover_letter = Column(String(2000))
    expected_ctc = Column(String(100))
    available_from = Column(String(100))
    why_interested = Column(String(1000))
    additional_info = Column(String(1000))
    status = Column(String(50), default="Applied")
    applied_date = Column(String(50))

    job = relationship("JobPost")
    employee = relationship("Employee", back_populates="applications")
