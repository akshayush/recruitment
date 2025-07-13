from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, status, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
import shutil
import os
import re
import time


from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

# Security middleware
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["*"]  # Configure based on your domain
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure based on your needs
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


from pathlib import Path
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash

from models import Base, engine, Employer, Employee, JobPost
from database import get_db
from schemas import EmployerCreate, EmployeeCreate, JobPostCreate

app = FastAPI(title="Jobs Dunia Placement Portal")
#templates = Jinja2Templates(directory="templates")
import os


# Security and validation functions
def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_mobile(mobile: str) -> bool:
    pattern = r'^\d{10}$'
    return bool(re.match(pattern, mobile.replace('+91', '').replace(' ', '')))

def sanitize_filename(filename: str) -> str:
    # Remove any path components and keep only safe characters
    filename = os.path.basename(filename)
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    return filename[:100]  # Limit length

def validate_file_type(filename: str) -> bool:
    allowed_extensions = {'.pdf', '.doc', '.docx'}
    return Path(filename).suffix.lower() in allowed_extensions


templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

app.mount("/static", StaticFiles(directory="static"), name="static")

Base.metadata.create_all(bind=engine)

# --- Home Page ---
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    try:
        print("Rendering home page")
        print(templates.TemplateResponse("home.html", {"request": request}))
        return templates.TemplateResponse("home.html", {"request": request})
    except Exception as e:
        print(f"Error rendering home page: {e}")
        return HTMLResponse(content="Internal Server Error", status_code=500)

# --- Current Openings Page ---
@app.get("/openings", response_class=HTMLResponse)
def current_openings(request: Request, db: Session = Depends(get_db)):
    jobs = db.query(JobPost).all()
    return templates.TemplateResponse("current_openings.html", {"request": request, "jobs": jobs})

# --- Employer Registration/Login ---
@app.get("/employer/register", response_class=HTMLResponse)
def employer_register_form(request: Request):
    return templates.TemplateResponse("employer_register.html", {"request": request})

@app.post("/employer/register")
def employer_register(
    employer_name: str = Form(...),
    mobile: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Input validation
    if not validate_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    if not validate_mobile(mobile):
        raise HTTPException(status_code=400, detail="Invalid mobile number format")
    
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
    
    # Check for duplicate email
    existing_employer = db.query(Employer).filter(Employer.email == email).first()
    if existing_employer:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Sanitize inputs
    employer_name = employer_name.strip()[:200]
    
    # Hash password before storing
    hashed_password = generate_password_hash(password)
    
    employer = Employer(
        employer_name=employer_name, 
        mobile=mobile, 
        email=email, 
        password=hashed_password
    )
    db.add(employer)
    db.commit()
    return RedirectResponse("/employer/login", status_code=302)

@app.get("/employer/login", response_class=HTMLResponse)
def employer_login_form(request: Request):
    return templates.TemplateResponse("employer_login.html", {"request": request})

# --- Employer Dashboard & Job Posting ---
@app.get("/employer/dashboard", response_class=HTMLResponse)
def employer_dashboard(request: Request, db: Session = Depends(get_db)):
    jobs = db.query(JobPost).all()
    return templates.TemplateResponse("employer_dashboard.html", {"request": request, "jobs": jobs})

@app.post("/employer/post_job")
def post_job(
    employer_id: int = Form(...),
    hiring_profile: str = Form(...),
    qualification: str = Form(...),
    experience: int = Form(...),
    positions: int = Form(...),
    skills: str = Form(...),
    location: str = Form(...),
    ctc: str = Form(...),
    responsibilities: str = Form(...),
    db: Session = Depends(get_db)
):
    # Validate employer exists
    employer = db.query(Employer).filter(Employer.id == employer_id).first()
    if not employer:
        raise HTTPException(status_code=404, detail="Employer not found")
    
    # Input validation
    if experience < 0 or experience > 50:
        raise HTTPException(status_code=400, detail="Invalid experience range")
    
    if positions < 1 or positions > 1000:
        raise HTTPException(status_code=400, detail="Invalid number of positions")
    
    # Sanitize inputs
    hiring_profile = hiring_profile.strip()[:200]
    qualification = qualification.strip()[:200]
    skills = skills.strip()[:500]
    location = location.strip()[:200]
    ctc = ctc.strip()[:100]
    responsibilities = responsibilities.strip()[:2000]
    
    job = JobPost(
        employer_id=employer_id,
        hiring_profile=hiring_profile,
        qualification=qualification,
        experience=experience,
        positions=positions,
        skills=skills,
        location=location,
        ctc=ctc,
        responsibilities=responsibilities
    )
    db.add(job)
    db.commit()
    return RedirectResponse("/employer/dashboard", status_code=302)

# --- Employee Registration/Login ---
@app.get("/employee/register", response_class=HTMLResponse)
def employee_register_form(request: Request):
    return templates.TemplateResponse("employee_register.html", {"request": request})

@app.post("/employee/register")
def employee_register(
    name: str = Form(...),
    mobile: str = Form(...),
    email: str = Form(...),
    qualification: str = Form(...),
    experience: int = Form(...),
    current_profile: str = Form(...),
    current_org: str = Form(...),
    current_ctc: str = Form(...),
    notice_period: str = Form(...),
    cv: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Input validation
    if not validate_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    if not validate_mobile(mobile):
        raise HTTPException(status_code=400, detail="Invalid mobile number format")
    
    if experience < 0 or experience > 50:
        raise HTTPException(status_code=400, detail="Invalid experience range")
    
    # File validation
    if not cv.filename or not validate_file_type(cv.filename):
        raise HTTPException(status_code=400, detail="Invalid file type. Only PDF, DOC, DOCX allowed")
    
    if cv.size > 5 * 1024 * 1024:  # 5MB limit
        raise HTTPException(status_code=400, detail="File size too large. Maximum 5MB allowed")
    
    # Check for duplicate email
    existing_employee = db.query(Employee).filter(Employee.email == email).first()
    if existing_employee:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Secure file handling
    safe_filename = sanitize_filename(cv.filename)
    timestamp = str(int(time.time()))
    unique_filename = f"{timestamp}_{safe_filename}"
    
    # Ensure CV directory exists
    cv_dir = Path("static/cvs")
    cv_dir.mkdir(parents=True, exist_ok=True)
    
    cv_path = cv_dir / unique_filename
    
    try:
        with open(cv_path, "wb") as buffer:
            content = cv.file.read()
            # Additional security: check file content
            if b'<script' in content.lower() or b'javascript' in content.lower():
                raise HTTPException(status_code=400, detail="Potentially malicious file content detected")
            buffer.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail="File upload failed")
    
    # Sanitize text inputs
    name = name.strip()[:100]
    qualification = qualification.strip()[:100]
    current_profile = current_profile.strip()[:200]
    current_org = current_org.strip()[:200]
    current_ctc = current_ctc.strip()[:50]
    notice_period = notice_period.strip()[:50]
    
    employee = Employee(
        name=name, mobile=mobile, email=email, qualification=qualification,
        experience=experience, current_profile=current_profile,
        current_org=current_org, current_ctc=current_ctc,
        notice_period=notice_period, cv=str(cv_path)
    )
    db.add(employee)
    db.commit()
    return RedirectResponse("/", status_code=302)
