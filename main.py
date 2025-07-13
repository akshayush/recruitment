
from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, status, HTTPException, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
import shutil
import os
import re
import time
import secrets
import jwt
from datetime import datetime, timedelta
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI(title="Jobs Dunia Placement Portal")

# Security middleware
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["*"]  # Configure based on your domain
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-domain.com"],  # Restrict to your domain
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
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response

from pathlib import Path
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash

from models import Base, engine, Employer, Employee, JobPost
from database import get_db
from schemas import EmployerCreate, EmployeeCreate, JobPostCreate

import os

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', 'your-google-client-id')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', 'your-google-client-secret')

# Rate limiting storage (in production, use Redis)
rate_limit_storage = {}

def check_rate_limit(key: str, max_requests: int = 10, window_minutes: int = 15):
    current_time = datetime.now()
    window_start = current_time - timedelta(minutes=window_minutes)
    
    if key not in rate_limit_storage:
        rate_limit_storage[key] = []
    
    # Clean old requests
    rate_limit_storage[key] = [
        req_time for req_time in rate_limit_storage[key] 
        if req_time > window_start
    ]
    
    if len(rate_limit_storage[key]) >= max_requests:
        raise HTTPException(status_code=429, detail="Too many requests")
    
    rate_limit_storage[key].append(current_time)

def create_jwt_token(user_id: int, user_type: str) -> str:
    payload = {
        "user_id": user_id,
        "user_type": user_type,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_employer(token: str = Cookie(None, alias="access_token"), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    payload = verify_jwt_token(token)
    if payload.get("user_type") != "employer":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    employer = db.query(Employer).filter(Employer.id == payload["user_id"]).first()
    if not employer:
        raise HTTPException(status_code=404, detail="Employer not found")
    
    return employer

def get_current_employee(token: str = Cookie(None, alias="employee_token"), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    payload = verify_jwt_token(token)
    if payload.get("user_type") != "employee":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    employee = db.query(Employee).filter(Employee.id == payload["user_id"]).first()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    return employee

def verify_google_token(token: str) -> dict:
    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        return idinfo
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Google token")

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

def sanitize_input(text: str, max_length: int = 500) -> str:
    """Sanitize text input to prevent XSS and limit length"""
    if not text:
        return ""
    # Remove HTML tags and limit length
    text = re.sub(r'<[^>]*>', '', text)
    text = text.strip()[:max_length]
    return text

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

app.mount("/static", StaticFiles(directory="static"), name="static")

Base.metadata.create_all(bind=engine)

# --- Home Page ---
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    try:
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
    request: Request,
    employer_name: str = Form(...),
    mobile: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Rate limiting
    client_ip = request.client.host
    check_rate_limit(f"register_{client_ip}", max_requests=5, window_minutes=60)
    
    # Input validation
    if not validate_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    if not validate_mobile(mobile):
        raise HTTPException(status_code=400, detail="Invalid mobile number format")
    
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
    
    # Check for duplicate email using parameterized query
    existing_employer = db.query(Employer).filter(Employer.email == email).first()
    if existing_employer:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Sanitize inputs
    employer_name = sanitize_input(employer_name, 200)
    
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

@app.post("/employer/login")
def employer_login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Rate limiting
    client_ip = request.client.host
    check_rate_limit(f"login_{client_ip}", max_requests=5, window_minutes=15)
    
    # Validate input
    if not validate_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    # Check credentials using parameterized query
    employer = db.query(Employer).filter(Employer.email == email).first()
    if not employer or not check_password_hash(employer.password, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create JWT token
    token = create_jwt_token(employer.id, "employer")
    
    response = RedirectResponse("/employer/dashboard", status_code=302)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=JWT_EXPIRATION_HOURS * 3600
    )
    return response

# --- Employer Dashboard & Job Posting ---
@app.get("/employer/dashboard", response_class=HTMLResponse)
def employer_dashboard(
    request: Request, 
    current_employer: Employer = Depends(get_current_employer),
    db: Session = Depends(get_db)
):
    # Only show jobs for the authenticated employer
    jobs = db.query(JobPost).filter(JobPost.employer_id == current_employer.id).all()
    return templates.TemplateResponse("employer_dashboard.html", {
        "request": request, 
        "jobs": jobs,
        "employer": current_employer
    })

@app.post("/employer/post_job")
def post_job(
    request: Request,
    hiring_profile: str = Form(...),
    qualification: str = Form(...),
    experience: int = Form(...),
    positions: int = Form(...),
    skills: str = Form(...),
    location: str = Form(...),
    ctc: str = Form(...),
    responsibilities: str = Form(...),
    current_employer: Employer = Depends(get_current_employer),
    db: Session = Depends(get_db)
):
    # Rate limiting
    client_ip = request.client.host
    check_rate_limit(f"post_job_{client_ip}", max_requests=10, window_minutes=60)
    
    # Input validation
    if experience < 0 or experience > 50:
        raise HTTPException(status_code=400, detail="Invalid experience range")
    
    if positions < 1 or positions > 1000:
        raise HTTPException(status_code=400, detail="Invalid number of positions")
    
    # Sanitize inputs
    hiring_profile = sanitize_input(hiring_profile, 200)
    qualification = sanitize_input(qualification, 200)
    skills = sanitize_input(skills, 500)
    location = sanitize_input(location, 200)
    ctc = sanitize_input(ctc, 100)
    responsibilities = sanitize_input(responsibilities, 2000)
    
    job = JobPost(
        employer_id=current_employer.id,
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
    request: Request,
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
    # Rate limiting
    client_ip = request.client.host
    check_rate_limit(f"emp_register_{client_ip}", max_requests=5, window_minutes=60)
    
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
    
    if cv.size and cv.size > 5 * 1024 * 1024:  # 5MB limit
        raise HTTPException(status_code=400, detail="File size too large. Maximum 5MB allowed")
    
    # Check for duplicate email using parameterized query
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
        content = cv.file.read()
        # Additional security: check file content
        if b'<script' in content.lower() or b'javascript' in content.lower():
            raise HTTPException(status_code=400, detail="Potentially malicious file content detected")
        
        with open(cv_path, "wb") as buffer:
            buffer.write(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail="File upload failed")
    
    # Sanitize text inputs
    name = sanitize_input(name, 100)
    qualification = sanitize_input(qualification, 100)
    current_profile = sanitize_input(current_profile, 200)
    current_org = sanitize_input(current_org, 200)
    current_ctc = sanitize_input(current_ctc, 50)
    notice_period = sanitize_input(notice_period, 50)
    
    employee = Employee(
        name=name, mobile=mobile, email=email, qualification=qualification,
        experience=experience, current_profile=current_profile,
        current_org=current_org, current_ctc=current_ctc,
        notice_period=notice_period, cv=str(cv_path)
    )
    db.add(employee)
    db.commit()
    return RedirectResponse("/", status_code=302)

@app.post("/employer/logout")
def employer_logout():
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie("access_token")
    return response

# --- Employee Login Routes ---
@app.get("/employee/login", response_class=HTMLResponse)
def employee_login_form(request: Request):
    return templates.TemplateResponse("employee_login.html", {"request": request})

@app.post("/employee/google-login")
def employee_google_login(
    request: Request,
    credential: str = Form(...),
    db: Session = Depends(get_db)
):
    # Rate limiting
    client_ip = request.client.host
    check_rate_limit(f"google_login_{client_ip}", max_requests=10, window_minutes=15)
    
    try:
        # Verify Google token
        user_info = verify_google_token(credential)
        email = user_info.get('email')
        name = user_info.get('name')
        
        if not email:
            raise HTTPException(status_code=400, detail="Unable to get email from Google")
        
        # Check if employee exists
        employee = db.query(Employee).filter(Employee.email == email).first()
        
        if not employee:
            # Create new employee account with Google info
            employee = Employee(
                name=name,
                email=email,
                mobile="",  # Will need to be filled later
                qualification="",
                experience=0,
                current_profile="",
                current_org="",
                current_ctc="",
                notice_period="",
                cv=""
            )
            db.add(employee)
            db.commit()
            db.refresh(employee)
        
        # Create JWT token
        token = create_jwt_token(employee.id, "employee")
        
        response = RedirectResponse("/employee/dashboard", status_code=302)
        response.set_cookie(
            key="employee_token",
            value=token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=JWT_EXPIRATION_HOURS * 3600
        )
        return response
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Google authentication failed: {str(e)}")

@app.get("/employee/dashboard", response_class=HTMLResponse)
def employee_dashboard(
    request: Request,
    current_employee: Employee = Depends(get_current_employee),
    db: Session = Depends(get_db)
):
    # Get available jobs
    jobs = db.query(JobPost).all()
    return templates.TemplateResponse("employee_dashboard.html", {
        "request": request,
        "employee": current_employee,
        "jobs": jobs
    })

@app.post("/employee/logout")
def employee_logout():
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie("employee_token")
    return response
