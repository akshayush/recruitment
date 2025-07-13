from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, status, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
import shutil
import os

from models import Base, engine, Employer, Employee, JobPost
from database import get_db
from schemas import EmployerCreate, EmployeeCreate, JobPostCreate

app = FastAPI(title="Jobs Dunia Placement Portal")
#templates = Jinja2Templates(directory="templates")
import os
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
    employer = Employer(employer_name=employer_name, mobile=mobile, email=email, password=password)
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
    # Save CV
    cv_path = f"static/cvs/{cv.filename}"
    with open(cv_path, "wb") as buffer:
        shutil.copyfileobj(cv.file, buffer)
    employee = Employee(
        name=name, mobile=mobile, email=email, qualification=qualification,
        experience=experience, current_profile=current_profile,
        current_org=current_org, current_ctc=current_ctc,
        notice_period=notice_period, cv=cv_path
    )
    db.add(employee)
    db.commit()
    return RedirectResponse("/", status_code=302)
