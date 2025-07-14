from pydantic import BaseModel

class EmployerCreate(BaseModel):
    employer_name: str
    mobile: str
    email: str
    password: str

class EmployeeCreate(BaseModel):
    name: str
    mobile: str
    email: str
    qualification: str
    experience: int
    current_profile: str
    current_org: str
    current_ctc: str
    notice_period: str
    cv: str

class JobPostCreate(BaseModel):
    employer_id: int
    hiring_profile: str
    qualification: str
    experience: int
    positions: int
    skills: str
    location: str
    ctc: str
    responsibilities: str

class JobApplicationCreate(BaseModel):
    job_id: int
    employee_id: int
    cover_letter: str
    expected_ctc: str
    available_from: str
    why_interested: str
    additional_info: str
