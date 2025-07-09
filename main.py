from fastapi import FastAPI, HTTPException,Request,Response,Form,UploadFile
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from functools import wraps
import requests, json
import mammoth
from pydantic import BaseModel, EmailStr
import hashlib
app = FastAPI()
templates=Jinja2Templates(directory="templates")
users_db = {}
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key="eEQ123@da")
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

def login_checker(func):
    @wraps(func)
    def wrap(*args):
        if "email" not in Request.session:
            return templates.TemplateResponse("authentication_page.html",{"request":Request,"message":"Sorry Login!"})
        func(*args)
    return wrap



@app.post("/api/register")
async def register_user(request: Request, response:Response, data: RegisterRequest):
    if data.email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    password= hash_password(data.password)
    users_db[data.email] = {"name": data.name, "password": password}
    return {"message": "User registered successfully"}


@app.post("/api/login")
async def login_user(request:Request, response:Response,data: LoginRequest):
    user = users_db.get(data.email)
    password = hash_password(data.password)
    print(users_db)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    print(users_db.get("password"),password)
    request.session["email"] = data.email
    return {'message':"Login Successful!","redirect_url":"/api/"}

@app.get("/api/")
def index_page(request:Request):
    return templates.TemplateResponse("index.html",context={"request":request})

@app.get("/api/authenticate")
def authenticate_page(request:Request):
    return templates.TemplateResponse("authentication_page.html",context={"request":request})

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "gemma:2b"

def extract_text(file: UploadFile) -> str:
    if file.filename.endswith(".pdf"):
        reader = PdfReader(file.file)
        text = ""
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
        return text
    elif file.filename.endswith(".docx"):
        # mammoth needs a file path, so save temporarily
        temp_path = "temp.docx"
        with open(temp_path, "wb") as temp_file:
            temp_file.write(file.file.read())

        with open(temp_path, "rb") as docx_file:
            result = mammoth.extract_raw_text(docx_file)
            text = result.value

        return text
    

    elif file.filename.endswith(".txt"):
        return file.file.read().decode()
    else:
        raise ValueError("Unsupported file type")

def build_prompt(jd_text: str, resume_text: str) -> str:
    return f"""
You are an expert recruiter. Compare the following Job Description and Resume. 
- List the matching skills.
- List the missing skills.
- Estimate a match percentage (0–100).

Job Description:
\"\"\"
{jd_text}
\"\"\"

Resume:
\"\"\"
{resume_text}
\"\"\"

Respond in the following JSON format:
{{
    "match_percentage": <int>,
    "matching_skills": [<list of skills>],
    "missing_skills": [<list of skills>]
}}
"""

def call_ollama(prompt: str) -> dict:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }

    response = requests.post(OLLAMA_URL, json=payload)
    response.raise_for_status()

    result_text = response.json()["response"]

    try:
        result_json = json.loads(result_text)
    except Exception:
        raise ValueError(f"Failed to parse LLM response: {result_text}")

    return result_json

@app.post("/api/match")
async def match(jd_text: str = Form(None), jd_file: UploadFile = None, resume_file: UploadFile = None):
    if jd_text:
        jd_content = jd_text
    elif jd_file:
        jd_content = extract_text(jd_file)
    else:
        return JSONResponse({"error": "No JD provided"}, status_code=400)

    if not resume_file:
        return JSONResponse({"error": "No resume provided"}, status_code=400)

    resume_content = extract_text(resume_file)

    prompt = build_prompt(jd_content, resume_content)

    try:
        result_json = call_ollama(prompt)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    return result_json

