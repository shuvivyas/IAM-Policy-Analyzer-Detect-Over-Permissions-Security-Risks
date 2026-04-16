from fastapi import FastAPI, Request
from analyzer import analyze_policy
from fastapi import UploadFile, File
import json

app = FastAPI()

@app.get("/")
def home():
    return {"message": "IAM Policy Analyzer Running"}

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    content = await file.read()
    policy = json.loads(content)
    result = analyze_policy(policy)
    return result

@app.post("/upload")
async def upload_policy(file: UploadFile = File(...)):
    content = await file.read()
    policy = json.loads(content)
    return {"test": "coming from render"}
    
