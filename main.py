from fastapi import FastAPI, UploadFile, File
from analyzer import analyze_policy
import json

app = FastAPI()

@app.get("/")
def home():
    return {"message": "IAM Policy Analyzer Running"}

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    try:
        content = await file.read()
        policy = json.loads(content)

        if "Statement" not in policy:
            return {"error": "Invalid IAM Policy: Missing 'Statement'"}

        result = analyze_policy(policy)
        return result

    except json.JSONDecodeError:
        return {"error": "Invalid JSON file"}

    except Exception as e:
        return {"error": str(e)}


@app.post("/upload")
async def upload_policy(file: UploadFile = File(...)):
    return {"test": "coming from render"}
