# IAM Policy Analyzer: Detect Over-Permissions & Security Risks

## Overview

This project is a full-stack security tool built to analyze AWS IAM policy documents and identify risky permission patterns.

It allows users to upload IAM policy JSON files through an interactive web interface. The system processes the policy, detects misconfigurations such as wildcard (`*`) access and overly broad permissions, and provides actionable recommendations to enforce least-privilege access.

The project focuses on implementing practical cloud security concepts such as permission analysis, risk detection, and policy optimization in a simple and effective way. It is designed as a demonstration of security auditing techniques commonly used in real-world applications.

---

## Features

* Detects over-permissive IAM policies  
* Flags wildcard actions (`*`) and resource access  
* Identifies admin-level privileges  
* Suggests least-privilege fixes  
* Upload IAM policy JSON for analysis  
* Interactive web interface  

---

## Tech Stack

* Python (FastAPI, Streamlit)  
* Uvicorn  

---

## Tools Used

- Streamlit (UI)  
- REST API (FastAPI)  
- JSON processing  

---

## Setup Instructions

### 1. Clone the repository
```
git clone https://github.com/your-username/iam-policy-analyzer.git
cd iam-policy-analyzer
```
### 2. Install dependencies
```
pip install -r requirements.txt
```
### 3. Run Backend
```
uvicorn main:app --reload
```
### 4. Run Frontend
```
streamlit run app.py
```

---

## How It Works

1. Upload an AWS IAM policy JSON file  
2. The frontend sends the policy to the backend  
3. The backend analyzes:
   - Wildcard permissions (`*`)  
   - Overly broad actions and resources  
   - Admin-level access  
4. Returns detected risks and suggested fixes  
5. Results are displayed in the UI  

---

## Example Checks

* `"Action": "*"` → Full access risk  
* `"Resource": "*"` → Unrestricted access  
* Broad `"Allow"` permissions → Potential privilege escalation  

---

## Notes

- Ensure valid IAM JSON format  
- Backend URL must be correctly configured  
- Designed for learning and demonstration purposes  

---