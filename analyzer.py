from fastapi import FastAPI, File, UploadFile
import json

app = FastAPI()

priority = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def detect_policy_type(policy):
    try:
        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for stmt in statements:
            if isinstance(stmt, dict) and "Principal" in stmt:
                return "Resource-Based Policy"

        return "Identity-Based Policy"
    except:
        return "Unknown"


@app.post("/analyze")
async def analyze_policy(file: UploadFile = File(...)):
    content = await file.read()

    # KEEP THIS SIMPLE (no decode changes)
    policy = json.loads(content)

    findings = []
    severities = []

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # 🚨 CRITICAL
        if "*" in actions and "*" in resources:
            findings.append("Full wildcard access (*:*)")
            severities.append("CRITICAL")
            continue

        # 🔥 HIGH
        if "*" in actions:
            findings.append("Wildcard action detected")
            severities.append("HIGH")

        for action in actions:
            if isinstance(action, str) and action.startswith("iam:"):
                findings.append("Sensitive IAM permission detected")
                severities.append("HIGH")
                break

        # 🟠 MEDIUM
        if "*" in resources:
            findings.append("Resource is too broad (*)")
            severities.append("MEDIUM")

        for action in actions:
            if isinstance(action, str) and action in ["s3:PutObject", "s3:DeleteObject"]:
                findings.append("Destructive S3 permission detected")
                severities.append("MEDIUM")
                break

    # ✅ FIXED: no score summing
    if severities:
        final_severity = max(severities, key=lambda x: priority[x])
    else:
        final_severity = "LOW"

    policy_type = detect_policy_type(policy)

    return {
        "policy_type": policy_type,
        "severity": final_severity,
        "findings": list(set(findings))
    }
