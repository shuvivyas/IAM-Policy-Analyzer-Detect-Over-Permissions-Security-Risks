from fastapi import FastAPI, File, UploadFile
import json

app = FastAPI()

# Severity priority
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
            if "Principal" in stmt:
                return "Resource-Based Policy"

        return "Identity-Based Policy"
    except:
        return "Unknown"


@app.post("/analyze")
async def analyze_policy(file: UploadFile = File(...)):
    content = await file.read()
    policy = json.loads(content)

    findings = []
    severities = []

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # 🚨 CRITICAL: Full wildcard
        if "*" in actions and "*" in resources:
            findings.append("Full wildcard access (*:*)")
            severities.append("CRITICAL")
            continue  # no need to check further

        # 🔥 HIGH: wildcard action
        if "*" in actions:
            findings.append("Wildcard action detected")
            severities.append("HIGH")

        # 🔥 HIGH: IAM full access
        for action in actions:
            if action.startswith("iam:"):
                findings.append("Sensitive IAM permission detected")
                severities.append("HIGH")
                break

        # 🟠 MEDIUM: wildcard resource
        if "*" in resources:
            findings.append("Resource is too broad (*)")
            severities.append("MEDIUM")

        # 🟠 MEDIUM: destructive S3 actions
        for action in actions:
            if action in ["s3:PutObject", "s3:DeleteObject"]:
                findings.append("Destructive S3 permission detected")
                severities.append("MEDIUM")
                break

    # ✅ FINAL SEVERITY = MAX (NOT SUM)
    if severities:
        final_severity = max(severities, key=lambda x: priority[x])
    else:
        final_severity = "LOW"

    policy_type = detect_policy_type(policy)

    return {
        "policy_type": policy_type,
        "severity": final_severity,
        "findings": list(set(findings))  # remove duplicates
    }
