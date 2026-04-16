def analyze_policy(policy):
    findings = []
    severities = []

    priority = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    def detect_policy_type(policy):
        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for stmt in statements:
            if isinstance(stmt, dict) and "Principal" in stmt:
                return "Resource-Based Policy"

        return "Identity-Based Policy"

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

        # CRITICAL
        if "*" in actions and "*" in resources:
            findings.append({
                "issue": "Full wildcard access (*:*)",
                "risk": "CRITICAL",
                "fix": "Avoid using '*' for both Action and Resource"
            })
            severities.append("CRITICAL")
            continue

        # HIGH
        if "*" in actions:
            findings.append({
                "issue": "Wildcard action detected",
                "risk": "HIGH",
                "fix": "Specify exact actions instead of '*'"
            })
            severities.append("HIGH")

        for action in actions:
            if isinstance(action, str) and action.startswith("iam:"):
                findings.append({
                    "issue": "Sensitive IAM permission detected",
                    "risk": "HIGH",
                    "fix": "Restrict IAM permissions to minimum required"
                })
                severities.append("HIGH")
                break

        # MEDIUM
        if "*" in resources:
            findings.append({
                "issue": "Resource is too broad (*)",
                "risk": "MEDIUM",
                "fix": "Restrict access to specific resources"
            })
            severities.append("MEDIUM")

        for action in actions:
            if isinstance(action, str) and action in ["s3:PutObject", "s3:DeleteObject"]:
                findings.append({
                    "issue": "Destructive S3 permission detected",
                    "risk": "MEDIUM",
                    "fix": "Limit write/delete permissions"
                })
                severities.append("MEDIUM")
                break

    if severities:
        final_severity = max(severities, key=lambda x: priority[x])
    else:
        final_severity = "LOW"

    return {
        "policy_type": detect_policy_type(policy),
        "severity": final_severity,
        "risk_score": priority[final_severity] * 50,
        "findings": findings
    }
