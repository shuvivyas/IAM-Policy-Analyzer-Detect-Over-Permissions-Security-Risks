def analyze_policy(policy):
    findings = []
    severities = []

    priority = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    policy_tags = []

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # 🔴 CRITICAL
        if "*" in actions and "*" in resources:
            findings.append({
                "issue": "Full wildcard access (*:*)",
                "risk": "CRITICAL",
                "fix": "Avoid using '*' for both Action and Resource",
                "attack": "Privilege escalation / Account takeover",
                "context": "Gives complete control over all AWS services"
            })
            severities.append("CRITICAL")
            policy_tags.append("Admin Policy")
            continue

        # 🔥 HIGH (IAM full access)
        for action in actions:
            if isinstance(action, str) and action.startswith("iam:"):
                findings.append({
                    "issue": "Sensitive IAM permission detected",
                    "risk": "HIGH",
                    "fix": "Restrict IAM permissions",
                    "attack": "Privilege escalation",
                    "context": "IAM access can lead to full account control"
                })
                severities.append("HIGH")
                policy_tags.append("Over-Permissive Policy")
                break

        # 🔥 AWS service context
        for action in actions:
            if action == "s3:*":
                findings.append({
                    "issue": "Full S3 access",
                    "risk": "HIGH",
                    "fix": "Limit S3 permissions",
                    "attack": "Data exfiltration",
                    "context": "Full access to S3 can expose sensitive data"
                })
                severities.append("HIGH")

            if action == "ec2:*":
                findings.append({
                    "issue": "Full EC2 access",
                    "risk": "HIGH",
                    "fix": "Restrict EC2 permissions",
                    "attack": "Infrastructure takeover",
                    "context": "Can launch/modify compute resources"
                })
                severities.append("HIGH")

        # 🟠 MEDIUM
        if "*" in resources:
            findings.append({
                "issue": "Resource is too broad (*)",
                "risk": "MEDIUM",
                "fix": "Restrict to specific resources",
                "attack": "Data exposure",
                "context": "Applies to all resources"
            })
            severities.append("MEDIUM")

        for action in actions:
            if isinstance(action, str) and action in ["s3:PutObject", "s3:DeleteObject"]:
                findings.append({
                    "issue": "Destructive S3 permission detected",
                    "risk": "MEDIUM",
                    "fix": "Limit write/delete access",
                    "attack": "Data tampering",
                    "context": "Allows modifying or deleting data"
                })
                severities.append("MEDIUM")
                break

    if severities:
        final_severity = max(severities, key=lambda x: priority[x])
    else:
        final_severity = "LOW"

    # 🎯 Policy classification
    if "Admin Policy" in policy_tags:
        policy_label = "Admin Policy"
    elif "Over-Permissive Policy" in policy_tags:
        policy_label = "Over-Permissive Policy"
    else:
        policy_label = "Least Privilege Policy"

    return {
        "policy_type": policy_label,
        "severity": final_severity,
        "risk_score": priority[final_severity] * 50,
        "findings": findings
    }
