def analyze_policy(policy):
    findings = []
    total_score = 0

    attack_map = {
        "Wildcard Action (*)": "Privilege Escalation",
        "Wildcard Resource (*)": "Data Exposure",
        "Full Admin Access": "Account Takeover",
        "Full S3 Access": "Data Exfiltration",
        "Full IAM Access": "Privilege Escalation"
    }

    statements = policy.get("Statement", [])

    for stmt in statements:
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # 🔴 Wildcard Action
        if "*" in actions:
            findings.append({
                "issue": "Wildcard Action (*)",
                "risk": "Critical",
                "fix": "Avoid using '*' in Action. Specify only required actions.",
                "attack": attack_map["Wildcard Action (*)"]
            })
            total_score += 100

        # 🟠 Wildcard Resource
        if "*" in resources:
            findings.append({
                "issue": "Wildcard Resource (*)",
                "risk": "High",
                "fix": "Restrict Resource to specific ARNs.",
                "attack": attack_map["Wildcard Resource (*)"]
            })
            total_score += 80

        # 🔥 AWS Context Checks
        if any("iam:*" in a.lower() for a in actions):
            findings.append({
                "issue": "Full IAM Access",
                "risk": "Critical",
                "fix": "Limit IAM permissions to required actions.",
                "attack": attack_map["Full IAM Access"]
            })
            total_score += 100

        if any("s3:*" in a.lower() for a in actions):
            findings.append({
                "issue": "Full S3 Access",
                "risk": "High",
                "fix": "Restrict S3 actions to required operations.",
                "attack": attack_map["Full S3 Access"]
            })
            total_score += 80

        # 🔴 Admin Access
        if "*" in actions and "*" in resources:
            findings.append({
                "issue": "Full Admin Access",
                "risk": "Critical",
                "fix": "Avoid full access policies. Follow least privilege.",
                "attack": attack_map["Full Admin Access"]
            })
            total_score += 120

    # 🎯 Overall Risk
    if total_score >= 200:
        overall_risk = "Critical"
    elif total_score >= 100:
        overall_risk = "High"
    else:
        overall_risk = "Low"

    # 🧠 Policy Type Detection
    policy_type = "Secure Policy"

    if total_score >= 200:
        policy_type = "Over-Permissive Policy"
    elif any(f["issue"] == "Full Admin Access" for f in findings):
        policy_type = "Admin Policy"

    return {
        "overall_risk": overall_risk,
        "total_score": total_score,
        "policy_type": policy_type,
        "findings": findings
    }
