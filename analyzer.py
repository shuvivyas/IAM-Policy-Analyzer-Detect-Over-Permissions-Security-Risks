# def analyze_policy(policy):
#     findings = []

#     statements = policy.get("Statement", [])

#     if not isinstance(statements, list):
#         statements = [statements]

#     for stmt in statements:
#         action = stmt.get("Action", [])
#         resource = stmt.get("Resource", [])
#         effect = stmt.get("Effect", "")

#         # Normalize to list
#         if isinstance(action, str):
#             action = [action]
#         if isinstance(resource, str):
#             resource = [resource]

#         # Rule 1: Action = "*"
#         if "*" in action:
#             findings.append({
#                 "issue": "Wildcard Action (*)",
#                 "risk": "High",
#                 "fix": "Specify only required actions like s3:GetObject"
#             })

#         # Rule 2: Resource = "*"
#         if "*" in resource:
#             findings.append({
#                 "issue": "Wildcard Resource (*)",
#                 "risk": "High",
#                 "fix": "Restrict to specific resources"
#             })

#         # Rule 3: Both = "*"
#         if "*" in action and "*" in resource:
#             findings.append({
#                 "issue": "Full Admin Access",
#                 "risk": "Critical",
#                 "fix": "Apply least privilege principle"
#             })

#         # Rule 4: Sensitive services
#         sensitive = ["iam:*", "sts:*"]
#         for a in action:
#             if a in sensitive:
#                 findings.append({
#                     "issue": f"Sensitive permission ({a})",
#                     "risk": "High",
#                     "fix": "Avoid giving full IAM/STS access"
#                 })

#     return findings

def analyze_policy(policy):
    findings = []
    total_score = 0

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    def add_finding(issue, risk, score, fix):
        nonlocal total_score

        if issue not in seen_issues:
            seen_issues.add(issue)
            findings.append({
                "issue": issue,
                "risk": risk,
                "score": score,
                "fix": fix
            })
            total_score += score
            
    for stmt in statements:
        action = stmt.get("Action", [])
        resource = stmt.get("Resource", [])
        effect = stmt.get("Effect", "")

        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]

        # --- RULE 1: Wildcard Action ---
        if "*" in action:
            findings.append({
                "issue": "Wildcard Action (*)",
                "risk": "High",
                "score": 80,
                "fix": "Specify only required actions"
            })
            total_score += 80

        # --- RULE 2: Wildcard Resource ---
        if "*" in resource:
            findings.append({
                "issue": "Wildcard Resource (*)",
                "risk": "High",
                "score": 75,
                "fix": "Restrict to specific resources"
            })
            total_score += 75

        # --- RULE 3: Full Admin ---
        if "*" in action and "*" in resource and effect == "Allow":
            findings.append({
                "issue": "Full Admin Access",
                "risk": "Critical",
                "score": 100,
                "fix": "Apply least privilege"
            })
            total_score += 100

        # --- RULE 4: Privilege Escalation ---
        escalation_actions = [
            "iam:PassRole",
            "iam:AttachRolePolicy",
            "iam:PutRolePolicy",
            "sts:AssumeRole"
        ]

        for a in action:
            if a in escalation_actions:
                findings.append({
                    "issue": f"Privilege Escalation Risk ({a})",
                    "risk": "Critical",
                    "score": 95,
                    "fix": "Restrict role modification permissions"
                })
                total_score += 95

        # --- RULE 5: Sensitive Services ---
        sensitive = ["iam:*", "sts:*", "organizations:*"]
        for a in action:
            if a in sensitive:
                findings.append({
                    "issue": f"Sensitive Permission ({a})",
                    "risk": "High",
                    "score": 85,
                    "fix": "Limit access to sensitive services"
                })
                total_score += 85

        # --- RULE 6: Dangerous Write/Delete ---
        dangerous = [
            "s3:PutObject",
            "s3:DeleteObject",
            "ec2:TerminateInstances"
        ]

        for a in action:
            if a in dangerous:
                findings.append({
                    "issue": f"Destructive Action ({a})",
                    "risk": "Medium",
                    "score": 60,
                    "fix": "Restrict destructive permissions"
                })
                total_score += 60

    # --- Overall Risk ---
    if total_score >= 150:
        overall = "Critical"
    elif total_score >= 100:
        overall = "High"
    elif total_score >= 50:
        overall = "Medium"
    else:
        overall = "Low"

    return {
        "overall_risk": overall,
        "total_score": total_score,
        "findings": findings
    }