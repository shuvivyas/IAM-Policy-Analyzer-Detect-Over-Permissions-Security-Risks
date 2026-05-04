def analyze_policy(policy):
    findings = []
    severities = []

    priority = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    seen_issues = set()
    policy_tags = []

    statements = policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        effect = stmt.get("Effect", "Allow")
        if effect != "Allow":
            continue

        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        condition = stmt.get("Condition", None)

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        actions = [a.lower() for a in actions if isinstance(a, str)]

        def add_finding(issue, risk, fix, attack, context):
            if issue in seen_issues:
                return
            seen_issues.add(issue)

            findings.append({
                "issue": issue,
                "risk": risk,
                "fix": fix,
                "attack": attack,
                "context": context
            })
            severities.append(risk)

        if "*" in actions and "*" in resources:
            add_finding(
                "Full wildcard access (*:*)",
                "CRITICAL",
                "Avoid using '*' for both Action and Resource",
                "Privilege escalation / Account takeover",
                "Gives complete control over all AWS services"
            )
            policy_tags.append("Admin Policy")

        escalation_actions = [
            "iam:passrole",
            "sts:assumerole",
            "iam:attachuserpolicy",
            "iam:putuserpolicy",
            "iam:addusertogroup"
        ]

        for action in actions:
            if action in escalation_actions:
                add_finding(
                    "Privilege escalation path detected",
                    "CRITICAL",
                    "Restrict role passing and policy attachment permissions",
                    "Privilege escalation",
                    f"Action {action} can be abused to gain higher privileges"
                )
                policy_tags.append("Over-Permissive Policy")

        for action in actions:
            if action.startswith("iam:"):
                add_finding(
                    "Sensitive IAM permission detected",
                    "HIGH",
                    "Restrict IAM permissions",
                    "Privilege escalation",
                    "IAM access can lead to full account control"
                )
                policy_tags.append("Over-Permissive Policy")
                break

        for action in actions:
            if action == "s3:*":
                add_finding(
                    "Full S3 access",
                    "HIGH",
                    "Limit S3 permissions",
                    "Data exfiltration",
                    "Full access to S3 can expose sensitive data"
                )

            if action == "ec2:*":
                add_finding(
                    "Full EC2 access",
                    "HIGH",
                    "Restrict EC2 permissions",
                    "Infrastructure takeover",
                    "Can launch/modify compute resources"
                )

        if "*" in resources:
            add_finding(
                "Resource is too broad (*)",
                "MEDIUM",
                "Restrict to specific resources",
                "Data exposure",
                "Applies to all resources"
            )

        for action in actions:
            if action in ["s3:putobject", "s3:deleteobject"]:
                add_finding(
                    "Destructive S3 permission detected",
                    "MEDIUM",
                    "Limit write/delete access",
                    "Data tampering",
                    "Allows modifying or deleting data"
                )
                break

        if not condition:
            add_finding(
                "No condition restrictions",
                "LOW",
                "Add conditions like IP restriction or MFA",
                "Unauthorized access",
                "Policy has no conditional checks"
            )

    if severities:
        final_severity = max(severities, key=lambda x: priority[x])
    else:
        final_severity = "LOW"

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
