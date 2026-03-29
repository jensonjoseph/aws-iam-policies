#!/usr/bin/env python3
"""Validates IAM policy files for least privilege compliance."""

import json
import sys
from pathlib import Path

# Actions that must never use wildcard resources
SENSITIVE_ACTIONS_PREFIXES = [
    "iam:", "sts:", "kms:", "secretsmanager:", "ssm:",
    "ec2:Terminate", "ec2:Delete", "rds:Delete", "s3:Delete",
    "dynamodb:Delete", "lambda:Delete", "cloudformation:Delete"
]

WILDCARD_ACTION_EXCEPTIONS = []  # Add any org-approved exceptions here

errors = []
warnings = []


def check_policy(path: str) -> bool:
    """Returns True if policy is valid."""
    file_path = Path(path)
    ok = True

    print(f"\n--- Validating: {path} ---")

    # 1. Parse JSON
    try:
        with open(file_path) as f:
            policy = json.load(f)
    except json.JSONDecodeError as e:
        errors.append(f"{path}: Invalid JSON — {e}")
        return False
    except FileNotFoundError:
        errors.append(f"{path}: File not found")
        return False

    # 2. Check top-level structure
    if "Version" not in policy:
        errors.append(f"{path}: Missing 'Version' field (should be '2012-10-17')")
        ok = False

    if "Statement" not in policy or not isinstance(policy["Statement"], list):
        errors.append(f"{path}: Missing or invalid 'Statement' field")
        return False

    for i, stmt in enumerate(policy["Statement"]):
        sid = stmt.get("Sid", f"Statement[{i}]")
        effect = stmt.get("Effect", "")
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # 3. No NotAction / NotResource
        if "NotAction" in stmt:
            errors.append(f"{path} [{sid}]: 'NotAction' is not allowed — use explicit Allow with specific actions")
            ok = False
        if "NotResource" in stmt:
            errors.append(f"{path} [{sid}]: 'NotResource' is not allowed — use explicit Allow with specific resources")
            ok = False

        if effect != "Allow":
            continue  # Deny statements are fine with wildcards

        # 4. No wildcard actions
        for action in actions:
            if action == "*":
                errors.append(f"{path} [{sid}]: Wildcard action '*' is not allowed")
                ok = False
            elif action.endswith(":*") and action not in WILDCARD_ACTION_EXCEPTIONS:
                errors.append(f"{path} [{sid}]: Wildcard action '{action}' is not allowed — specify individual actions")
                ok = False

        # 5. No wildcard resource with sensitive actions
        has_wildcard_resource = "*" in resources
        if has_wildcard_resource:
            for action in actions:
                for prefix in SENSITIVE_ACTIONS_PREFIXES:
                    if action.lower().startswith(prefix.lower()):
                        errors.append(
                            f"{path} [{sid}]: Sensitive action '{action}' cannot use wildcard Resource '*'"
                        )
                        ok = False
                        break
            # Warn (not error) for non-sensitive wildcard resources
            non_sensitive = [
                a for a in actions
                if not any(a.lower().startswith(p.lower()) for p in SENSITIVE_ACTIONS_PREFIXES)
            ]
            if non_sensitive:
                warnings.append(
                    f"{path} [{sid}]: Actions {non_sensitive} use wildcard Resource '*' — consider scoping to specific ARNs"
                )

        # 6. Conditions encouraged for sensitive actions
        if "Condition" not in stmt and has_wildcard_resource:
            warnings.append(f"{path} [{sid}]: Consider adding Conditions to restrict this statement further")

    if ok:
        print(f"  PASS")
    return ok


def main():
    files = [f for f in sys.argv[1:] if f.endswith(".json")]

    if not files:
        print("No policy files to validate.")
        sys.exit(0)

    results = [check_policy(f) for f in files]

    if warnings:
        print("\n⚠️  Warnings:")
        for w in warnings:
            print(f"  - {w}")

    if errors:
        print("\n❌ Errors:")
        for e in errors:
            print(f"  - {e}")
        print(f"\nValidation FAILED ({len(errors)} error(s))")
        sys.exit(1)

    print(f"\n✅ All {len(files)} policy file(s) passed validation.")
    if warnings:
        print(f"   ({len(warnings)} warning(s) — review recommended)")


if __name__ == "__main__":
    main()
