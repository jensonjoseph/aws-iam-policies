#!/usr/bin/env python3
"""Deploys IAM policy files to AWS. Creates new policy or a new version if it already exists."""

import json
import sys
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

iam = boto3.client("iam")


def policy_name_from_path(path: str) -> str:
    """Derives a policy name from the file path, e.g. policies/s3/read-only.json -> s3-read-only"""
    p = Path(path)
    parts = p.relative_to("policies").with_suffix("").parts
    return "-".join(parts)


def get_account_id() -> str:
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]


def deploy_policy(path: str, account_id: str):
    policy_name = policy_name_from_path(path)
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"

    with open(path) as f:
        document = f.read()

    # Validate JSON before sending to AWS
    json.loads(document)

    try:
        # Try to get existing policy
        iam.get_policy(PolicyArn=policy_arn)
        policy_exists = True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            policy_exists = False
        else:
            raise

    if policy_exists:
        # Rotate versions — IAM allows max 5; delete oldest non-default if needed
        versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
        non_default = [v for v in versions if not v["IsDefaultVersion"]]
        if len(versions) >= 5:
            oldest = sorted(non_default, key=lambda v: v["CreateDate"])[0]
            iam.delete_policy_version(PolicyArn=policy_arn, VersionId=oldest["VersionId"])
            print(f"  Deleted old version {oldest['VersionId']} of {policy_name}")

        response = iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=document,
            SetAsDefault=True
        )
        version = response["PolicyVersion"]["VersionId"]
        print(f"  Updated policy '{policy_name}' -> {version} ({policy_arn})")
    else:
        response = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=document,
            Description=f"Managed by GitHub — {path}"
        )
        print(f"  Created policy '{policy_name}' ({policy_arn})")


def main():
    files = [f for f in sys.argv[1:] if f.endswith(".json") and f.startswith("policies/")]

    if not files:
        print("No policy files to deploy.")
        sys.exit(0)

    account_id = get_account_id()
    print(f"Deploying to AWS account: {account_id}\n")

    failed = []
    for f in files:
        print(f"--- Deploying: {f} ---")
        try:
            deploy_policy(f, account_id)
        except Exception as e:
            print(f"  ERROR: {e}")
            failed.append(f)

    if failed:
        print(f"\n❌ Failed to deploy: {failed}")
        sys.exit(1)

    print(f"\n✅ Successfully deployed {len(files)} policy file(s).")


if __name__ == "__main__":
    main()
