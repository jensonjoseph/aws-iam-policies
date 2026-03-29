# AWS IAM Policies

This repository manages AWS IAM policies following the **least privilege principle**. All policies are validated on PR and automatically deployed to AWS on merge.

## Workflow

```
Developer authors policy → Opens PR → Automated validation runs → Peer review → Merge → Auto-deploy to AWS
```

## Adding a New Policy

1. Create a JSON file under `policies/<service>/<policy-name>.json`
2. Follow the [policy template](#policy-template) below
3. Open a PR — validation runs automatically
4. Get approval and merge — policy deploys automatically

## Policy Template

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DescriptiveName",
      "Effect": "Allow",
      "Action": [
        "service:SpecificAction"
      ],
      "Resource": "arn:aws:service:region:account-id:resource/specific-resource"
    }
  ]
}
```

## Least Privilege Rules

| Rule | Bad | Good |
|------|-----|------|
| No wildcard actions | `"s3:*"` | `"s3:GetObject"` |
| No wildcard resources with sensitive actions | `"Resource": "*"` | `"Resource": "arn:aws:s3:::my-bucket/*"` |
| No `NotAction` / `NotResource` | `"NotAction": [...]` | Use explicit Allow |
| Scoped conditions encouraged | _(none)_ | `"Condition": {...}` |

## Validation

The PR workflow (`validate.yml`) checks:
- Valid JSON structure
- No wildcard (`*`) actions
- No `*` resource paired with write/admin actions
- No `NotAction` or `NotResource` usage
- Correct IAM policy schema

## AWS Setup (One-Time)

Configure GitHub OIDC in your AWS account so GitHub Actions can assume a role without long-lived credentials:

```bash
# 1. Create the OIDC provider in AWS
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1

# 2. Create the deployment role (trust policy in iam/github-actions-trust-policy.json)
aws iam create-role \
  --role-name GitHubActions-IAMPolicyDeployer \
  --assume-role-policy-document file://iam/github-actions-trust-policy.json

# 3. Attach required permissions to the role
aws iam attach-role-policy \
  --role-name GitHubActions-IAMPolicyDeployer \
  --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
```

Then add these secrets/variables to the GitHub repository:

| Name | Type | Value |
|------|------|-------|
| `AWS_ACCOUNT_ID` | Variable | Your 12-digit AWS account ID |
| `AWS_REGION` | Variable | e.g. `us-east-1` |
