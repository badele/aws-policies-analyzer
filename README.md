# aws-policies-analyzer

A command-line tool for analyzing AWS IAM policies, roles, and their relationships.

## Description

This tool allows you to analyze the relationships between IAM roles, policies, and actions in your AWS account. It uses a caching system to avoid querying the AWS API each time it's used.

## Available Commands

The tool offers three main commands that allow you to explore the relationships between roles, policies, and actions.

### Main Commands

| Command       | Description                                                 |
| ------------- | ----------------------------------------------------------- |
| `--by-role`   | Find policies and actions associated with one or more roles |
| `--by-policy` | Find roles and actions associated with one or more policies |
| `--by-action` | Find roles and policies associated with one or more actions |

### Additional Options

| Option            | Description                            |
| ----------------- | -------------------------------------- |
| `--sync-policies` | Force the update of the AWS data cache |

## Installation

```bash
# Normal installation
just install

# Development environment installation
just dev
```

## Force Cache Update

Force the cache update before performing the search:

You must at least execute it once

```bash
aws_policies_analyzer --sync-policies
```

```text
{
    "policies_count": 1386,
    "roles_count": 67,
    "actions_count": 12932
}
```

## Usage Examples

### Search by Role

Retrieve all policies and actions associated with a specific role:

```bash
aws_policies_analyzer --by-role AWSServiceRoleForAmazonEKS | jq
aws_policies_analyzer --by-role AWSServiceRoleForAmazonEKS | jq -r '.[].policies[]'
aws_policies_analyzer --by-role AWSServiceRoleForAmazonEKS | jq -r '.[].actions[]'
```

Or for multiple roles at once:

```bash
aws_policies_analyzer --by-role AWSServiceRoleForAmazonEKS AWSServiceRoleForAmazonSSM | jq
aws_policies_analyzer --by-role AWSServiceRoleForAmazonEKS AWSServiceRoleForAmazonSSM | jq -r '.[]["policies"][]'

# Detect same actions
aws_policies_analyzer --by-role AWSServiceRoleForAmazonEKS AWSServiceRoleForAmazonSSM | jq -r '.[]["actions"][]' | sort | uniq -d
```

### Search by Policy

Retrieve all roles and actions associated with a specific policy:

```bash
aws_policies_analyzer --by-policy arn:aws:iam::aws:policy/AdministratorAccess | jq
```

Or for multiple policies at once:

```bash
aws_policies_analyzer --by-policy arn:aws:iam::aws:policy/AmazonS3FullAccess arn:aws:iam::aws:policy/AmazonEC2FullAccess | jq
```

### Search by Action

Retrieve all roles and policies associated with a specific action:

```bash
aws_policies_analyzer --by-action iam:CreateServiceLinkedRole | jq
aws_policies_analyzer --by-action iam:CreateServiceLinkedRole | jq -r '.[].policies[]'
aws_policies_analyzer --by-action iam:CreateServiceLinkedRole | jq -r '.[].action'
```

Or for multiple actions at once:

```bash
# Search common policies
aws_policies_analyzer --by-action s3:GetObject ec2:DescribeInstances | jq -r '.[]["policies"][]' | sort | uniq -d
```

## Output Format

All commands return data in JSON format, which allows them to be easily
processed with tools like `jq`.

### Example Output for `--by-role`

```json
{
    "role": "AWSServiceRoleForAmazonEKS",
    "policies": [
        "arn:aws:iam::aws:policy/aws-service-role/AmazonEKSServiceRolePolicy"
    ],
    "actions": [
        "ec2:CreateNetworkInterface",
        "ec2:DeleteNetworkInterface",
        ...
    ]
}
```

## Caching System

The tool uses three cache files to optimize performance:

- `aws_policies_cache.json`: Cache of AWS policies
- `aws_roles_cache.json`: Cache of IAM roles
- `aws_cross_ref_cache.json`: Cache of the cross-reference table of
  relationships

The cache is automatically updated when necessary, but you can force its update
with the `--sync-policies` option.

## Development environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```
