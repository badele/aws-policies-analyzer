# aws-policies-analyzer

A command-line tool for analyzing AWS IAM policies, roles, and their relationships.

## Description

This tool allows you to analyze the relationships between IAM roles, policies, and actions in your AWS account. It uses a caching system to avoid querying the AWS API each time it's used.

## Available Commands

The tool offers three main commands that allow you to explore the relationships between roles, policies, and actions.

### Main Commands

| Command       | Description                                                    |
| ------------- | -------------------------------------------------------------- |
| `--by-role`   | Find policies and actions associated with one or more roles    |
| `--by-policy` | Find roles and actions associated with one or more policies    |
| `--by-action` | Find roles and policies associated with one or more actions    |

### Additional Options

| Option          | Description                                |
| --------------- | ------------------------------------------ |
| `--force-cache` | Force the update of the AWS data cache     |

## Installation

- With Python: `pip install boto3`
- With Nix: `nix develop`

## Usage Examples

### Search by Role

Retrieve all policies and actions associated with a specific role:

```bash
python analyze.py --by-role AWSServiceRoleForAmazonEKS | jq
python analyze.py --by-role AWSServiceRoleForAmazonEKS | jq -r '.policies[]'
python analyze.py --by-role AWSServiceRoleForAmazonEKS | jq -r '.actions[]'
```

Or for multiple roles at once:

```bash
python analyze.py --by-role AWSServiceRoleForAmazonEKS AWSServiceRoleForAmazonSSM | jq
python analyze.py --by-role AWSServiceRoleForAmazonEKS AWSServiceRoleForAmazonSSM | jq -r '.[]["policies"][]'

# Detect same actions
python analyze.py --by-role AWSServiceRoleForAmazonEKS AWSServiceRoleForAmazonSSM | jq -r '.[]["actions"][]' | sort | uniq -d
```

### Search by Policy

Retrieve all roles and actions associated with a specific policy:

```bash
python analyze.py --by-policy arn:aws:iam::aws:policy/AdministratorAccess | jq
```

Or for multiple policies at once:

```bash
python analyze.py --by-policy arn:aws:iam::aws:policy/AmazonS3FullAccess arn:aws:iam::aws:policy/AmazonEC2FullAccess | jq
```

### Search by Action

Retrieve all roles and policies associated with a specific action:

```bash
python analyze.py --by-action iam:CreateServiceLinkedRole | jq
python analyze.py --by-action iam:CreateServiceLinkedRole | jq -r '.policies[]'
python analyze.py --by-action iam:CreateServiceLinkedRole | jq -r '.action'
```

Or for multiple actions at once:

```bash
# Search for common policies
python analyze.py --by-action s3:GetObject ec2:DescribeInstances | jq -r '.[]["policies"][]' | sort | uniq -d
```

### Force Cache Update

Force the cache update before performing the search:

```bash
python analyze.py --by-role AWSServiceRoleForAmazonEKS --force-cache | jq
```

## Output Format

All commands return data in JSON format, which allows them to be easily processed with tools like `jq`.

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
- `aws_cross_ref_cache.json`: Cache of the cross-reference table of relationships

The cache is automatically updated when necessary, but you can force its update with the `--force-cache` option.
