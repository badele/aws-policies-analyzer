#!/usr/bin/env python3

import argparse
import json
import os
import sys
from typing import List, Dict, Union, Any

import boto3

POLICIES_CACHE_FILE = "aws_policies_cache.json"
ROLES_CACHE_FILE = "aws_roles_cache.json"
CROSS_REF_CACHE_FILE = "aws_cross_ref_cache.json"


# Convert python object to json string
def to_json(obj):
    return json.dumps(obj, indent=4, ensure_ascii=False)


# Get all managed AWS policies
def get_all_policies(force_refresh=False):
    if not force_refresh and os.path.exists(POLICIES_CACHE_FILE):
        with open(POLICIES_CACHE_FILE, "r") as f:
            return json.loads(f.read())

    session = boto3.Session()
    iam_client = session.client("iam")

    paginator = iam_client.get_paginator("list_policies")
    policies = []

    for page in paginator.paginate(Scope="ALL"):
        for policy in page["Policies"]:
            policy_arn = policy["Arn"]
            policy_name = policy["PolicyName"]

            policy_version = iam_client.get_policy_version(
                PolicyArn=policy_arn, VersionId=policy["DefaultVersionId"]
            )
            document = policy_version["PolicyVersion"]["Document"]
            statements = document.get("Statement", [])

            actions = []
            for statement in statements:
                if "Action" in statement:
                    try:
                        actions.extend(
                            statement["Action"]
                            if isinstance(statement["Action"], list)
                            else [statement["Action"]]
                        )
                    except TypeError:
                        pass

            policies.append(
                {
                    "PolicyArn": policy_arn,
                    "PolicyName": policy_name,
                    "Actions": actions,
                }
            )

    with open(POLICIES_CACHE_FILE, "w") as f:
        f.write(to_json(policies))

    return policies

def get_all_roles(force_refresh=False) -> List[Dict[str, Any]]:
    """
    Retrieves all IAM roles with their attached policies.

    Args:
        force_refresh: Force the update of the AWS roles cache

    Returns:
        A list of IAM roles with their attached policies
    """
    if not force_refresh and os.path.exists(ROLES_CACHE_FILE):
        with open(ROLES_CACHE_FILE, "r") as f:
            return json.loads(f.read())

    session = boto3.Session()
    iam_client = session.client("iam")

    paginator = iam_client.get_paginator("list_roles")
    roles = []

    # Retrieve all roles
    for page in paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]
            
            # Retrieve policies attached to the role
            response = iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = response.get("AttachedPolicies", [])
            
            policies = []
            for policy in attached_policies:
                policies.append(
                    {
                        "PolicyArn": policy["PolicyArn"],
                        "PolicyName": policy["PolicyName"],
                    }
                )
            
            # Add the role with its attached policies
            roles.append(
                {
                    "RoleName": role["RoleName"],
                    "RoleId": role["RoleId"],
                    "Arn": role["Arn"],
                    "Path": role["Path"],
                    "CreateDate": role["CreateDate"].strftime("%Y-%m-%d %H:%M:%S"),
                    "Description": role.get("Description", ""),
                    "AttachedPolicies": policies,
                }
            )

    with open(ROLES_CACHE_FILE, "w") as f:
        f.write(to_json(roles))

    return roles

def build_cross_reference_table(force_refresh=False) -> Dict[str, Dict[str, Any]]:
    """
    Builds a dynamic cross-reference table that allows navigation between roles, policies, and actions.
    Uses a caching system to avoid rebuilding the table on each call.
    
    Args:
        force_refresh: Force the update of policies, roles, and cross-reference table caches
        
    Returns:
        A dictionary with three main keys ('roles', 'policies', 'actions') containing
        the relationships between these entities to allow searches in all directions.
    """
    # Check if the cache exists and if we're not forcing a refresh
    if not force_refresh and os.path.exists(CROSS_REF_CACHE_FILE):
        # Check if the policy and role caches are more recent than the cross-reference table cache
        cross_ref_mtime = os.path.getmtime(CROSS_REF_CACHE_FILE)
        policies_cache_exists = os.path.exists(POLICIES_CACHE_FILE)
        roles_cache_exists = os.path.exists(ROLES_CACHE_FILE)
        
        # If both caches exist, check their modification dates
        if policies_cache_exists and roles_cache_exists:
            policies_mtime = os.path.getmtime(POLICIES_CACHE_FILE)
            roles_mtime = os.path.getmtime(ROLES_CACHE_FILE)
            
            # If the cross-reference table cache is more recent than the policy and role caches,
            # we can use the cross-reference table cache
            if cross_ref_mtime >= policies_mtime and cross_ref_mtime >= roles_mtime:
                with open(CROSS_REF_CACHE_FILE, "r") as f:
                    return json.loads(f.read())
    
    # If we get here, we need to rebuild the cross-reference table
    # Retrieve all policies and all roles
    all_policies = get_all_policies(force_refresh=force_refresh)
    all_roles = get_all_roles(force_refresh=force_refresh)
    
    # Initialize the data structure
    cross_ref = {
        'roles': {},      # role_name -> {policies: [], actions: []}
        'policies': {},   # policy_arn -> {roles: [], actions: []}
        'actions': {}     # action -> {roles: [], policies: []}
    }
    
    # Build policy -> actions relationships
    for policy in all_policies:
        policy_arn = policy['PolicyArn']
        policy_name = policy['PolicyName']
        actions = policy.get('Actions', [])
        
        # Add the policy to the 'policies' section
        if policy_arn not in cross_ref['policies']:
            cross_ref['policies'][policy_arn] = {
                'name': policy_name,
                'roles': [],
                'actions': actions
            }
        
        # For each action, add this policy
        for action in actions:
            if action not in cross_ref['actions']:
                cross_ref['actions'][action] = {
                    'roles': [],
                    'policies': []
                }
            
            # Add this policy to the action
            if policy_arn not in cross_ref['actions'][action]['policies']:
                cross_ref['actions'][action]['policies'].append(policy_arn)
    
    # Build role -> policies and role -> actions relationships
    for role in all_roles:
        role_name = role['RoleName']
        role_arn = role['Arn']
        attached_policies = role.get('AttachedPolicies', [])
        
        # Add the role to the 'roles' section
        if role_name not in cross_ref['roles']:
            cross_ref['roles'][role_name] = {
                'arn': role_arn,
                'policies': [],
                'actions': []
            }
        
        # For each attached policy
        for policy in attached_policies:
            policy_arn = policy['PolicyArn']
            
            # Add this policy to the role
            if policy_arn not in cross_ref['roles'][role_name]['policies']:
                cross_ref['roles'][role_name]['policies'].append(policy_arn)
            
            # Add this role to the policy
            if policy_arn in cross_ref['policies']:
                if role_name not in cross_ref['policies'][policy_arn]['roles']:
                    cross_ref['policies'][policy_arn]['roles'].append(role_name)
                
                # Add the actions of this policy to the role
                actions = cross_ref['policies'][policy_arn]['actions']
                for action in actions:
                    if action not in cross_ref['roles'][role_name]['actions']:
                        cross_ref['roles'][role_name]['actions'].append(action)
                    
                    # Add this role to the action
                    if action in cross_ref['actions']:
                        if role_name not in cross_ref['actions'][action]['roles']:
                            cross_ref['actions'][action]['roles'].append(role_name)
    
    # Save the cross-reference table in the cache
    with open(CROSS_REF_CACHE_FILE, "w") as f:
        f.write(to_json(cross_ref))
    
    return cross_ref





def query_by_role(role_names: Union[str, List[str]], force_refresh=False) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Retrieves policies and actions associated with one or more specific roles.
    
    Args:
        role_names: The role name or a list of role names to search for
        force_refresh: Force the update of caches
        
    Returns:
        A dictionary or a list of dictionaries containing policies and actions associated with the roles
    """
    cross_ref = build_cross_reference_table(force_refresh=force_refresh)
    
    # Convert to list if it's a single string
    if isinstance(role_names, str):
        role_names = [role_names]
    
    results = []
    for role_name in role_names:
        if role_name not in cross_ref['roles']:
            results.append(None)
            continue
        
        results.append({
            'role': role_name,
            'policies': cross_ref['roles'][role_name]['policies'],
            'actions': cross_ref['roles'][role_name]['actions']
        })
    
    # If only one role was requested, return the result directly
    if len(results) == 1:
        return results[0]
    
    return results


def query_by_policy(policy_arns: Union[str, List[str]], force_refresh=False) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Retrieves roles and actions associated with one or more specific policies.
    
    Args:
        policy_arns: The policy ARN or a list of policy ARNs to search for
        force_refresh: Force the update of caches
        
    Returns:
        A dictionary or a list of dictionaries containing roles and actions associated with the policies
    """
    cross_ref = build_cross_reference_table(force_refresh=force_refresh)
    
    # Convert to list if it's a single string
    if isinstance(policy_arns, str):
        policy_arns = [policy_arns]
    
    results = []
    for policy_arn in policy_arns:
        if policy_arn not in cross_ref['policies']:
            results.append(None)
            continue
        
        results.append({
            'roles': cross_ref['policies'][policy_arn]['roles'],
            'policy': policy_arn,
            'actions': cross_ref['policies'][policy_arn]['actions'],
            'name': cross_ref['policies'][policy_arn]['name'],
        })
    
    # If only one policy was requested, return the result directly
    if len(results) == 1:
        return results[0]
    
    return results


def query_by_action(actions: Union[str, List[str]], force_refresh=False) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Retrieves roles and policies associated with one or more specific actions.
    
    Args:
        actions: The action or a list of actions to search for
        force_refresh: Force the update of caches
        
    Returns:
        A dictionary or a list of dictionaries containing roles and policies associated with the actions
    """
    cross_ref = build_cross_reference_table(force_refresh=force_refresh)
    
    # Convert to list if it's a single string
    if isinstance(actions, str):
        actions = [actions]
    
    results = []
    for action in actions:
        if action not in cross_ref['actions']:
            results.append(None)
            continue
        
        results.append({
            'roles': cross_ref['actions'][action]['roles'],
            'policies': cross_ref['actions'][action]['policies'],
            'action': action,
        })
    
    # If only one action was requested, return the result directly
    if len(results) == 1:
        return results[0]
    
    return results


def read_stdin() -> List[str]:
    """
    Reads data from standard input if available.

    Returns:
        A list of strings read from stdin
    """
    if not sys.stdin.isatty():
        return sys.stdin.read().strip().split()
    return []


def main():
    parser = argparse.ArgumentParser(description="AWS IAM Policies CLI Tool")

    # Main commands
    main_group = parser.add_mutually_exclusive_group(required=True)
    main_group.add_argument("--by-role", type=str, nargs='+', help="Search by role (can take multiple values)")
    main_group.add_argument(
        "--by-policy", type=str, nargs='+', help="Search by policy(ARN) (can take multiple values)"
    )
    main_group.add_argument(
        "--by-action",
        type=str,
        nargs='+',
        help="Search by action (can take multiple values)",
    )

    # Options
    parser.add_argument(
        "--force-cache", action="store_true", help="Force cache update"
    )

    args = parser.parse_args()

    # Command processing
    if args.by_role:
        print(to_json(query_by_role(args.by_role, force_refresh=args.force_cache)))
    elif args.by_policy:
        print(to_json(query_by_policy(args.by_policy, force_refresh=args.force_cache)))
    elif args.by_action:
        print(to_json(query_by_action(args.by_action, force_refresh=args.force_cache)))
                                
    else:
        print("Error: Command not recognized")


if __name__ == "__main__":
    main()
