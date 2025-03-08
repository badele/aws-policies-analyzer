#!/usr/bin/env python3

import argparse

from aws_policies_analyzer import (
    query_by_action,
    query_by_policy,
    query_by_role,
    sync_policies,
    to_json,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="AWS IAM Policies CLI Tool")

    # Main commands
    main_group = parser.add_mutually_exclusive_group(required=True)
    main_group.add_argument(
        "--by-role",
        type=str,
        nargs="+",
        help="Search by role (can take multiple values)",
    )
    main_group.add_argument(
        "--by-policy",
        type=str,
        nargs="+",
        help="Search by policy(ARN) (can take multiple values)",
    )
    main_group.add_argument(
        "--by-action",
        type=str,
        nargs="+",
        help="Search by action (can take multiple values)",
    )
    main_group.add_argument(
        "--sync-policies",
        action="store_true",
        help="Force synchronization of all AWS policies, roles, and cross-reference data",
    )

    # Options
    parser.add_argument("--force-cache", action="store_true", help="Force cache update")

    args = parser.parse_args()

    # Command processing
    if args.by_role:
        print(to_json(query_by_role(args.by_role, force_refresh=args.force_cache)))
    elif args.by_policy:
        print(to_json(query_by_policy(args.by_policy, force_refresh=args.force_cache)))
    elif args.by_action:
        print(to_json(query_by_action(args.by_action, force_refresh=args.force_cache)))
    elif args.sync_policies:
        result = sync_policies()
        print(to_json(result))
    else:
        print("Error: Command not recognized")


if __name__ == "__main__":
    main()
