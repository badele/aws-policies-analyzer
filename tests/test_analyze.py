#!/usr/bin/env python3

import datetime
import json
from unittest.mock import MagicMock, mock_open, patch

import aws_policies_analyzer


# Tests for to_json function
def test_to_json() -> None:
    test_obj = {"key": "value", "list": [1, 2, 3]}
    result = aws_policies_analyzer.to_json(test_obj)
    assert json.loads(result) == test_obj

    nested_obj = {"nested": {"key": "value"}, "items": [{"id": 1}, {"id": 2}]}
    result = aws_policies_analyzer.to_json(nested_obj)
    assert json.loads(result) == nested_obj


# Tests for get_all_policies function
@patch("os.path.exists")
@patch(
    "builtins.open", new_callable=mock_open, read_data=json.dumps([{"test": "data"}])
)
def test_get_all_policies_with_cache(
    mock_file: MagicMock, mock_exists: MagicMock
) -> None:
    mock_exists.return_value = True
    result = aws_policies_analyzer.get_all_policies()
    assert result == [{"test": "data"}]
    mock_file.assert_called_once_with(aws_policies_analyzer.POLICIES_CACHE_FILE, "r")


@patch("boto3.Session")
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open)
def test_get_all_policies_without_cache(
    mock_file: MagicMock, mock_exists: MagicMock, mock_session: MagicMock
) -> None:
    mock_exists.return_value = False

    mock_client = MagicMock()
    mock_session.return_value.client.return_value = mock_client

    mock_paginator = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator

    mock_policy = {
        "Arn": "arn:aws:iam::aws:policy/TestPolicy",
        "PolicyName": "TestPolicy",
        "DefaultVersionId": "v1",
    }

    mock_paginator.paginate.return_value = [{"Policies": [mock_policy]}]

    mock_client.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {"Statement": [{"Action": ["s3:GetObject", "s3:PutObject"]}]}
        }
    }

    result = aws_policies_analyzer.get_all_policies()

    assert len(result) == 1
    assert result[0]["PolicyArn"] == mock_policy["Arn"]
    assert result[0]["PolicyName"] == mock_policy["PolicyName"]
    assert set(result[0]["Actions"]) == set(["s3:GetObject", "s3:PutObject"])


# Tests for get_all_roles function
@patch("os.path.exists")
@patch(
    "builtins.open", new_callable=mock_open, read_data=json.dumps([{"test": "data"}])
)
def test_get_all_roles_with_cache(mock_file: MagicMock, mock_exists: MagicMock) -> None:
    mock_exists.return_value = True
    result = aws_policies_analyzer.get_all_roles()
    assert result == [{"test": "data"}]
    mock_file.assert_called_once_with(aws_policies_analyzer.ROLES_CACHE_FILE, "r")


@patch("boto3.Session")
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open)
def test_get_all_roles_without_cache(
    mock_file: MagicMock, mock_exists: MagicMock, mock_session: MagicMock
) -> None:
    mock_exists.return_value = False

    mock_client = MagicMock()
    mock_session.return_value.client.return_value = mock_client

    mock_paginator = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator

    mock_role = {
        "RoleName": "TestRole",
        "RoleId": "AROAXXXXXXXXXXXXXXXXX",
        "Arn": "arn:aws:iam::123456789012:role/TestRole",
        "Path": "/",
        "CreateDate": datetime.datetime(2023, 1, 1, 12, 0, 0),
        "Description": "Test role",
    }

    mock_paginator.paginate.return_value = [{"Roles": [mock_role]}]

    mock_client.list_attached_role_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyArn": "arn:aws:iam::aws:policy/TestPolicy",
                "PolicyName": "TestPolicy",
            }
        ]
    }

    result = aws_policies_analyzer.get_all_roles()

    assert len(result) == 1
    assert result[0]["RoleName"] == mock_role["RoleName"]
    assert result[0]["CreateDate"] == "2023-01-01 12:00:00"
    assert len(result[0]["AttachedPolicies"]) == 1


# Tests for build_cross_reference_table function
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open, read_data=json.dumps({"test": "data"}))
def test_build_cross_reference_table_with_valid_cache(
    mock_file: MagicMock, mock_exists: MagicMock
) -> None:
    mock_exists.return_value = True

    result = aws_policies_analyzer.build_cross_reference_table()
    assert result == {"test": "data"}


@patch("aws_policies_analyzer.get_all_policies")
@patch("aws_policies_analyzer.get_all_roles")
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open)
def test_build_cross_reference_table_from_scratch(
    mock_file: MagicMock,
    mock_exists: MagicMock,
    mock_get_all_roles: MagicMock,
    mock_get_all_policies: MagicMock,
) -> None:
    mock_exists.return_value = False

    mock_get_all_policies.return_value = [
        {
            "PolicyArn": "arn:aws:iam::aws:policy/TestPolicy1",
            "PolicyName": "TestPolicy1",
            "Actions": ["s3:GetObject", "s3:PutObject"],
        }
    ]

    mock_get_all_roles.return_value = [
        {
            "RoleName": "TestRole1",
            "Arn": "arn:aws:iam::123456789012:role/TestRole1",
            "AttachedPolicies": [
                {
                    "PolicyArn": "arn:aws:iam::aws:policy/TestPolicy1",
                    "PolicyName": "TestPolicy1",
                }
            ],
        }
    ]

    result = aws_policies_analyzer.build_cross_reference_table()

    assert "roles" in result
    assert "policies" in result
    assert "actions" in result
    assert "TestRole1" in result["roles"]
    assert "s3:GetObject" in result["actions"]


# Tests for query functions
@patch("aws_policies_analyzer.build_cross_reference_table")
def test_query_by_role(mock_build_cross_ref: MagicMock) -> None:
    mock_build_cross_ref.return_value = {
        "roles": {
            "TestRole": {
                "arn": "arn:aws:iam::123456789012:role/TestRole",
                "policies": ["arn:aws:iam::aws:policy/TestPolicy"],
                "actions": ["s3:GetObject", "s3:PutObject"],
            }
        }
    }

    # Test with single role
    result = aws_policies_analyzer.query_by_role("TestRole")
    assert result is not None
    assert result["role"] == "TestRole"
    assert "arn:aws:iam::aws:policy/TestPolicy" in result["policies"]
    assert "s3:GetObject" in result["actions"]

    # Test with list of roles
    results = aws_policies_analyzer.query_by_role(["TestRole"])
    assert len(results) == 1
    assert results[0] is not None
    assert results[0]["role"] == "TestRole"

    # Test with non-existent role
    result_none = aws_policies_analyzer.query_by_role("NonExistentRole")
    assert result_none is None

    # Test with list containing non-existent role
    results_mixed = aws_policies_analyzer.query_by_role(["TestRole", "NonExistentRole"])
    assert len(results_mixed) == 2
    assert results_mixed[0] is not None
    assert results_mixed[1] is None


@patch("aws_policies_analyzer.build_cross_reference_table")
def test_query_by_policy(mock_build_cross_ref: MagicMock) -> None:
    policy_arn = "arn:aws:iam::aws:policy/TestPolicy"
    mock_build_cross_ref.return_value = {
        "policies": {
            policy_arn: {
                "name": "TestPolicy",
                "roles": ["TestRole1", "TestRole2"],
                "actions": ["s3:GetObject", "s3:PutObject"],
            }
        }
    }

    # Test with single policy
    result = aws_policies_analyzer.query_by_policy(policy_arn)
    assert result is not None
    assert result["policy"] == policy_arn
    assert "TestRole1" in result["roles"]
    assert "s3:GetObject" in result["actions"]

    # Test with list of policies
    results = aws_policies_analyzer.query_by_policy([policy_arn])
    assert len(results) == 1
    assert results[0] is not None
    assert results[0]["policy"] == policy_arn

    # Test with non-existent policy
    result_none = aws_policies_analyzer.query_by_policy("NonExistentPolicy")
    assert result_none is None

    # Test with list containing non-existent policy
    results_mixed = aws_policies_analyzer.query_by_policy(
        [policy_arn, "NonExistentPolicy"]
    )
    assert len(results_mixed) == 2
    assert results_mixed[0] is not None
    assert results_mixed[1] is None


@patch("aws_policies_analyzer.build_cross_reference_table")
def test_query_by_action(mock_build_cross_ref: MagicMock) -> None:
    action = "s3:GetObject"
    mock_build_cross_ref.return_value = {
        "actions": {
            action: {
                "roles": ["TestRole1", "TestRole2"],
                "policies": ["arn:aws:iam::aws:policy/TestPolicy1"],
            }
        }
    }

    # Test with single action
    result = aws_policies_analyzer.query_by_action(action)
    assert result is not None
    assert result["action"] == action
    assert "TestRole1" in result["roles"]
    assert "arn:aws:iam::aws:policy/TestPolicy1" in result["policies"]

    # Test with list of actions
    results = aws_policies_analyzer.query_by_action([action])
    assert len(results) == 1
    assert results[0] is not None
    assert results[0]["action"] == action

    # Test with non-existent action
    result_none = aws_policies_analyzer.query_by_action("NonExistentAction")
    assert result_none is None

    # Test with list containing non-existent action
    results_mixed = aws_policies_analyzer.query_by_action([action, "NonExistentAction"])
    assert len(results_mixed) == 2
    assert results_mixed[0] is not None
    assert results_mixed[1] is None


# Test for read_stdin
@patch("sys.stdin")
def test_read_stdin(mock_stdin: MagicMock) -> None:
    mock_stdin.isatty.return_value = False
    mock_stdin.read.return_value = "line1 line2 line3"

    result = aws_policies_analyzer.read_stdin()
    assert result == ["line1", "line2", "line3"]

    mock_stdin.isatty.return_value = True
    result = aws_policies_analyzer.read_stdin()
    assert result == []


# Test for main function
@patch("aws_policies_analyzer.cli.query_by_role")
@patch("aws_policies_analyzer.cli.to_json")
@patch("builtins.print")
@patch("sys.argv", ["aws_policies_analyzer", "--by-role", "TestRole"])
def test_main(
    mock_print: MagicMock, mock_to_json: MagicMock, mock_query_by_role: MagicMock
) -> None:
    mock_query_by_role.return_value = {"test": "data"}
    mock_to_json.return_value = '{"test": "data"}'

    from aws_policies_analyzer.cli import main

    main()

    mock_query_by_role.assert_called_once_with(["TestRole"], force_refresh=False)
    mock_to_json.assert_called_once_with({"test": "data"})
    mock_print.assert_called_once_with('{"test": "data"}')
