"""Tests for SQL generation and policy document functions in sfutils_extvolumes.extvolume."""

from __future__ import annotations

import json

import click
import pytest

from sfutils_extvolumes.extvolume import (
    ExternalVolumeConfig,
    _assert_safe_identifier,
    _sql_str,
    get_external_volume_sql,
    get_initial_trust_policy,
    get_s3_access_policy,
    get_snowflake_trust_policy,
)


class TestSqlStr:
    def test_no_quotes(self):
        assert _sql_str("hello") == "hello"

    def test_escapes_single_quotes(self):
        assert _sql_str("it's") == "it''s"

    def test_multiple_quotes(self):
        assert _sql_str("a'b'c") == "a''b''c"

    def test_empty_string(self):
        assert _sql_str("") == ""


class TestAssertSafeIdentifier:
    def test_valid_identifier(self):
        # Should not raise
        _assert_safe_identifier("MY_VOLUME")

    def test_valid_with_digits(self):
        _assert_safe_identifier("VOLUME_1")

    def test_valid_with_dollar(self):
        _assert_safe_identifier("MY_VOLUME$")

    def test_leading_digit_raises(self):
        with pytest.raises(click.ClickException, match="Invalid"):
            _assert_safe_identifier("1VOLUME")

    def test_hyphen_raises(self):
        with pytest.raises(click.ClickException, match="Invalid"):
            _assert_safe_identifier("MY-VOLUME")

    def test_space_raises(self):
        with pytest.raises(click.ClickException, match="Invalid"):
            _assert_safe_identifier("MY VOLUME")

    def test_dot_raises(self):
        with pytest.raises(click.ClickException, match="Invalid"):
            _assert_safe_identifier("MY.VOLUME")

    def test_custom_label_in_error(self):
        with pytest.raises(click.ClickException, match="volume_name"):
            _assert_safe_identifier("1invalid", "volume_name")


class TestGetS3AccessPolicy:
    def test_returns_valid_iam_policy(self):
        policy = get_s3_access_policy("my-bucket")
        assert policy["Version"] == "2012-10-17"
        assert len(policy["Statement"]) == 2

    def test_policy_references_bucket(self):
        policy = get_s3_access_policy("my-bucket")
        doc = json.dumps(policy)
        assert "my-bucket" in doc

    def test_allows_put_get_delete(self):
        policy = get_s3_access_policy("my-bucket")
        object_statement = policy["Statement"][0]
        actions = object_statement["Action"]
        assert "s3:PutObject" in actions
        assert "s3:GetObject" in actions
        assert "s3:DeleteObject" in actions

    def test_allows_list_bucket(self):
        policy = get_s3_access_policy("my-bucket")
        bucket_statement = policy["Statement"][1]
        assert "s3:ListBucket" in bucket_statement["Action"]

    def test_resource_arn_format(self):
        policy = get_s3_access_policy("test-bucket")
        resource = policy["Statement"][0]["Resource"]
        assert resource == "arn:aws:s3:::test-bucket/*"


class TestGetInitialTrustPolicy:
    def test_structure(self):
        policy = get_initial_trust_policy("123456789012", "MYEXT_ID")
        assert policy["Version"] == "2012-10-17"
        assert len(policy["Statement"]) == 1

    def test_account_id_in_principal(self):
        policy = get_initial_trust_policy("123456789012", "MYEXT_ID")
        principal = policy["Statement"][0]["Principal"]["AWS"]
        assert "123456789012" in principal

    def test_external_id_condition(self):
        policy = get_initial_trust_policy("123456789012", "MYEXT_ID")
        condition = policy["Statement"][0]["Condition"]
        assert condition["StringEquals"]["sts:ExternalId"] == "MYEXT_ID"

    def test_assume_role_action(self):
        policy = get_initial_trust_policy("123456789012", "MYEXT_ID")
        assert policy["Statement"][0]["Action"] == "sts:AssumeRole"

    def test_serializable_to_json(self):
        policy = get_initial_trust_policy("123456789012", "MYEXT_ID")
        # Should not raise
        json.dumps(policy)


class TestGetSnowflakeTrustPolicy:
    def test_structure(self):
        arn = "arn:aws:iam::123456789012:user/snowflake-abc"
        policy = get_snowflake_trust_policy(arn, "EXT123")
        assert policy["Version"] == "2012-10-17"
        assert policy["Statement"][0]["Sid"] == "SnowflakeAccess"

    def test_snowflake_arn_as_principal(self):
        arn = "arn:aws:iam::123456789012:user/snowflake-abc"
        policy = get_snowflake_trust_policy(arn, "EXT123")
        assert policy["Statement"][0]["Principal"]["AWS"] == arn

    def test_external_id_condition(self):
        arn = "arn:aws:iam::123456789012:user/snowflake-abc"
        policy = get_snowflake_trust_policy(arn, "EXT123")
        condition = policy["Statement"][0]["Condition"]
        assert condition["StringEquals"]["sts:ExternalId"] == "EXT123"

    def test_serializable_to_json(self):
        arn = "arn:aws:iam::123456789012:user/snowflake-abc"
        policy = get_snowflake_trust_policy(arn, "EXT123")
        json.dumps(policy)


class TestGetExternalVolumeSql:
    def _make_config(self, **kwargs) -> ExternalVolumeConfig:
        defaults = {
            "bucket_name": "my-test-bucket",
            "role_name": "my-test-role",
            "policy_name": "my-test-policy",
            "volume_name": "MY_VOLUME",
            "storage_location_name": "MY_LOCATION",
            "external_id": "MY_EXT_ID",
            "aws_region": "us-west-2",
            "allow_writes": True,
            "comment": "",
        }
        defaults.update(kwargs)
        return ExternalVolumeConfig(**defaults)

    def test_contains_create_statement(self):
        config = self._make_config()
        sql = get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")
        assert "CREATE EXTERNAL VOLUME IF NOT EXISTS" in sql

    def test_force_uses_create_or_replace(self):
        config = self._make_config()
        sql = get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role", force=True)
        assert "CREATE OR REPLACE EXTERNAL VOLUME" in sql

    def test_contains_volume_name(self):
        config = self._make_config(volume_name="MY_VOLUME")
        sql = get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")
        assert "MY_VOLUME" in sql

    def test_contains_bucket(self):
        config = self._make_config(bucket_name="my-test-bucket")
        sql = get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")
        assert "my-test-bucket" in sql

    def test_contains_role_arn(self):
        arn = "arn:aws:iam::123456789012:role/my-role"
        config = self._make_config()
        sql = get_external_volume_sql(config, arn)
        assert arn in sql

    def test_contains_external_id(self):
        config = self._make_config(external_id="MY_EXT_ID_ABC123")
        sql = get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")
        assert "MY_EXT_ID_ABC123" in sql

    def test_allow_writes_true(self):
        config = self._make_config(allow_writes=True)
        sql = get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")
        assert "ALLOW_WRITES = TRUE" in sql

    def test_allow_writes_false(self):
        config = self._make_config(allow_writes=False)
        sql = get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")
        assert "ALLOW_WRITES = FALSE" in sql

    def test_comment_included(self):
        config = self._make_config(comment="My test comment")
        sql = get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")
        assert "My test comment" in sql

    def test_no_comment_when_empty(self):
        config = self._make_config(comment="")
        sql = get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")
        assert "COMMENT" not in sql

    def test_sql_injection_in_bucket_name_escaped(self):
        config = self._make_config(bucket_name="bucket'; DROP TABLE users; --")
        sql = get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")
        # Single quotes in the bucket name should be escaped (doubled)
        assert "''" in sql

    def test_invalid_volume_name_raises(self):
        config = self._make_config(volume_name="my-invalid-volume")
        with pytest.raises(click.ClickException, match="Invalid volume_name"):
            get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")

    def test_invalid_storage_location_name_raises(self):
        config = self._make_config(storage_location_name="invalid name!")
        with pytest.raises(click.ClickException, match="Invalid storage_location_name"):
            get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")

    def test_s3_provider(self):
        config = self._make_config()
        sql = get_external_volume_sql(config, "arn:aws:iam::123456789012:role/my-role")
        assert "STORAGE_PROVIDER = 'S3'" in sql
