"""Tests for naming utility functions in sfutils_extvolumes.extvolume."""

from __future__ import annotations

import re

from sfutils_extvolumes.extvolume import (
    format_comment,
    generate_external_id,
    get_resource_tags,
    normalize_identifier,
    to_aws_name,
    to_sql_identifier,
)


class TestNormalizeIdentifier:
    def test_snowflake_style_uppercases(self):
        assert normalize_identifier("my project", "snowflake") == "MY_PROJECT"

    def test_snowflake_replaces_spaces_with_underscores(self):
        assert normalize_identifier("hello world", "snowflake") == "HELLO_WORLD"

    def test_aws_style_lowercases(self):
        assert normalize_identifier("My Project", "aws") == "my-project"

    def test_aws_replaces_spaces_with_hyphens(self):
        assert normalize_identifier("hello world", "aws") == "hello-world"

    def test_strips_special_chars(self):
        assert normalize_identifier("my-project!", "snowflake") == "MY_PROJECT"

    def test_collapses_multiple_separators(self):
        assert normalize_identifier("my--project", "aws") == "my-project"

    def test_strips_leading_trailing_separators(self):
        result = normalize_identifier("_my_project_", "snowflake")
        assert not result.startswith("_")
        assert not result.endswith("_")

    def test_default_style_is_snowflake(self):
        assert normalize_identifier("my project") == "MY_PROJECT"


class TestToAwsName:
    def test_basic_lowercase_conversion(self):
        assert to_aws_name("MyBucket") == "mybucket"

    def test_underscores_become_hyphens(self):
        assert to_aws_name("my_bucket") == "my-bucket"

    def test_with_prefix(self):
        result = to_aws_name("bucket", "alice")
        assert result == "alice-bucket"

    def test_removes_invalid_chars(self):
        result = to_aws_name("my bucket!")
        assert " " not in result
        assert "!" not in result

    def test_collapses_consecutive_hyphens(self):
        result = to_aws_name("my--bucket")
        assert "--" not in result

    def test_strips_leading_trailing_hyphens(self):
        result = to_aws_name("-my-bucket-")
        assert not result.startswith("-")
        assert not result.endswith("-")

    def test_prefix_normalized(self):
        result = to_aws_name("bucket", "Alice_User")
        assert result.startswith("alice-user-")


class TestToSqlIdentifier:
    def test_basic_upper_conversion(self):
        assert to_sql_identifier("my_volume") == "MY_VOLUME"

    def test_hyphens_become_underscores(self):
        assert to_sql_identifier("my-volume") == "MY_VOLUME"

    def test_with_prefix(self):
        result = to_sql_identifier("volume", "alice")
        assert result == "ALICE_VOLUME"

    def test_digit_prefix_gets_underscore(self):
        result = to_sql_identifier("123volume")
        assert result.startswith("_")

    def test_removes_invalid_chars(self):
        result = to_sql_identifier("my volume!")
        assert " " not in result
        assert "!" not in result

    def test_collapses_consecutive_underscores(self):
        result = to_sql_identifier("my__volume")
        assert "__" not in result

    def test_strips_leading_trailing_underscores(self):
        result = to_sql_identifier("_my_volume_")
        assert not result.startswith("_")
        assert not result.endswith("_")


class TestGenerateExternalId:
    def test_returns_string(self):
        result = generate_external_id("my-bucket")
        assert isinstance(result, str)

    def test_with_prefix(self):
        result = generate_external_id("my-bucket", "alice")
        assert "ALICE" in result

    def test_contains_ext(self):
        result = generate_external_id("my-bucket")
        assert "EXT" in result

    def test_each_call_unique(self):
        a = generate_external_id("my-bucket")
        b = generate_external_id("my-bucket")
        assert a != b

    def test_valid_sql_identifier_chars(self):
        result = generate_external_id("my-bucket", "alice")
        assert re.match(r"^[A-Z_][A-Z0-9_$]*$", result), f"Not a valid identifier: {result}"


class TestFormatComment:
    def test_with_prefix_and_bucket(self):
        result = format_comment("alice", "iceberg-data")
        assert "ALICE" in result
        assert "sfutils-extvolumes" in result

    def test_without_prefix(self):
        result = format_comment(None, "iceberg-data")
        assert "USER" in result
        assert "sfutils-extvolumes" in result

    def test_bucket_normalized(self):
        result = format_comment("alice", "my bucket!")
        assert "MY_BUCKET" in result


class TestGetResourceTags:
    def test_returns_list_of_dicts(self):
        tags = get_resource_tags("alice", "iceberg-data", "MY_VOLUME")
        assert isinstance(tags, list)
        assert all(isinstance(t, dict) for t in tags)

    def test_managed_by_tag(self):
        tags = get_resource_tags("alice", "iceberg-data", "MY_VOLUME")
        tag_keys = {t["Key"]: t["Value"] for t in tags}
        assert tag_keys.get("managed-by") == "sfutils-extvolumes"

    def test_user_tag_normalized(self):
        tags = get_resource_tags("Alice User", "iceberg-data", "MY_VOLUME")
        tag_keys = {t["Key"]: t["Value"] for t in tags}
        assert tag_keys["user"] == "ALICE_USER"

    def test_none_prefix_uses_unknown(self):
        tags = get_resource_tags(None, "iceberg-data", "MY_VOLUME")
        tag_keys = {t["Key"]: t["Value"] for t in tags}
        assert tag_keys["user"] == "UNKNOWN"

    def test_volume_name_in_tags(self):
        tags = get_resource_tags("alice", "iceberg-data", "MY_VOLUME")
        tag_keys = {t["Key"]: t["Value"] for t in tags}
        assert tag_keys["snowflake-volume"] == "MY_VOLUME"
