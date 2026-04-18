"""Tests for sensitive-value masking functions in sfutils_extvolumes._snow."""

from __future__ import annotations

from sfutils_extvolumes._snow import (
    get_snow_cli_options,
    is_masking_enabled,
    mask_arn,
    mask_aws_account_id,
    mask_external_id,
    mask_ip_address,
    mask_sensitive_string,
    set_masking,
    set_snow_cli_options,
)


class TestMaskAwsAccountId:
    def test_masks_12_digit_account_id(self):
        assert mask_aws_account_id("123456789012") == "1234****9012"

    def test_leaves_non_12_digit_string_unchanged(self):
        assert mask_aws_account_id("12345") == "12345"

    def test_leaves_non_numeric_string_unchanged(self):
        assert mask_aws_account_id("abcdefghijkl") == "abcdefghijkl"

    def test_empty_string(self):
        assert mask_aws_account_id("") == ""

    def test_preserves_first_and_last_four(self):
        result = mask_aws_account_id("000011112222")
        assert result.startswith("0000")
        assert result.endswith("2222")


class TestMaskIpAddress:
    def test_masks_ipv4(self):
        assert mask_ip_address("192.168.1.100") == "192.168.***.***"

    def test_masks_ipv4_with_cidr(self):
        result = mask_ip_address("10.0.0.1/32")
        assert result.endswith("/32")

    def test_preserves_first_two_octets(self):
        result = mask_ip_address("172.16.50.1")
        assert result.startswith("172.16.")

    def test_non_ip_string_unchanged(self):
        assert mask_ip_address("not-an-ip") == "not-an-ip"


class TestMaskExternalId:
    def test_masks_long_external_id(self):
        result = mask_external_id("ABCDEFGHIJKLMNOP")
        assert result.startswith("ABC")
        assert result.endswith("NOP")
        assert "***" in result

    def test_masks_short_external_id(self):
        # Short IDs get all stars
        result = mask_external_id("AB")
        assert result == "**"

    def test_exactly_6_chars_all_masked(self):
        result = mask_external_id("ABCDEF")
        assert result == "******"

    def test_7_chars_has_stars(self):
        # 7 chars: first 3, then (7-6)=1 star, then last 3  → "ABC*EFG"
        result = mask_external_id("ABCDEFG")
        assert "*" in result


class TestMaskArn:
    def test_masks_account_id_in_arn(self):
        arn = "arn:aws:iam::123456789012:role/MyRole"
        result = mask_arn(arn)
        assert "123456789012" not in result
        assert "1234****9012" in result
        assert result.startswith("arn:aws:iam::")
        assert result.endswith(":role/MyRole")

    def test_non_arn_unchanged(self):
        assert mask_arn("not-an-arn") == "not-an-arn"

    def test_s3_arn(self):
        arn = "arn:aws:s3:::my-bucket"
        # S3 ARNs have no account ID in the typical format; pattern won't match
        result = mask_arn(arn)
        assert result == arn


class TestMaskSensitiveString:
    def test_auto_detects_account_id(self):
        result = mask_sensitive_string("123456789012")
        assert result == "1234****9012"

    def test_auto_detects_ip_address(self):
        result = mask_sensitive_string("10.0.0.1")
        assert "***" in result

    def test_auto_detects_arn(self):
        arn = "arn:aws:iam::123456789012:role/MyRole"
        result = mask_sensitive_string(arn)
        assert "1234****9012" in result

    def test_explicit_external_id_type(self):
        result = mask_sensitive_string("ABCDEFGHIJKLMNOP", "external_id")
        assert "***" in result

    def test_passthrough_when_masking_disabled(self):
        set_masking(False)
        try:
            assert mask_sensitive_string("123456789012") == "123456789012"
        finally:
            set_masking(True)

    def test_respects_global_mask_setting(self):
        set_masking(True)
        result = mask_sensitive_string("123456789012")
        assert "****" in result


class TestSetMasking:
    def test_enable_masking(self):
        set_masking(True)
        assert is_masking_enabled() is True

    def test_disable_masking(self):
        set_masking(False)
        assert is_masking_enabled() is False
        set_masking(True)  # restore

    def test_toggling(self):
        set_masking(True)
        assert is_masking_enabled() is True
        set_masking(False)
        assert is_masking_enabled() is False
        set_masking(True)
        assert is_masking_enabled() is True


class TestSetSnowCliOptions:
    def test_default_options(self):
        set_snow_cli_options()
        opts = get_snow_cli_options()
        assert opts.verbose is False
        assert opts.debug is False
        assert opts.mask_sensitive is True

    def test_verbose_flag(self):
        set_snow_cli_options(verbose=True)
        opts = get_snow_cli_options()
        assert opts.verbose is True
        assert opts.debug is False

    def test_debug_flag(self):
        set_snow_cli_options(debug=True)
        opts = get_snow_cli_options()
        assert opts.debug is True

    def test_mask_sensitive_false(self):
        set_snow_cli_options(mask_sensitive=False)
        opts = get_snow_cli_options()
        assert opts.mask_sensitive is False

    def test_get_flags_verbose(self):
        set_snow_cli_options(verbose=True)
        assert "--verbose" in get_snow_cli_options().get_flags()

    def test_get_flags_debug(self):
        set_snow_cli_options(debug=True)
        assert "--debug" in get_snow_cli_options().get_flags()

    def test_get_flags_default_empty(self):
        set_snow_cli_options()
        assert get_snow_cli_options().get_flags() == []
