"""CLI integration tests for sfutils_extvolumes using CliRunner."""

from __future__ import annotations

import json
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner

from sfutils_extvolumes._snow import run_snow_sql, run_snow_sql_stdin
from sfutils_extvolumes.extvolume import cli


@pytest.fixture()
def runner() -> CliRunner:
    # mix_stderr=True so ClickException error messages appear in result.output
    return CliRunner(mix_stderr=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _completed_proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> CompletedProcess:
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# describe command
# ---------------------------------------------------------------------------


class TestDescribeCommand:
    def test_describe_success(self, runner):
        storage_json = json.dumps({
            "STORAGE_AWS_IAM_USER_ARN": "arn:aws:iam::123456789012:user/snowflake-abc",
            "STORAGE_AWS_EXTERNAL_ID": "MY_EXTID_ABC123",
        })
        rows = [
            {
                "parent_property": "STORAGE_LOCATIONS",
                "property": "STORAGE_LOCATION_1",
                "property_value": storage_json,
            }
        ]

        with patch("sfutils_extvolumes.extvolume.run_snow_sql", return_value=rows):
            result = runner.invoke(cli, ["describe", "--volume-name", "MY_VOLUME"])

        assert result.exit_code == 0, result.output
        assert "MY_VOLUME" in result.output
        assert "iam_user_arn" in result.output

    def test_describe_missing_volume_name(self, runner):
        result = runner.invoke(cli, ["describe"])
        assert result.exit_code != 0

    def test_describe_snow_sql_failure(self, runner):
        with patch(
            "sfutils_extvolumes.extvolume.run_snow_sql",
            side_effect=click.ClickException("snow sql failed: connection error"),
        ):
            result = runner.invoke(cli, ["describe", "--volume-name", "MY_VOLUME"])

        assert result.exit_code != 0

    def test_describe_empty_result(self, runner):
        with patch("sfutils_extvolumes.extvolume.run_snow_sql", return_value=None):
            result = runner.invoke(cli, ["describe", "--volume-name", "MY_VOLUME"])

        assert result.exit_code != 0

    def test_describe_missing_iam_user_arn(self, runner):
        # Row present but no STORAGE_AWS_IAM_USER_ARN in the JSON
        rows = [
            {
                "parent_property": "STORAGE_LOCATIONS",
                "property": "STORAGE_LOCATION_1",
                "property_value": json.dumps({"SOME_OTHER_KEY": "value"}),
            }
        ]
        with patch("sfutils_extvolumes.extvolume.run_snow_sql", return_value=rows):
            result = runner.invoke(cli, ["describe", "--volume-name", "MY_VOLUME"])

        assert result.exit_code != 0
        assert "STORAGE_AWS_IAM_USER_ARN" in result.output or "Could not find" in result.output


# ---------------------------------------------------------------------------
# verify command
# ---------------------------------------------------------------------------


class TestVerifyCommand:
    def test_verify_success(self, runner):
        verification_json = json.dumps({
            "success": True,
            "storageLocationSelectionResult": "SUCCEEDED",
        })
        rows = [{"SYSTEM$VERIFY_EXTERNAL_VOLUME('MY_VOLUME')": verification_json}]

        with patch("sfutils_extvolumes.extvolume.run_snow_sql", return_value=rows):
            result = runner.invoke(cli, ["verify", "--volume-name", "MY_VOLUME"])

        assert result.exit_code == 0, result.output
        assert "verified" in result.output.lower()

    def test_verify_failure(self, runner):
        verification_json = json.dumps({
            "success": False,
            "storageLocationSelectionResult": "FAILED",
        })
        rows = [{"SYSTEM$VERIFY_EXTERNAL_VOLUME('MY_VOLUME')": verification_json}]

        with patch("sfutils_extvolumes.extvolume.run_snow_sql", return_value=rows):
            result = runner.invoke(cli, ["verify", "--volume-name", "MY_VOLUME"])

        # Verify command itself exits 0; the failure is reported in text
        assert result.exit_code == 0
        assert "failed" in result.output.lower() or "✗" in result.output

    def test_verify_missing_volume_name(self, runner):
        result = runner.invoke(cli, ["verify"])
        assert result.exit_code != 0

    def test_verify_empty_result(self, runner):
        with patch("sfutils_extvolumes.extvolume.run_snow_sql", return_value=None):
            result = runner.invoke(cli, ["verify", "--volume-name", "MY_VOLUME"])

        assert result.exit_code == 0
        assert "Could not verify" in result.output

    def test_verify_no_matching_key(self, runner):
        rows = [{"SOME_OTHER_COLUMN": "data"}]
        with patch("sfutils_extvolumes.extvolume.run_snow_sql", return_value=rows):
            result = runner.invoke(cli, ["verify", "--volume-name", "MY_VOLUME"])

        assert result.exit_code == 0
        assert "Could not find" in result.output


# ---------------------------------------------------------------------------
# update-trust command
# ---------------------------------------------------------------------------


class TestUpdateTrustCommand:
    def _make_describe_rows(self) -> list:
        storage_json = json.dumps({
            "STORAGE_AWS_IAM_USER_ARN": "arn:aws:iam::123456789012:user/sf-abc",
            "STORAGE_AWS_EXTERNAL_ID": "MY_EXTID",
        })
        return [
            {
                "parent_property": "STORAGE_LOCATIONS",
                "property": "STORAGE_LOCATION_1",
                "property_value": storage_json,
            }
        ]

    def test_update_trust_with_bucket(self, runner):
        mock_iam = MagicMock()

        with (
            patch(
                "sfutils_extvolumes.extvolume.run_snow_sql",
                return_value=self._make_describe_rows(),
            ),
            patch("sfutils_extvolumes.extvolume.boto3") as mock_boto3,
        ):
            mock_boto3.client.return_value = mock_iam
            result = runner.invoke(
                cli,
                ["--no-prefix", "update-trust", "--bucket", "iceberg-data"],
            )

        assert result.exit_code == 0, result.output
        assert "Trust policy updated" in result.output

    def test_update_trust_no_bucket_no_role_volume(self, runner):
        result = runner.invoke(cli, ["update-trust"])
        assert result.exit_code != 0

    def test_update_trust_explicit_role_and_volume(self, runner):
        mock_iam = MagicMock()

        with (
            patch(
                "sfutils_extvolumes.extvolume.run_snow_sql",
                return_value=self._make_describe_rows(),
            ),
            patch("sfutils_extvolumes.extvolume.boto3") as mock_boto3,
        ):
            mock_boto3.client.return_value = mock_iam
            result = runner.invoke(
                cli,
                [
                    "--no-prefix",
                    "update-trust",
                    "--role-name",
                    "my-role",
                    "--volume-name",
                    "MY_VOLUME",
                ],
            )

        assert result.exit_code == 0, result.output


# ---------------------------------------------------------------------------
# Global CLI flags
# ---------------------------------------------------------------------------


class TestGlobalCliFlags:
    def test_help_text(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "External Volume" in result.output

    def test_prefix_passed_through(self, runner):
        with patch("sfutils_extvolumes.extvolume.run_snow_sql", return_value=None):
            result = runner.invoke(
                cli,
                ["--prefix", "testuser", "verify", "--volume-name", "MY_VOLUME"],
            )
        assert "testuser" in result.output

    def test_no_prefix_suppresses_prefix(self, runner):
        with patch("sfutils_extvolumes.extvolume.run_snow_sql", return_value=None):
            result = runner.invoke(
                cli,
                ["--no-prefix", "verify", "--volume-name", "MY_VOLUME"],
            )
        assert "Using prefix" not in result.output


# ---------------------------------------------------------------------------
# run_snow_sql / run_snow_sql_stdin (unit-level subprocess mocking)
# ---------------------------------------------------------------------------


class TestRunSnowSql:
    def test_success_returns_parsed_json(self):
        mock_result = _completed_proc(stdout='[{"col": "val"}]')
        with patch("sfutils_extvolumes._snow.subprocess.run", return_value=mock_result):
            result = run_snow_sql("SELECT 1")

        assert result == [{"col": "val"}]

    def test_failure_raises_click_exception(self):
        mock_result = _completed_proc(returncode=1, stderr="authentication failed")
        with (
            patch("sfutils_extvolumes._snow.subprocess.run", return_value=mock_result),
            pytest.raises(click.ClickException, match="snow sql failed"),
        ):
            run_snow_sql("SELECT 1")

    def test_check_false_does_not_raise_on_failure(self):
        mock_result = _completed_proc(returncode=1, stderr="error")
        with patch("sfutils_extvolumes._snow.subprocess.run", return_value=mock_result):
            result = run_snow_sql("SELECT 1", check=False)

        # Returns None on non-zero exit when check=False
        assert result is None

    def test_empty_stdout_returns_none(self):
        mock_result = _completed_proc(stdout="")
        with patch("sfutils_extvolumes._snow.subprocess.run", return_value=mock_result):
            result = run_snow_sql("SELECT 1")

        assert result is None

    def test_invalid_json_returns_none(self):
        mock_result = _completed_proc(stdout="not-json")
        with patch("sfutils_extvolumes._snow.subprocess.run", return_value=mock_result):
            result = run_snow_sql("SELECT 1")

        assert result is None


class TestRunSnowSqlStdin:
    def test_success_returns_completed_process(self):
        mock_result = _completed_proc(returncode=0, stdout="Statement executed.")
        with patch("sfutils_extvolumes._snow.subprocess.run", return_value=mock_result):
            result = run_snow_sql_stdin("CREATE TABLE foo (id INT);")

        assert result.returncode == 0

    def test_failure_raises_click_exception(self):
        mock_result = _completed_proc(returncode=1, stderr="syntax error")
        with (
            patch("sfutils_extvolumes._snow.subprocess.run", return_value=mock_result),
            pytest.raises(click.ClickException, match="snow sql failed"),
        ):
            run_snow_sql_stdin("BAD SQL;")

    def test_check_false_returns_result(self):
        mock_result = _completed_proc(returncode=1, stderr="error")
        with patch("sfutils_extvolumes._snow.subprocess.run", return_value=mock_result):
            result = run_snow_sql_stdin("BAD SQL;", check=False)

        assert result.returncode == 1

    def test_sql_passed_as_stdin(self):
        mock_result = _completed_proc(returncode=0)
        with patch("sfutils_extvolumes._snow.subprocess.run", return_value=mock_result) as mock_run:
            run_snow_sql_stdin("CREATE TABLE foo (id INT);")

        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs.get("input") == "CREATE TABLE foo (id INT);"
