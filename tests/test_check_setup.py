"""Tests for pure utility functions in sfutils_extvolumes.check_setup."""

from __future__ import annotations

from sfutils_extvolumes.check_setup import (
    PROVIDER_CREDENTIAL_ENV_VARS,
    _credential_env_human_summary,
    _env_nonempty,
    csp_credential_env_snapshot,
    csp_credential_signal_for_provider,
    resolved_sa_admin_role,
    resolved_sf_utils_db,
)


class TestResolvedSfUtilsDb:
    def test_explicit_arg_wins(self, monkeypatch):
        monkeypatch.setenv("SF_UTILS_DB", "ENV_DB")
        assert resolved_sf_utils_db(database="ARG_DB", default_db="DEFAULT") == "ARG_DB"

    def test_sf_utils_db_env_used_when_no_arg(self, monkeypatch):
        monkeypatch.setenv("SF_UTILS_DB", "ENV_DB")
        monkeypatch.delenv("SNOW_UTILS_DB", raising=False)
        assert resolved_sf_utils_db(database=None, default_db="DEFAULT") == "ENV_DB"

    def test_snow_utils_db_legacy_fallback(self, monkeypatch):
        monkeypatch.delenv("SF_UTILS_DB", raising=False)
        monkeypatch.setenv("SNOW_UTILS_DB", "LEGACY_DB")
        assert resolved_sf_utils_db(database=None, default_db="DEFAULT") == "LEGACY_DB"

    def test_default_when_no_env(self, monkeypatch):
        monkeypatch.delenv("SF_UTILS_DB", raising=False)
        monkeypatch.delenv("SNOW_UTILS_DB", raising=False)
        assert resolved_sf_utils_db(database=None, default_db="DEFAULT") == "DEFAULT"

    def test_sf_utils_db_takes_priority_over_legacy(self, monkeypatch):
        monkeypatch.setenv("SF_UTILS_DB", "NEW")
        monkeypatch.setenv("SNOW_UTILS_DB", "OLD")
        assert resolved_sf_utils_db(database=None, default_db="DEFAULT") == "NEW"


class TestResolvedSaAdminRole:
    def test_explicit_arg_wins(self, monkeypatch):
        monkeypatch.setenv("SA_ADMIN_ROLE", "ENV_ROLE")
        assert resolved_sa_admin_role(admin_role="ARG_ROLE") == "ARG_ROLE"

    def test_env_var_used_when_no_arg(self, monkeypatch):
        monkeypatch.setenv("SA_ADMIN_ROLE", "ENV_ROLE")
        assert resolved_sa_admin_role(admin_role=None) == "ENV_ROLE"

    def test_default_accountadmin(self, monkeypatch):
        monkeypatch.delenv("SA_ADMIN_ROLE", raising=False)
        assert resolved_sa_admin_role(admin_role=None) == "ACCOUNTADMIN"

    def test_blank_arg_falls_through_to_env(self, monkeypatch):
        monkeypatch.setenv("SA_ADMIN_ROLE", "ENV_ROLE")
        assert resolved_sa_admin_role(admin_role=None) == "ENV_ROLE"


class TestEnvNonempty:
    def test_set_variable(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR_NONEMPTY", "hello")
        assert _env_nonempty("TEST_VAR_NONEMPTY") is True

    def test_unset_variable(self, monkeypatch):
        monkeypatch.delenv("TEST_VAR_NONEMPTY", raising=False)
        assert _env_nonempty("TEST_VAR_NONEMPTY") is False

    def test_empty_string_variable(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR_NONEMPTY", "")
        assert _env_nonempty("TEST_VAR_NONEMPTY") is False

    def test_whitespace_only_variable(self, monkeypatch):
        monkeypatch.setenv("TEST_VAR_NONEMPTY", "   ")
        assert _env_nonempty("TEST_VAR_NONEMPTY") is False


class TestCspCredentialEnvSnapshot:
    def test_s3_snapshot_returns_all_vars(self, monkeypatch):
        for v in PROVIDER_CREDENTIAL_ENV_VARS["s3"]:
            monkeypatch.delenv(v, raising=False)
        snapshot = csp_credential_env_snapshot("s3")
        assert len(snapshot) == len(PROVIDER_CREDENTIAL_ENV_VARS["s3"])

    def test_snapshot_set_flag_true(self, monkeypatch):
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        snapshot = csp_credential_env_snapshot("s3")
        entry = next(e for e in snapshot if e["name"] == "AWS_ACCESS_KEY_ID")
        assert entry["set"] is True

    def test_snapshot_set_flag_false(self, monkeypatch):
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        snapshot = csp_credential_env_snapshot("s3")
        entry = next(e for e in snapshot if e["name"] == "AWS_ACCESS_KEY_ID")
        assert entry["set"] is False

    def test_values_not_in_snapshot(self, monkeypatch):
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        snapshot = csp_credential_env_snapshot("s3")
        for entry in snapshot:
            assert "value" not in entry


class TestCspCredentialSignalForProvider:
    # S3 tests
    def test_s3_static_keys(self, monkeypatch):
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "SECRET")
        signal, satisfied_by, _note = csp_credential_signal_for_provider("s3")
        assert signal is True
        assert satisfied_by == "static_keys"

    def test_s3_profile(self, monkeypatch):
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
        monkeypatch.setenv("AWS_PROFILE", "myprofile")
        signal, satisfied_by, _note = csp_credential_signal_for_provider("s3")
        assert signal is True
        assert satisfied_by == "profile"

    def test_s3_web_identity(self, monkeypatch):
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
        monkeypatch.delenv("AWS_PROFILE", raising=False)
        monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
        monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/tmp/token")
        signal, satisfied_by, _note = csp_credential_signal_for_provider("s3")
        assert signal is True
        assert satisfied_by == "web_identity"

    def test_s3_no_signal(self, monkeypatch):
        for v in [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
        ]:
            monkeypatch.delenv(v, raising=False)
        signal, _satisfied_by, note = csp_credential_signal_for_provider("s3")
        assert signal is False
        assert _satisfied_by is None
        assert note is not None

    # Azure tests
    def test_azure_service_principal(self, monkeypatch):
        monkeypatch.setenv("AZURE_CLIENT_ID", "client-id")
        monkeypatch.setenv("AZURE_TENANT_ID", "tenant-id")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret")
        signal, satisfied_by, _note = csp_credential_signal_for_provider("azure")
        assert signal is True
        assert satisfied_by == "service_principal"

    def test_azure_federated(self, monkeypatch):
        monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
        monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
        monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)
        monkeypatch.setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/token")
        signal, satisfied_by, _note = csp_credential_signal_for_provider("azure")
        assert signal is True
        assert satisfied_by == "federated"

    def test_azure_no_signal(self, monkeypatch):
        for v in [
            "AZURE_CLIENT_ID",
            "AZURE_TENANT_ID",
            "AZURE_CLIENT_SECRET",
            "AZURE_FEDERATED_TOKEN_FILE",
        ]:
            monkeypatch.delenv(v, raising=False)
        signal, _satisfied_by, note = csp_credential_signal_for_provider("azure")
        assert signal is False
        assert note is not None

    # GCS tests
    def test_gcs_credentials_file(self, monkeypatch):
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/path/to/creds.json")
        signal, satisfied_by, _note = csp_credential_signal_for_provider("gcs")
        assert signal is True
        assert satisfied_by == "credentials_file"

    def test_gcs_project_env(self, monkeypatch):
        monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
        monkeypatch.setenv("GCLOUD_PROJECT", "my-project")
        signal, satisfied_by, _note = csp_credential_signal_for_provider("gcs")
        assert signal is True
        assert satisfied_by == "project_env"

    def test_gcs_no_signal(self, monkeypatch):
        for v in ["GOOGLE_APPLICATION_CREDENTIALS", "GCLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT"]:
            monkeypatch.delenv(v, raising=False)
        signal, _satisfied_by, note = csp_credential_signal_for_provider("gcs")
        assert signal is False
        assert note is not None


class TestCredentialEnvHumanSummary:
    def test_satisfied_s3_static_keys(self):
        result = _credential_env_human_summary("s3", "static_keys", True, None)
        assert "satisfied" in result
        assert "static access key env" in result

    def test_satisfied_s3_profile(self):
        result = _credential_env_human_summary("s3", "profile", True, None)
        assert "profile" in result

    def test_not_satisfied(self):
        result = _credential_env_human_summary("s3", None, False, "No creds")
        assert "none detected" in result

    def test_gcs_credentials_file(self):
        result = _credential_env_human_summary("gcs", "credentials_file", True, None)
        assert "GOOGLE_APPLICATION_CREDENTIALS" in result
