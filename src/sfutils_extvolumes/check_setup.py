#!/usr/bin/env python3
# Copyright 2026 Snowflake Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Pre-flight check for sfutils-extvolumes tool readiness.

Checks whether the snow CLI and CSP CLI tools (aws/az/gcloud) are available
and credential env signals are present.  External volumes are account-level
Snowflake objects — no database setup is needed.

On success writes [prereqs].tools_verified to manifest.toml so subsequent
skill steps can skip re-checking.
"""

import datetime
import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import click

from sfutils_extvolumes._toml_manifest import load_manifest, save_manifest

DEFAULT_MANIFEST_PATH = ".sfutils/manifest.toml"


def resolved_sa_admin_role(*, admin_role: str | None) -> str:
    """Resolve admin role: --admin-role / SA_ADMIN_ROLE, then ACCOUNTADMIN."""
    for candidate in (admin_role, os.environ.get("SA_ADMIN_ROLE")):
        if candidate and str(candidate).strip():
            return str(candidate).strip()
    return "ACCOUNTADMIN"


# Lowercase CLI value -> list of (STORAGE_PROVIDER label, executable basename)
PROVIDER_CLI_TOOLS: dict[str, list[tuple[str, str]]] = {
    "s3": [("S3", "aws")],
    "azure": [("AZURE", "az")],
    "gcs": [("GCS", "gcloud")],
}

SUPPORTED_STORAGE_PROVIDERS = ["S3"]
PLANNED_STORAGE_PROVIDERS = ["AZURE", "GCS"]

# Diagnostic watch list per provider (OR satisfaction — see csp_credential_signal_for_provider).
PROVIDER_CREDENTIAL_ENV_VARS: dict[str, list[str]] = {
    "s3": [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    ],
    "azure": [
        "AZURE_CLIENT_ID",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_FEDERATED_TOKEN_FILE",
        "AZURE_CLIENT_CERTIFICATE_PATH",
        "AZURE_AUTHORITY_HOST",
    ],
    "gcs": [
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GCLOUD_PROJECT",
        "CLOUDSDK_CORE_PROJECT",
    ],
}


def _env_nonempty(name: str) -> bool:
    v = os.environ.get(name)
    return bool(v and str(v).strip())


def csp_credential_env_snapshot(provider_key: str) -> list[dict[str, object]]:
    """Per-variable set/unset flags only (no secret values)."""
    names = PROVIDER_CREDENTIAL_ENV_VARS[provider_key]
    return [{"name": n, "set": _env_nonempty(n)} for n in names]


def csp_credential_signal_for_provider(
    provider_key: str,
) -> tuple[bool, str | None, str | None]:
    """Return (signal, satisfied_by, note_if_no_signal).

    Satisfaction uses OR branches only: one auth style is enough.
    """
    if provider_key == "s3":
        if _env_nonempty("AWS_ACCESS_KEY_ID") and _env_nonempty("AWS_SECRET_ACCESS_KEY"):
            return True, "static_keys", None
        if _env_nonempty("AWS_PROFILE") or _env_nonempty("AWS_DEFAULT_PROFILE"):
            return True, "profile", None
        if _env_nonempty("AWS_WEB_IDENTITY_TOKEN_FILE"):
            return True, "web_identity", None
        return (
            False,
            None,
            "No AWS credential-related env vars detected; boto3 may still use "
            "~/.aws/credentials, IAM instance role, or SSO.",
        )

    if provider_key == "azure":
        if (
            _env_nonempty("AZURE_CLIENT_ID")
            and _env_nonempty("AZURE_TENANT_ID")
            and _env_nonempty("AZURE_CLIENT_SECRET")
        ):
            return True, "service_principal", None
        if _env_nonempty("AZURE_FEDERATED_TOKEN_FILE"):
            return True, "federated", None
        return (
            False,
            None,
            "No Azure credential env signals detected; Azure tools may still use "
            "managed identity, az login, or other methods.",
        )

    if provider_key == "gcs":
        if _env_nonempty("GOOGLE_APPLICATION_CREDENTIALS"):
            return True, "credentials_file", None
        if _env_nonempty("GCLOUD_PROJECT") or _env_nonempty("CLOUDSDK_CORE_PROJECT"):
            return True, "project_env", None
        return (
            False,
            None,
            "No GCS credential env signals detected; gcloud may still use "
            "application-default credentials or the metadata service.",
        )

    return False, None, None


def _credential_env_human_summary(
    provider_key: str, satisfied_by: str | None, signal: bool, note: str | None
) -> str:
    if signal and satisfied_by:
        labels = {
            "s3": {
                "static_keys": "static access key env",
                "profile": "AWS profile env",
                "web_identity": "web identity token file env",
            },
            "azure": {
                "service_principal": "service principal env",
                "federated": "federated token file env",
            },
            "gcs": {
                "credentials_file": "GOOGLE_APPLICATION_CREDENTIALS",
                "project_env": "gcloud project env",
            },
        }
        lbl = labels.get(provider_key, {}).get(satisfied_by, satisfied_by)
        return f"Credential env signal: satisfied ({lbl})"
    return "Credential env signal: none detected"


def require_snow_cli() -> None:
    """Exit 2 if `snow` is not on PATH."""
    if not shutil.which("snow"):
        click.echo(
            click.style(
                "snow CLI not found on PATH. Install snowflake-cli (e.g. "
                "pip install 'snowflake-cli>=3.16.0') or run from a project venv: "
                "uv run check-setup",
                fg="red",
            )
        )
        sys.exit(2)


def _manifest_connection(manifest_path: str = DEFAULT_MANIFEST_PATH) -> str | None:
    """Read [snowflake].connection from manifest.toml. Returns None if not set."""
    p = Path(manifest_path)
    if not p.exists():
        return None
    try:
        with p.open("rb") as fh:
            data = tomllib.load(fh)
        return data.get("snowflake", {}).get("connection") or None
    except Exception:
        return None


def run_sql(query: str, connection: str | None = None) -> list | None:
    """Execute SQL and return parsed JSON result.

    Uses *connection* if provided, otherwise falls back to the manifest
    connection, then the SNOWFLAKE_DEFAULT_CONNECTION_NAME env var.
    """
    conn = connection or _manifest_connection() or os.environ.get(
        "SNOWFLAKE_DEFAULT_CONNECTION_NAME"
    )
    cmd = ["snow", "sql", "--query", query, "--format", "json"]
    if conn:
        cmd.extend(["-c", conn])

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None

    if result.stdout.strip():
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
    return None


def _fetch_connection_metadata(connection: str) -> dict:
    """Fetch account/user/account_url via snow connection test -c <connection>."""
    cmd = ["snow", "connection", "test", "-c", connection, "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return {}
    try:
        data = json.loads(result.stdout)
        if isinstance(data, list) and data:
            data = data[0]
        host = (
            data.get("Host") or data.get("host") or data.get("SnowflakeHost") or ""
        )
        return {
            "account": str(data.get("Account") or data.get("account") or "").strip(),
            "user": str(data.get("User") or data.get("user") or "").strip(),
            "account_url": f"https://{host}".strip() if host else "",
        }
    except Exception:
        return {}


def _update_manifest_prereqs(
    manifest_path: str,
    connection: str | None,
    admin_role: str,
) -> None:
    """Write connection metadata and tools_verified date to manifest after tools verified.

    For external volumes, tools_verified means snow + CSP CLI are confirmed on PATH.
    No database setup is needed for account-level external volume objects.
    """
    p = Path(manifest_path)
    if not p.exists():
        return
    data = load_manifest(manifest_path)
    if not data:
        return

    sf = data.setdefault("snowflake", {})
    if connection:
        sf["connection"] = connection
        meta = _fetch_connection_metadata(connection)
        for k, v in meta.items():
            if v:
                sf[k] = v
    sf.setdefault("admin_role", admin_role)

    prereqs = data.setdefault("prereqs", {})
    prereqs["tools_verified"] = datetime.date.today().isoformat()

    save_manifest(manifest_path, data)


def csp_cli_tools_for_provider(provider_key: str) -> tuple[list[dict[str, object]], bool]:
    """Return tool status dicts and whether all required tools are on PATH."""
    pairs = PROVIDER_CLI_TOOLS[provider_key]
    tools: list[dict[str, object]] = []
    for prov_label, exe in pairs:
        tools.append(
            {
                "provider": prov_label,
                "tool": exe,
                "available": shutil.which(exe) is not None,
            }
        )
    all_available = all(bool(t["available"]) for t in tools)
    return tools, all_available


@click.command()
@click.option("--suggest", is_flag=True, help="Output suggested defaults as JSON")
@click.option(
    "--admin-role",
    envvar="SA_ADMIN_ROLE",
    default=None,
    help="Admin role to cache in manifest (default: ACCOUNTADMIN)",
)
@click.option(
    "--provider",
    type=click.Choice(list(PROVIDER_CLI_TOOLS.keys()), case_sensitive=False),
    default="s3",
    help="Storage provider: which CSP CLI tools and credential env vars to check (default: s3).",
)
@click.option(
    "--manifest-path",
    default=DEFAULT_MANIFEST_PATH,
    show_default=True,
    help="Path to manifest.toml",
)
def check(
    suggest: bool,
    admin_role: str | None,
    provider: str,
    manifest_path: str,
) -> None:
    """Check that snow CLI and CSP tools are ready for external volume creation.

    External volumes are account-level Snowflake objects — no database setup
    is needed.  This command verifies:
      - snow CLI is on PATH
      - CSP CLI tools (aws/az/gcloud) are on PATH for the selected provider
      - Credential env signals are present (informational only)

    On success, writes [prereqs].tools_verified to manifest.toml.

    Exit codes:
      0 - Tools ready
      1 - Required tools missing
      2 - Error during check (e.g. snow CLI missing)
    """
    require_snow_cli()

    provider_key = provider.lower()
    csp_tools, csp_tools_ready = csp_cli_tools_for_provider(provider_key)
    cred_env = csp_credential_env_snapshot(provider_key)
    cred_signal, cred_satisfied_by, cred_note = csp_credential_signal_for_provider(provider_key)

    connection = _manifest_connection(manifest_path) or os.environ.get(
        "SNOWFLAKE_DEFAULT_CONNECTION_NAME"
    )

    if suggest:
        click.echo(
            json.dumps(
                {
                    "connection": connection or None,
                    "ready": csp_tools_ready,
                    "provider": provider_key,
                    "csp_cli_tools": csp_tools,
                    "csp_tools_ready": csp_tools_ready,
                    "csp_credential_env": cred_env,
                    "csp_credential_env_signal": cred_signal,
                    "csp_credential_env_satisfied_by": cred_satisfied_by,
                    "credential_env_note": cred_note,
                    "supported_storage_providers": SUPPORTED_STORAGE_PROVIDERS,
                    "planned_storage_providers": PLANNED_STORAGE_PROVIDERS,
                }
            )
        )
        sys.exit(0)

    ver_result = subprocess.run(["snow", "--version"], capture_output=True, text=True, check=False)
    snow_version = ver_result.stdout.strip() if ver_result.returncode == 0 else "unknown"
    click.echo(f"Using {snow_version}")

    click.echo("sfutils-extvolumes pre-flight check\n")
    click.echo(f"CSP CLI tools (provider={provider_key})")
    for entry in csp_tools:
        exe = str(entry["tool"])
        ok = bool(entry["available"])
        line = f"  {exe}: " + ("OK" if ok else "MISSING (not on PATH)")
        click.echo(click.style(line, fg="green" if ok else "yellow"))
    click.echo()

    summary = _credential_env_human_summary(
        provider_key, cred_satisfied_by, cred_signal, cred_note
    )
    click.echo(summary)
    set_vars = [str(e["name"]) for e in cred_env if bool(e["set"])]
    if set_vars:
        click.echo("  Set credential-related env (names only): " + ", ".join(set_vars))
    if not cred_signal and cred_note:
        click.echo(click.style(f"  Note: {cred_note}", fg="yellow"))
    click.echo()

    if not csp_tools_ready:
        click.echo(click.style("⚠ Required CSP CLI tools missing", fg="yellow"))
        for entry in csp_tools:
            if not bool(entry["available"]):
                click.echo(f"  ✗ {entry['tool']} not found on PATH")
        sys.exit(1)

    click.echo(click.style("✓ Tools ready", fg="green"))
    resolved_role = resolved_sa_admin_role(admin_role=admin_role)
    _update_manifest_prereqs(manifest_path, connection, resolved_role)
    if Path(manifest_path).exists():
        click.echo(f"  tools_verified written to {manifest_path}")
    sys.exit(0)


if __name__ == "__main__":
    check()
