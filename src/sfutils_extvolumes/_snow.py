"""
Vendored snow CLI utilities for sfutils-extvolumes.

Thin wrappers around the `snow` CLI for executing SQL, plus
sensitive-value masking for AWS ARNs, account IDs, and external IDs.
Originally aligned with shared sfutils patterns; this package is self-contained
beyond click/boto3. Feel free to customize for extvolume-specific needs.
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass

import click


@dataclass
class SnowCLIOptions:
    """Options for snow CLI commands."""

    verbose: bool = False
    debug: bool = False
    mask_sensitive: bool = True

    def get_flags(self) -> list[str]:
        flags = []
        if self.debug:
            flags.append("--debug")
        elif self.verbose:
            flags.append("--verbose")
        return flags


_snow_cli_options = SnowCLIOptions()


def mask_aws_account_id(value: str) -> str:
    """Mask AWS account ID: 123456789012 -> 1234****9012"""
    if len(value) == 12 and value.isdigit():
        return f"{value[:4]}****{value[-4:]}"
    return value


def mask_ip_address(value: str) -> str:
    """Mask IP address: 192.168.1.100 -> 192.168.***.***"""
    parts = value.replace("/32", "").split(".")
    if len(parts) == 4:
        masked = f"{parts[0]}.{parts[1]}.***.***"
        if "/32" in value:
            masked += "/32"
        return masked
    return value


def mask_external_id(value: str) -> str:
    """Mask external ID: abc123xyz -> abc***xyz"""
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:3]}{'*' * (len(value) - 6)}{value[-3:]}"


def mask_arn(value: str) -> str:
    """Mask ARN account ID portion."""
    pattern = r"(arn:aws:[^:]+:[^:]*:)(\d{12})(:.+)"
    match = re.match(pattern, value)
    if match:
        return f"{match.group(1)}{mask_aws_account_id(match.group(2))}{match.group(3)}"
    return value


def mask_sensitive_string(value: str, mask_type: str = "auto") -> str:
    """Mask a sensitive string based on type or auto-detect."""
    if not _snow_cli_options.mask_sensitive:
        return value

    is_account_id = mask_type == "aws_account_id" or (
        mask_type == "auto" and len(value) == 12 and value.isdigit()
    )
    if is_account_id:
        return mask_aws_account_id(value)
    is_ip = mask_type == "ip" or (
        mask_type == "auto" and re.match(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$", value)
    )
    if is_ip:
        return mask_ip_address(value)
    elif mask_type == "arn" or (mask_type == "auto" and value.startswith("arn:aws:")):
        return mask_arn(value)
    elif mask_type == "external_id":
        return mask_external_id(value)
    return value


def set_masking(enabled: bool) -> None:
    """Enable or disable sensitive value masking."""
    global _snow_cli_options
    _snow_cli_options.mask_sensitive = enabled


def is_masking_enabled() -> bool:
    """Check if masking is enabled."""
    return _snow_cli_options.mask_sensitive


def set_snow_cli_options(
    verbose: bool = False, debug: bool = False, mask_sensitive: bool = True
) -> None:
    """Set global snow CLI options."""
    global _snow_cli_options
    _snow_cli_options = SnowCLIOptions(verbose=verbose, debug=debug, mask_sensitive=mask_sensitive)


def get_snow_cli_options() -> SnowCLIOptions:
    """Get current snow CLI options."""
    return _snow_cli_options


def run_snow_sql(
    query: str, *, format: str = "json", check: bool = True, role: str | None = None
) -> dict | list | None:
    """Execute a snow sql command and return parsed JSON output."""
    cmd = ["snow", "sql", *_snow_cli_options.get_flags(), "--query", query, "--format", format]
    if role:
        cmd.extend(["--role", role])

    if _snow_cli_options.debug:
        click.echo(f"[DEBUG] Running: snow sql --query ({len(query)} chars — set SFUTILS_DEBUG_SQL=1 to show)")
        if os.environ.get("SFUTILS_DEBUG_SQL"):
            click.echo(f"[DEBUG] Full cmd: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if _snow_cli_options.debug and result.stderr:
        click.echo(f"[DEBUG] stderr: {result.stderr}")

    if check and result.returncode != 0:
        raise click.ClickException(f"snow sql failed: {result.stderr}")

    if format == "json" and result.stdout.strip():
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
    return None


def run_snow_sql_stdin(sql: str, *, check: bool = True) -> subprocess.CompletedProcess:
    """Execute multi-statement SQL via stdin."""
    cmd = ["snow", "sql", *_snow_cli_options.get_flags(), "--stdin"]

    if _snow_cli_options.debug:
        click.echo(f"[DEBUG] Running: {' '.join(cmd)}")
        click.echo(f"[DEBUG] SQL ({len(sql)} chars — set SFUTILS_DEBUG_SQL=1 to show)")
        if os.environ.get("SFUTILS_DEBUG_SQL"):
            click.echo(sql)

    result = subprocess.run(cmd, input=sql, capture_output=True, text=True, check=False)

    if _snow_cli_options.debug and result.stderr:
        click.echo(f"[DEBUG] stderr: {result.stderr}")
    if _snow_cli_options.debug and result.stdout:
        click.echo(f"[DEBUG] stdout: {result.stdout}")

    if check and result.returncode != 0:
        raise click.ClickException(f"snow sql failed: {result.stderr}")

    return result
