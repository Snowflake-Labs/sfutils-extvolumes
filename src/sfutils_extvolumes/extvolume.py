#!/usr/bin/env python3
# Copyright 2026 Snowflake Inc.
# Generated with Cortex Code
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
"""
Snowflake External Volume Manager

Creates and configures:
- S3 bucket for Iceberg table storage
- IAM policy and role with trust relationship
- Snowflake external volume
- Updates IAM trust policy with Snowflake's IAM user ARN and external ID
"""

import getpass
import json
import os
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import boto3
import click
from botocore.exceptions import ClientError
from dotenv import load_dotenv

from sfutils_extvolumes._snow import (
    mask_sensitive_string,
    run_snow_sql,
    run_snow_sql_stdin,
    set_masking,
    set_snow_cli_options,
)

# =============================================================================
# Wait Utilities
# =============================================================================


def wait_with_backoff(
    check_fn: Callable[[], bool],
    description: str,
    max_attempts: int = 6,
    initial_delay: float = 2.0,
    max_delay: float = 30.0,
    backoff_factor: float = 2.0,
) -> bool:
    """
    Wait with exponential backoff until check_fn returns True.

    Args:
        check_fn: Function that returns True when ready, False otherwise
        description: What we're waiting for (for logging)
        max_attempts: Maximum number of attempts
        initial_delay: Initial delay in seconds
        max_delay: Maximum delay between attempts
        backoff_factor: Multiplier for each subsequent delay

    Returns:
        True if check succeeded, False if all attempts exhausted
    """
    delay = initial_delay
    for attempt in range(1, max_attempts + 1):
        if check_fn():
            return True
        if attempt < max_attempts:
            click.echo(f"  Waiting for {description}... (attempt {attempt}/{max_attempts})")
            time.sleep(delay)
            delay = min(delay * backoff_factor, max_delay)
    return False


def wait_for_iam_role(iam_client: Any, role_name: str, max_wait: int = 30) -> None:
    """Wait for IAM role to be available with exponential backoff."""
    click.echo("Waiting for IAM role propagation...")

    def check_role() -> bool:
        try:
            iam_client.get_role(RoleName=role_name)
            return True
        except ClientError:
            return False

    if wait_with_backoff(check_role, "IAM role", max_attempts=6, initial_delay=2.0):
        click.echo("✓ IAM role is available")
    else:
        click.echo("⚠ IAM role propagation timeout, proceeding anyway...")


def wait_for_trust_policy(
    iam_client: Any, role_name: str, expected_principal: str, max_wait: int = 30
) -> None:
    """Wait for IAM trust policy to be updated with exponential backoff."""
    click.echo("Waiting for trust policy propagation...")

    def check_trust() -> bool:
        try:
            response = iam_client.get_role(RoleName=role_name)
            trust_policy = response["Role"]["AssumeRolePolicyDocument"]
            for statement in trust_policy.get("Statement", []):
                principal = statement.get("Principal", {})
                if isinstance(principal, dict):
                    aws_principal = principal.get("AWS", "")
                    if expected_principal in str(aws_principal):
                        return True
            return False
        except ClientError:
            return False

    if wait_with_backoff(check_trust, "trust policy", max_attempts=6, initial_delay=2.0):
        click.echo("✓ Trust policy is updated")
    else:
        click.echo("⚠ Trust policy propagation timeout, proceeding anyway...")


def normalize_identifier(name: str, style: str = "snowflake") -> str:
    """Normalize name for SQL or DNS compliance.

    Args:
        name: Raw input (e.g., "My Cool Project!")
        style: "snowflake" (UPPER_SNAKE) or "aws" (lower-kebab)

    Returns:
        Normalized identifier safe for SQL or AWS DNS
    """
    clean = re.sub(r"[^a-zA-Z0-9\s\-_]", "", name)
    clean = re.sub(r"\s+", "_" if style == "snowflake" else "-", clean)
    clean = re.sub(r"[-_]+", "_" if style == "snowflake" else "-", clean)
    clean = clean.strip("-_")

    if style == "snowflake":
        return clean.upper()
    else:
        return clean.lower()


def format_comment(prefix: str | None, bucket: str) -> str:
    """Format comment using consistent pattern across sfutils skills.

    Pattern: "Used by {USER} - {PROJECT} app - managed by sfutils-extvolumes"
    """
    user_part = normalize_identifier(prefix, "snowflake") if prefix else "USER"
    project_part = normalize_identifier(bucket, "snowflake")
    return f"Used by {user_part} - {project_part} app - managed by sfutils-extvolumes"


@dataclass
class ExternalVolumeConfig:
    """Configuration for external volume setup."""

    bucket_name: str
    role_name: str
    policy_name: str
    volume_name: str
    storage_location_name: str
    external_id: str
    aws_region: str
    allow_writes: bool = True
    comment: str = ""


# =============================================================================
# Naming Utilities
# =============================================================================


def get_current_username() -> str:
    """Get the current username for prefixing resources.

    Priority: SNOWFLAKE_USER env var > system username (getpass.getuser)
    This matches the pattern used by PAT/Networks skills.
    """
    return os.environ.get("SNOWFLAKE_USER", getpass.getuser()).lower()


def to_aws_name(name: str, prefix: str | None = None) -> str:
    """
    Convert a name to AWS-compatible format.

    AWS names can contain alphanumeric characters, hyphens, and some allow underscores.
    S3 bucket names: lowercase, 3-63 chars, no dots, alphanumeric and hyphens.
    IAM names: alphanumeric, plus these characters: +=,.@_-
    """
    # Lowercase and replace underscores with hyphens for consistency
    aws_name = name.lower().replace("_", "-")
    # Remove any characters that aren't alphanumeric or hyphens
    aws_name = re.sub(r"[^a-z0-9-]", "", aws_name)
    # Remove consecutive hyphens
    aws_name = re.sub(r"-+", "-", aws_name)
    # Remove leading/trailing hyphens
    aws_name = aws_name.strip("-")

    if prefix:
        prefix = prefix.lower().replace("_", "-")
        prefix = re.sub(r"[^a-z0-9-]", "", prefix)
        aws_name = f"{prefix}-{aws_name}"

    return aws_name


def to_sql_identifier(name: str, prefix: str | None = None) -> str:
    """
    Convert a name to valid Snowflake SQL identifier.

    Snowflake unquoted identifiers: start with letter or underscore,
    contain letters, digits, underscores. Case-insensitive (stored uppercase).
    """
    # Replace hyphens and spaces with underscores
    sql_name = name.replace("-", "_").replace(" ", "_")
    # Remove any characters that aren't alphanumeric or underscores
    sql_name = re.sub(r"[^a-zA-Z0-9_]", "", sql_name)
    # Remove consecutive underscores
    sql_name = re.sub(r"_+", "_", sql_name)
    # Remove leading/trailing underscores
    sql_name = sql_name.strip("_")
    # Ensure it starts with a letter or underscore (not a digit)
    if sql_name and sql_name[0].isdigit():
        sql_name = f"_{sql_name}"

    if prefix:
        prefix = prefix.replace("-", "_").replace(" ", "_")
        prefix = re.sub(r"[^a-zA-Z0-9_]", "", prefix)
        sql_name = f"{prefix}_{sql_name}"

    return sql_name.upper()


def generate_external_id(bucket: str, prefix: str | None = None) -> str:
    """
    Generate a unique external ID for AWS trust policy.

    The external ID is used to prevent the "confused deputy" problem in AWS.
    It combines a readable prefix with a unique suffix for security.

    Format: {PREFIX}_{BUCKET}_EXT_{SHORT_UUID}
    Example: KSAMPATH_ICEBERG_DEMO_EXT_A1B2C3D4
    """
    # Generate a short unique suffix (8 chars from UUID)
    unique_suffix = uuid.uuid4().hex[:8].upper()

    # Build the base name
    base_name = f"{bucket}_ext_{unique_suffix}"

    return to_sql_identifier(base_name, prefix)


def get_aws_account_id(sts_client: Any) -> str:
    """Get the current AWS account ID."""
    return sts_client.get_caller_identity()["Account"]


def get_resource_tags(prefix: str | None, bucket: str, volume_name: str) -> list[dict[str, str]]:
    """Generate AWS resource tags for traceability and cost allocation.

    Tags follow the consistent sfutils pattern for all AWS resources.
    """
    user_part = normalize_identifier(prefix, "snowflake") if prefix else "UNKNOWN"
    project_part = normalize_identifier(bucket, "snowflake")
    return [
        {"Key": "managed-by", "Value": "sfutils-extvolumes"},
        {"Key": "user", "Value": user_part},
        {"Key": "project", "Value": project_part},
        {"Key": "snowflake-volume", "Value": volume_name},
    ]


# =============================================================================
# S3 Bucket Operations
# =============================================================================


def create_s3_bucket(
    s3_client: Any,
    bucket_name: str,
    region: str,
    versioning: bool = True,
    tags: list[dict[str, str]] | None = None,
) -> bool:
    """Create an S3 bucket with optional versioning and tags."""
    click.echo(f"Creating S3 bucket: {bucket_name}")

    try:
        # Check if bucket exists
        try:
            s3_client.head_bucket(Bucket=bucket_name)
            click.echo(f"✓ Bucket {bucket_name} already exists")
            return False
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "403":
                raise click.ClickException(
                    f"Bucket {bucket_name} exists but you don't have access. "
                    "Choose a different bucket name."
                ) from e
            if error_code != "404":
                raise

        # Create bucket with location constraint for non-us-east-1 regions
        create_params: dict[str, Any] = {"Bucket": bucket_name}
        if region != "us-east-1":
            create_params["CreateBucketConfiguration"] = {"LocationConstraint": region}

        s3_client.create_bucket(**create_params)
        click.echo(f"✓ Created bucket: {bucket_name}")

        # Enable versioning (recommended for data recovery)
        if versioning:
            s3_client.put_bucket_versioning(
                Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
            )
            click.echo("✓ Enabled bucket versioning")

        # Apply tags for traceability
        if tags:
            s3_client.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": tags})
            click.echo("✓ Applied resource tags")

        return True

    except ClientError as e:
        raise click.ClickException(f"Failed to create bucket: {e}") from e


def delete_s3_bucket(s3_client: Any, bucket_name: str, force: bool = False) -> None:
    """Delete an S3 bucket (optionally emptying it first)."""
    click.echo(f"Deleting S3 bucket: {bucket_name}")

    try:
        if force:
            # Delete all objects first
            paginator = s3_client.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket_name):
                objects_to_delete = []
                for version in page.get("Versions", []):
                    objects_to_delete.append(
                        {"Key": version["Key"], "VersionId": version["VersionId"]}
                    )
                for marker in page.get("DeleteMarkers", []):
                    objects_to_delete.append(
                        {"Key": marker["Key"], "VersionId": marker["VersionId"]}
                    )
                if objects_to_delete:
                    s3_client.delete_objects(
                        Bucket=bucket_name, Delete={"Objects": objects_to_delete}
                    )

        s3_client.delete_bucket(Bucket=bucket_name)
        click.echo(f"✓ Deleted bucket: {bucket_name}")

    except ClientError as e:
        raise click.ClickException(f"Failed to delete bucket: {e}") from e


# =============================================================================
# IAM Policy Operations
# =============================================================================


def get_s3_access_policy(bucket_name: str) -> dict:
    """Generate IAM policy document for S3 access."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:DeleteObject",
                    "s3:DeleteObjectVersion",
                ],
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringLike": {"s3:prefix": ["*"]}},
            },
        ],
    }


def create_iam_policy(
    iam_client: Any,
    policy_name: str,
    bucket_name: str,
    tags: list[dict[str, str]] | None = None,
    sts_client: Any | None = None,
) -> str:
    """Create IAM policy for S3 access and return the policy ARN.

    Args:
        sts_client: Optional pre-configured STS client. When omitted a new
            ``boto3.client("sts")`` is created, which inherits the current
            env -- problematic when RustFS ``AWS_*`` vars are set.
    """
    click.echo(f"Creating IAM policy: {policy_name}")

    account_id = get_aws_account_id(sts_client or boto3.client("sts"))
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"

    try:
        # Check if policy exists
        try:
            iam_client.get_policy(PolicyArn=policy_arn)
            click.echo(f"✓ Policy {policy_name} already exists")
            return policy_arn
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

        # Create policy
        policy_document = get_s3_access_policy(bucket_name)
        create_params: dict[str, Any] = {
            "PolicyName": policy_name,
            "PolicyDocument": json.dumps(policy_document),
            "Description": f"Policy for Snowflake external volume access to {bucket_name}",
        }
        if tags:
            create_params["Tags"] = tags
        response = iam_client.create_policy(**create_params)
        policy_arn = response["Policy"]["Arn"]
        click.echo(f"✓ Created policy: {policy_arn}")
        return policy_arn

    except ClientError as e:
        raise click.ClickException(f"Failed to create IAM policy: {e}") from e


def delete_iam_policy(iam_client: Any, policy_arn: str) -> None:
    """Delete an IAM policy."""
    click.echo(f"Deleting IAM policy: {policy_arn}")

    try:
        iam_client.delete_policy(PolicyArn=policy_arn)
        click.echo(f"✓ Deleted policy: {policy_arn}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise click.ClickException(f"Failed to delete policy: {e}") from e


# =============================================================================
# IAM Role Operations
# =============================================================================


def get_initial_trust_policy(account_id: str, external_id: str) -> dict:
    """Generate initial trust policy (before Snowflake user ARN is known)."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }


def get_snowflake_trust_policy(snowflake_user_arn: str, external_id: str) -> dict:
    """Generate trust policy for Snowflake IAM user."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SnowflakeAccess",
                "Effect": "Allow",
                "Principal": {"AWS": snowflake_user_arn},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }


def create_iam_role(
    iam_client: Any,
    role_name: str,
    policy_arn: str,
    account_id: str,
    external_id: str,
    tags: list[dict[str, str]] | None = None,
) -> str:
    """Create IAM role with initial trust policy and return the role ARN."""
    click.echo(f"Creating IAM role: {role_name}")

    try:
        # Check if role exists
        try:
            response = iam_client.get_role(RoleName=role_name)
            role_arn = response["Role"]["Arn"]
            click.echo(f"✓ Role {role_name} already exists")
            return role_arn
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

        # Create role with initial trust policy
        trust_policy = get_initial_trust_policy(account_id, external_id)
        create_params: dict[str, Any] = {
            "RoleName": role_name,
            "AssumeRolePolicyDocument": json.dumps(trust_policy),
            "Description": "IAM role for Snowflake external volume access",
        }
        if tags:
            create_params["Tags"] = tags
        response = iam_client.create_role(**create_params)
        role_arn = response["Role"]["Arn"]
        click.echo(f"✓ Created role: {role_arn}")

        # Attach policy to role
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        click.echo("✓ Attached policy to role")

        return role_arn

    except ClientError as e:
        raise click.ClickException(f"Failed to create IAM role: {e}") from e


def update_role_trust_policy(
    iam_client: Any, role_name: str, snowflake_user_arn: str, external_id: str
) -> None:
    """Update IAM role trust policy with Snowflake IAM user ARN."""
    click.echo(f"Updating trust policy for role: {role_name}")

    try:
        trust_policy = get_snowflake_trust_policy(snowflake_user_arn, external_id)
        iam_client.update_assume_role_policy(
            RoleName=role_name, PolicyDocument=json.dumps(trust_policy)
        )
        click.echo(f"✓ Updated trust policy with Snowflake IAM user: {snowflake_user_arn}")

    except ClientError as e:
        raise click.ClickException(f"Failed to update trust policy: {e}") from e


def delete_iam_role(iam_client: Any, role_name: str, policy_arn: str) -> None:
    """Delete an IAM role (detaching policies first)."""
    click.echo(f"Deleting IAM role: {role_name}")

    try:
        # Detach policy first
        try:
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            click.echo("✓ Detached policy from role")
        except ClientError:
            pass

        iam_client.delete_role(RoleName=role_name)
        click.echo(f"✓ Deleted role: {role_name}")

    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise click.ClickException(f"Failed to delete role: {e}") from e


# =============================================================================
# Snowflake External Volume Operations
# =============================================================================


def _sql_str(value: str) -> str:
    """Escape a value for safe use inside a SQL single-quoted literal."""
    return value.replace("'", "''")


_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def _assert_safe_identifier(value: str, label: str = "identifier") -> None:
    """Raise ClickException if value is not a safe unquoted SQL identifier."""
    if not _IDENT_RE.match(value):
        raise click.ClickException(
            f"Invalid {label} '{value}': must match ^[A-Za-z_][A-Za-z0-9_$]*$"
        )


def get_external_volume_sql(
    config: ExternalVolumeConfig, role_arn: str, force: bool = False
) -> str:
    """Generate SQL for creating external volume."""
    _assert_safe_identifier(config.volume_name, "volume_name")
    _assert_safe_identifier(config.storage_location_name, "storage_location_name")
    allow_writes = "TRUE" if config.allow_writes else "FALSE"
    create_stmt = (
        "CREATE OR REPLACE EXTERNAL VOLUME" if force else "CREATE EXTERNAL VOLUME IF NOT EXISTS"
    )
    comment_clause = f"\n    COMMENT = '{_sql_str(config.comment)}'" if config.comment else ""
    return f"""{create_stmt} {config.volume_name}
    STORAGE_LOCATIONS = (
        (
            NAME = '{_sql_str(config.storage_location_name)}'
            STORAGE_PROVIDER = 'S3'
            STORAGE_BASE_URL = 's3://{_sql_str(config.bucket_name)}/'
            STORAGE_AWS_ROLE_ARN = '{_sql_str(role_arn)}'
            STORAGE_AWS_EXTERNAL_ID = '{_sql_str(config.external_id)}'
        )
    )
    ALLOW_WRITES = {allow_writes}{comment_clause};"""


def create_external_volume(
    config: ExternalVolumeConfig, role_arn: str, force: bool = False
) -> None:
    """Create Snowflake external volume."""
    click.echo(f"Creating Snowflake external volume: {config.volume_name}")
    sql = get_external_volume_sql(config, role_arn, force)
    run_snow_sql_stdin(sql)
    click.echo(f"✓ Created external volume: {config.volume_name}")


def describe_external_volume(volume_name: str) -> dict[str, str]:
    """Describe external volume and extract AWS IAM user ARN and external ID."""
    _assert_safe_identifier(volume_name, "volume_name")
    click.echo(f"Describing external volume: {volume_name}")

    try:
        result = run_snow_sql(f"DESC EXTERNAL VOLUME {volume_name}")
    except click.ClickException as e:
        raise click.ClickException(
            f"Failed to describe external volume '{volume_name}'. "
            f"Verify the volume exists and you have access.\nError: {e}"
        ) from e

    if not result:
        raise click.ClickException(
            f"No data returned when describing external volume '{volume_name}'"
        )

    # Parse the result to find STORAGE_AWS_IAM_USER_ARN and STORAGE_AWS_EXTERNAL_ID
    properties = {}
    for row in result:
        parent_prop = row.get("parent_property", "")
        prop_name = row.get("property", "")
        prop_value = row.get("property_value", "")

        # Storage location details are nested as JSON inside property_value
        if parent_prop == "STORAGE_LOCATIONS" and prop_name.startswith("STORAGE_LOCATION_"):
            try:
                location_data = json.loads(prop_value)
                if "STORAGE_AWS_IAM_USER_ARN" in location_data:
                    properties["iam_user_arn"] = location_data["STORAGE_AWS_IAM_USER_ARN"]
                if "STORAGE_AWS_EXTERNAL_ID" in location_data:
                    properties["external_id"] = location_data["STORAGE_AWS_EXTERNAL_ID"]
            except json.JSONDecodeError:
                pass  # Skip if not valid JSON

    if "iam_user_arn" not in properties:
        raise click.ClickException(
            "Could not find STORAGE_AWS_IAM_USER_ARN in external volume description"
        )

    iam_user_arn = properties.get("iam_user_arn")
    external_id = properties.get("external_id")
    click.echo(f"✓ Snowflake IAM User ARN: {mask_sensitive_string(iam_user_arn, 'arn')}")  # pyright: ignore[reportArgumentType]
    click.echo(f"✓ External ID: {mask_sensitive_string(external_id, 'external_id')}")  # pyright: ignore[reportArgumentType]

    return properties


def drop_external_volume(volume_name: str) -> None:
    """Drop Snowflake external volume."""
    _assert_safe_identifier(volume_name, "volume_name")
    click.echo(f"Dropping Snowflake external volume: {volume_name}")

    run_snow_sql(f"DROP EXTERNAL VOLUME IF EXISTS {volume_name}")
    click.echo(f"✓ Dropped external volume: {volume_name}")


def verify_external_volume(volume_name: str) -> None:
    """Verify external volume connectivity."""
    click.echo(f"Verifying external volume: {volume_name}")

    result = run_snow_sql(f"SELECT SYSTEM$VERIFY_EXTERNAL_VOLUME('{_sql_str(volume_name)}')")

    if not result:
        click.echo("⚠ Could not verify external volume")
        return

    # The result column name may vary based on volume name case
    status_json = None
    for key, value in result[0].items():
        if "SYSTEM$VERIFY_EXTERNAL_VOLUME" in key.upper():
            status_json = value
            break

    if not status_json:
        click.echo("⚠ Could not find verification result")
        return

    # Parse the JSON response
    try:
        verification = json.loads(status_json)
        success = verification.get("success", False)
        storage_result = verification.get("storageLocationSelectionResult", "N/A")

        if success:
            click.echo("✓ External volume verified successfully")
        else:
            click.echo("✗ External volume verification failed")

        click.echo(f"  success: {success}")
        click.echo(f"  storageLocationSelectionResult: {storage_result}")

    except json.JSONDecodeError:
        # Fallback to raw output if not valid JSON
        if "success" in status_json.lower():
            click.echo("✓ External volume verified successfully")
        else:
            click.echo(f"⚠ Verification result: {status_json}")


# =============================================================================
# CLI Commands
# =============================================================================

# Auto-load .env from current working directory so callers
# don't need ``set -a && source .env && set +a`` before invoking.
load_dotenv()


@click.group()
@click.option(
    "--region",
    "-r",
    envvar="AWS_REGION",
    default="us-west-2",
    help="AWS region (or set AWS_REGION env var)",
)
@click.option(
    "--prefix",
    "-p",
    envvar="EXTVOLUME_PREFIX",
    default=None,
    help="Prefix for AWS resources (default: current username). Use --no-prefix to disable.",
)
@click.option(
    "--no-prefix",
    is_flag=True,
    help="Disable username prefix for AWS resources",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output (info level logging for snow CLI)",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug output (debug level logging for snow CLI, shows SQL)",
)
@click.option(
    "--comment",
    "-c",
    default=None,
    help="Comment for external volume (inferred from prefix/bucket if not provided)",
)
@click.pass_context
def cli(
    ctx: click.Context,
    region: str,
    prefix: str | None,
    no_prefix: bool,
    verbose: bool,
    debug: bool,
    comment: str | None,
) -> None:
    """
    Snowflake External Volume Manager

    Setup and manage external volumes with S3 storage for Iceberg tables,
    data lake access, COPY INTO unload, and external stages.

    Storage backends: AWS S3 is supported. Azure Blob Storage and Google Cloud
    Storage are not implemented in this CLI yet.

    \b
    By default, AWS resources are prefixed with your username to avoid conflicts
    in shared accounts. Use --no-prefix to disable or --prefix to customize.

    \b
    Debug options:
        --verbose  Show info level output from snow CLI
        --debug    Show debug output including SQL statements

    \b
    Prerequisites:
    - AWS credentials configured (aws configure or environment variables)
    - Snowflake CLI configured (snow connection test)
    - Appropriate permissions in both AWS and Snowflake
    """
    # Set global snow CLI options
    set_snow_cli_options(verbose=verbose, debug=debug)

    ctx.ensure_object(dict)
    ctx.obj["region"] = region

    # Determine prefix: explicit prefix > no-prefix flag > default (username)
    if no_prefix:
        ctx.obj["prefix"] = None
    elif prefix:
        ctx.obj["prefix"] = prefix
    else:
        ctx.obj["prefix"] = get_current_username()

    ctx.obj["comment"] = comment

    if ctx.obj["prefix"]:
        click.echo(f"Using prefix: {ctx.obj['prefix']}")


@cli.command()
@click.option(
    "--bucket",
    "-b",
    required=True,
    envvar="BUCKET",
    help="S3 bucket base name (will be prefixed with username)",
)
@click.option(
    "--role-name",
    default=None,
    help="IAM role name (default: {prefix}-{bucket}-snowflake-role)",
)
@click.option(
    "--policy-name",
    default=None,
    help="IAM policy name (default: {prefix}-{bucket}-snowflake-policy)",
)
@click.option(
    "--volume-name",
    envvar="EXTERNAL_VOLUME_NAME",
    default=None,
    help="Snowflake external volume name (default: {PREFIX}_{BUCKET}_EXTERNAL_VOLUME)",
)
@click.option(
    "--storage-location-name",
    default=None,
    help="Storage location name (default: {prefix}-{bucket}-s3-{region})",
)
@click.option(
    "--external-id",
    default=None,
    help="External ID for trust relationship (default: auto-generated unique ID)",
)
@click.option(
    "--no-writes",
    is_flag=True,
    help="Create read-only external volume",
)
@click.option(
    "--skip-verify",
    is_flag=True,
    help="Skip external volume verification",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Preview what would be created without making changes",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Overwrite existing external volume (CREATE OR REPLACE)",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format (default: text)",
)
@click.pass_context
def create(
    ctx: click.Context,
    bucket: str,
    role_name: str | None,
    policy_name: str | None,
    volume_name: str | None,
    storage_location_name: str | None,
    external_id: str | None,
    no_writes: bool,
    skip_verify: bool,
    dry_run: bool,
    force: bool,
    output: str,
) -> None:
    """
    Create S3 bucket, IAM role, and Snowflake external volume.

    \b
    This command:
    1. Creates an S3 bucket with versioning enabled
    2. Creates an IAM policy for S3 access
    3. Creates an IAM role with initial trust policy
    4. Creates a Snowflake external volume
    5. Retrieves Snowflake's IAM user ARN
    6. Updates IAM role trust policy for Snowflake access
    7. Verifies the external volume connectivity

    \b
    AWS resources are prefixed with your username by default.
    Snowflake objects use SQL-safe naming (hyphens become underscores, UPPERCASE).

    \b
    Example:
        extvolume create --bucket iceberg-data
        # Creates: ksampath-iceberg-data (S3), KSAMPATH_ICEBERG_DATA_EXTERNAL_VOLUME (Snowflake)

        extvolume --no-prefix create --bucket iceberg-data
        # Creates: iceberg-data (S3), ICEBERG_DATA_EXTERNAL_VOLUME (Snowflake)

        extvolume create --bucket iceberg-data --dry-run
        # Preview resources without creating them

        extvolume create --bucket iceberg-data --output json
        # Output results as JSON for automation
    """
    # Validate bucket name (no dots allowed)
    if "." in bucket:
        raise click.ClickException("Bucket names cannot contain dots (S3 SSL limitation)")

    region = ctx.obj["region"]
    prefix = ctx.obj.get("prefix")

    # Generate AWS names (lowercase, hyphens)
    aws_bucket_name = to_aws_name(bucket, prefix)
    aws_role_name = role_name or to_aws_name(f"{bucket}-snowflake-role", prefix)
    aws_policy_name = policy_name or to_aws_name(f"{bucket}-snowflake-policy", prefix)
    aws_storage_location = storage_location_name or to_aws_name(f"{bucket}-s3-{region}", prefix)

    # Generate Snowflake names (uppercase, underscores, SQL-safe)
    sf_volume_name = volume_name or to_sql_identifier(f"{bucket}_external_volume", prefix)
    # Generate a unique external ID for security (prevents confused deputy problem)
    sf_external_id = external_id or generate_external_id(bucket, prefix)
    sf_comment = ctx.obj.get("comment") or format_comment(prefix, bucket)

    config = ExternalVolumeConfig(
        bucket_name=aws_bucket_name,
        role_name=aws_role_name,
        policy_name=aws_policy_name,
        volume_name=sf_volume_name,
        storage_location_name=aws_storage_location,
        external_id=sf_external_id,
        aws_region=region,
        allow_writes=not no_writes,
        comment=sf_comment,
    )

    # Generate resource tags for AWS resources (used in create and JSON output)
    aws_tags = get_resource_tags(prefix, bucket, config.volume_name)

    # Helper to build result dict for JSON output
    def build_result(
        status: str, account_id: str | None = None, role_arn: str | None = None
    ) -> dict:
        result = {
            "status": status,
            "prefix": prefix,
            "aws": {
                "bucket": config.bucket_name,
                "role": config.role_name,
                "policy": config.policy_name,
                "storage_location": config.storage_location_name,
                "region": config.aws_region,
                "tags": {tag["Key"]: tag["Value"] for tag in aws_tags},
            },
            "snowflake": {
                "external_volume": config.volume_name,
                "external_id": config.external_id,
                "allow_writes": config.allow_writes,
                "comment": config.comment,
            },
        }
        if account_id:
            result["aws"]["account_id"] = account_id
        if role_arn:
            result["aws"]["role_arn"] = role_arn
        return result

    # JSON output for dry-run
    if output == "json" and dry_run:
        click.echo(json.dumps(build_result("dry_run"), indent=2))
        return

    # Text output header
    if output == "text":
        click.echo("=" * 60)
        click.echo("Snowflake External Volume Manager - Create")
        if dry_run:
            click.echo("  [DRY RUN - No changes will be made]")
        click.echo("=" * 60)
        click.echo()
        click.echo(f"Prefix:           {prefix or '(none)'}")
        click.echo()
        click.echo("AWS Resources (lowercase, hyphens):")
        click.echo(f"  Bucket:           {config.bucket_name}")
        click.echo(f"  IAM Role:         {config.role_name}")
        click.echo(f"  IAM Policy:       {config.policy_name}")
        click.echo(f"  Storage Location: {config.storage_location_name}")
        click.echo()
        click.echo("Snowflake Objects (UPPERCASE, underscores):")
        click.echo(f"  External Volume:  {config.volume_name}")
        ext_id_display = (
            config.external_id
            if dry_run
            else mask_sensitive_string(config.external_id, "external_id")
        )
        click.echo(f"  External ID:      {ext_id_display}")
        click.echo()
        click.echo(f"Region:           {config.aws_region}")
        click.echo(f"Allow Writes:     {config.allow_writes}")
        click.echo()

    if dry_run:
        set_masking(False)
        # For dry-run, try to get account_id but use placeholder if AWS creds unavailable
        try:
            sts_client = boto3.client("sts")
            account_id = get_aws_account_id(sts_client)
        except Exception:
            account_id = "<AWS_ACCOUNT_ID>"
            click.echo("⚠ AWS credentials not available - using placeholders")
            click.echo()
        role_arn = f"arn:aws:iam::{account_id}:role/{config.role_name}"

        click.echo("─" * 60)
        click.echo("Step 1: Create S3 bucket with versioning")
        click.echo("─" * 60)
        click.echo(f"Bucket: {config.bucket_name}")
        click.echo(f"Region: {region}")
        click.echo("Versioning: Enabled")
        click.echo()

        click.echo("─" * 60)
        click.echo("Step 2: Create IAM Policy")
        click.echo("─" * 60)
        click.echo(f"Policy Name: {config.policy_name}")
        click.echo(f"Policy ARN:  arn:aws:iam::{account_id}:policy/{config.policy_name}")
        click.echo()
        click.echo("Policy Document:")
        policy_doc = get_s3_access_policy(config.bucket_name)
        click.echo(json.dumps(policy_doc, indent=2))
        click.echo()

        click.echo("─" * 60)
        click.echo("Step 3: Create IAM Role with Trust Policy")
        click.echo("─" * 60)
        click.echo(f"Role Name: {config.role_name}")
        click.echo(f"Role ARN:  {role_arn}")
        click.echo()
        click.echo("Initial Trust Policy (before Snowflake IAM user is known):")
        initial_trust = get_initial_trust_policy(account_id, config.external_id)
        click.echo(json.dumps(initial_trust, indent=2))
        click.echo()
        click.echo("Final Trust Policy (after external volume creation):")
        final_trust = get_snowflake_trust_policy("<SNOWFLAKE_IAM_USER_ARN>", config.external_id)
        click.echo(json.dumps(final_trust, indent=2))
        click.echo()

        click.echo("─" * 60)
        click.echo("Step 4: Create Snowflake External Volume")
        click.echo("─" * 60)
        click.echo()
        click.echo(get_external_volume_sql(config, role_arn, force))
        click.echo()

        click.echo("─" * 60)
        click.echo("Step 5-7: Post-creation steps")
        click.echo("─" * 60)
        click.echo("-- Retrieve Snowflake IAM user ARN")
        click.echo(f"DESC EXTERNAL VOLUME {config.volume_name};")
        click.echo()
        click.echo("-- Update IAM trust policy with actual Snowflake IAM user ARN")
        click.echo("-- Verify external volume")
        click.echo(f"SELECT SYSTEM$VERIFY_EXTERNAL_VOLUME('{config.volume_name}');")
        click.echo()
        click.echo("─" * 60)
        click.echo("Dry run complete. No resources were created.")
        click.echo("To create these resources, run without --dry-run")
        return

    # Initialize AWS clients
    s3_client = boto3.client("s3", region_name=region)
    iam_client = boto3.client("iam")
    sts_client = boto3.client("sts")

    account_id = get_aws_account_id(sts_client)
    policy_arn = f"arn:aws:iam::{account_id}:policy/{config.policy_name}"

    if output == "text":
        click.echo(f"AWS Account ID: {mask_sensitive_string(account_id, 'aws_account_id')}")
        click.echo()

    # Track what we've created for potential rollback
    created_bucket = False
    created_policy = False
    created_role = False

    def rollback_aws_resources() -> None:
        """Clean up AWS resources on failure."""
        click.echo()
        click.echo("─" * 40)
        click.echo("Rolling back AWS resources...")
        click.echo("─" * 40)
        if created_role:
            try:
                delete_iam_role(iam_client, config.role_name, policy_arn)
            except Exception as e:
                click.echo(f"⚠ Failed to delete role: {e}")
        if created_policy:
            try:
                delete_iam_policy(iam_client, policy_arn)
            except Exception as e:
                click.echo(f"⚠ Failed to delete policy: {e}")
        if created_bucket:
            try:
                delete_s3_bucket(s3_client, config.bucket_name, force=False)
            except Exception as e:
                click.echo(f"⚠ Failed to delete bucket: {e}")

    try:
        # Step 1: Create S3 bucket
        click.echo("─" * 40)
        click.echo("Step 1: Create S3 Bucket")
        click.echo("─" * 40)
        created_bucket = create_s3_bucket(s3_client, config.bucket_name, region, tags=aws_tags)
        click.echo()

        # Step 2: Create IAM policy
        click.echo("─" * 40)
        click.echo("Step 2: Create IAM Policy")
        click.echo("─" * 40)
        policy_arn = create_iam_policy(
            iam_client, config.policy_name, config.bucket_name, tags=aws_tags
        )
        created_policy = True
        click.echo()

        # Step 3: Create IAM role with initial trust policy
        click.echo("─" * 40)
        click.echo("Step 3: Create IAM Role")
        click.echo("─" * 40)
        role_arn = create_iam_role(
            iam_client, config.role_name, policy_arn, account_id, config.external_id, tags=aws_tags
        )
        created_role = True
        click.echo()

        # Wait for IAM role propagation with backoff
        wait_for_iam_role(iam_client, config.role_name)

        # Step 4: Create Snowflake external volume
        click.echo("─" * 40)
        click.echo("Step 4: Create Snowflake External Volume")
        click.echo("─" * 40)
        create_external_volume(config, role_arn, force)
        click.echo()

        # Step 5: Get Snowflake IAM user ARN
        click.echo("─" * 40)
        click.echo("Step 5: Retrieve Snowflake IAM User")
        click.echo("─" * 40)
        sf_props = describe_external_volume(config.volume_name)
        click.echo()

        # Step 6: Update trust policy
        click.echo("─" * 40)
        click.echo("Step 6: Update IAM Trust Policy")
        click.echo("─" * 40)
        # Use the external ID from Snowflake if different from what we specified
        actual_external_id = sf_props.get("external_id", config.external_id)
        update_role_trust_policy(
            iam_client, config.role_name, sf_props["iam_user_arn"], actual_external_id
        )
        click.echo()

        # Wait for trust policy propagation with backoff
        wait_for_trust_policy(iam_client, config.role_name, sf_props["iam_user_arn"])

        # Step 7: Verify
        if not skip_verify:
            click.echo("─" * 40)
            click.echo("Step 7: Verify External Volume")
            click.echo("─" * 40)
            verify_external_volume(config.volume_name)
            click.echo()

    except click.ClickException:
        rollback_aws_resources()
        raise
    except Exception as e:
        rollback_aws_resources()
        raise click.ClickException(f"Unexpected error: {e}") from e

    # JSON output for successful creation
    if output == "json":
        click.echo(json.dumps(build_result("success", account_id, role_arn), indent=2))
        return

    click.echo("=" * 60)
    click.echo("✓ External volume setup completed successfully!")
    click.echo("=" * 60)
    click.echo()
    click.echo("You can now create Iceberg tables using:")
    click.echo()
    click.echo("  CREATE OR REPLACE ICEBERG TABLE my_iceberg_table (")
    click.echo("      id INT,")
    click.echo("      name STRING,")
    click.echo("      created_at TIMESTAMP_NTZ,")
    click.echo("      amount DECIMAL(10,2)")
    click.echo("    )")
    click.echo("    CATALOG = 'SNOWFLAKE'")
    click.echo(f"    EXTERNAL_VOLUME = '{config.volume_name}'")
    click.echo("    BASE_LOCATION = 'my_iceberg_table';")
    click.echo()
    click.echo("Or with partitioning:")
    click.echo()
    click.echo("  CREATE OR REPLACE ICEBERG TABLE my_partitioned_table (")
    click.echo("      id INT,")
    click.echo("      category STRING,")
    click.echo("      event_date DATE,")
    click.echo("      data VARIANT")
    click.echo("    )")
    click.echo("    CATALOG = 'SNOWFLAKE'")
    click.echo("    PARTITION BY (category)")
    click.echo(f"    EXTERNAL_VOLUME = '{config.volume_name}'")
    click.echo("    BASE_LOCATION = 'my_partitioned_table';")
    click.echo()
    click.echo("See: https://docs.snowflake.com/user-guide/tables-iceberg-create")


@cli.command()
@click.option(
    "--bucket",
    "-b",
    required=True,
    envvar="BUCKET",
    help="S3 bucket base name (same as used in create)",
)
@click.option(
    "--role-name",
    default=None,
    help="IAM role name (default: {prefix}-{bucket}-snowflake-role)",
)
@click.option(
    "--policy-name",
    default=None,
    help="IAM policy name (default: {prefix}-{bucket}-snowflake-policy)",
)
@click.option(
    "--volume-name",
    envvar="EXTERNAL_VOLUME_NAME",
    default=None,
    help="Snowflake external volume name (default: {PREFIX}_{BUCKET}_EXTERNAL_VOLUME)",
)
@click.option(
    "--delete-bucket",
    is_flag=True,
    help="Also delete the S3 bucket (use with --force to delete non-empty bucket)",
)
@click.option(
    "--force",
    is_flag=True,
    help="Force delete bucket even if not empty",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip confirmation prompt (for Cortex Code automation only)",
)
@click.option(
    "-o",
    "--output",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.pass_context
def delete(
    ctx: click.Context,
    bucket: str,
    role_name: str | None,
    policy_name: str | None,
    volume_name: str | None,
    delete_bucket: bool,
    force: bool,
    yes: bool,
    output: str,
) -> None:
    """
    Delete external volume and associated AWS resources.

    \b
    This command:
    1. Drops the Snowflake external volume
    2. Deletes the IAM role
    3. Deletes the IAM policy
    4. Optionally deletes the S3 bucket

    \b
    Uses the same naming conventions as create (with username prefix by default).

    \b
    Example:
        extvolume delete --bucket iceberg-data
        extvolume delete --bucket iceberg-data --delete-bucket --force
    """
    if not yes:
        click.confirm("Are you sure you want to delete these resources?", abort=True)
    region = ctx.obj["region"]
    prefix = ctx.obj.get("prefix")

    # Generate AWS names (lowercase, hyphens)
    aws_bucket_name = to_aws_name(bucket, prefix)
    aws_role_name = role_name or to_aws_name(f"{bucket}-snowflake-role", prefix)
    aws_policy_name = policy_name or to_aws_name(f"{bucket}-snowflake-policy", prefix)

    # Generate Snowflake names (uppercase, underscores, SQL-safe)
    sf_volume_name = volume_name or to_sql_identifier(f"{bucket}_external_volume", prefix)

    if output == "text":
        click.echo("=" * 60)
        click.echo("Snowflake External Volume Manager - Delete")
        click.echo("=" * 60)
        click.echo()
        click.echo(f"Bucket:          {aws_bucket_name}")
        click.echo(f"IAM Role:        {aws_role_name}")
        click.echo(f"IAM Policy:      {aws_policy_name}")
        click.echo(f"External Volume: {sf_volume_name}")
        click.echo()

    # Initialize AWS clients
    s3_client = boto3.client("s3", region_name=region)
    iam_client = boto3.client("iam")
    sts_client = boto3.client("sts")

    account_id = get_aws_account_id(sts_client)
    policy_arn = f"arn:aws:iam::{account_id}:policy/{aws_policy_name}"

    deleted_resources = []

    # Step 1: Drop external volume
    if output == "text":
        click.echo("─" * 40)
        click.echo("Step 1: Drop External Volume")
        click.echo("─" * 40)
    drop_external_volume(sf_volume_name)
    deleted_resources.append({"type": "external_volume", "name": sf_volume_name})
    if output == "text":
        click.echo()

    # Step 2: Delete IAM role
    if output == "text":
        click.echo("─" * 40)
        click.echo("Step 2: Delete IAM Role")
        click.echo("─" * 40)
    delete_iam_role(iam_client, aws_role_name, policy_arn)
    deleted_resources.append({"type": "iam_role", "name": aws_role_name})
    if output == "text":
        click.echo()

    # Step 3: Delete IAM policy
    if output == "text":
        click.echo("─" * 40)
        click.echo("Step 3: Delete IAM Policy")
        click.echo("─" * 40)
    delete_iam_policy(iam_client, policy_arn)
    deleted_resources.append({"type": "iam_policy", "arn": policy_arn})
    if output == "text":
        click.echo()

    # Step 4: Delete bucket (optional)
    if delete_bucket:
        if output == "text":
            click.echo("─" * 40)
            click.echo("Step 4: Delete S3 Bucket")
            click.echo("─" * 40)
        delete_s3_bucket(s3_client, aws_bucket_name, force=force)
        deleted_resources.append({"type": "s3_bucket", "name": aws_bucket_name})
        if output == "text":
            click.echo()

    if output == "json":
        click.echo(json.dumps({"status": "success", "deleted": deleted_resources}, indent=2))
    else:
        click.echo("=" * 60)
        click.echo("✓ Resources deleted successfully!")
        click.echo("=" * 60)


@cli.command()
@click.option(
    "--volume-name",
    "-v",
    envvar="EXTERNAL_VOLUME_NAME",
    required=True,
    help="Snowflake external volume name",
)
def verify(volume_name: str) -> None:
    """
    Verify an existing external volume.

    \b
    Example:
        extvolume verify --volume-name my_external_volume
    """
    click.echo("=" * 60)
    click.echo("Snowflake External Volume Manager - Verify")
    click.echo("=" * 60)
    click.echo()

    verify_external_volume(volume_name)

    click.echo()
    click.echo("=" * 60)


@cli.command()
@click.option(
    "--volume-name",
    "-v",
    envvar="EXTERNAL_VOLUME_NAME",
    required=True,
    help="Snowflake external volume name",
)
def describe(volume_name: str) -> None:
    """
    Describe an existing external volume.

    \b
    Example:
        extvolume describe --volume-name my_external_volume
    """
    click.echo("=" * 60)
    click.echo("Snowflake External Volume Manager - Describe")
    click.echo("=" * 60)
    click.echo()

    props = describe_external_volume(volume_name)

    click.echo()
    click.echo("Properties:")
    for key, value in props.items():
        click.echo(f"  {key}: {value}")

    click.echo()
    click.echo("=" * 60)


@cli.command(name="update-trust")
@click.option(
    "--bucket",
    "-b",
    envvar="BUCKET",
    default=None,
    help="S3 bucket base name (to derive role and volume names)",
)
@click.option(
    "--role-name",
    "-r",
    default=None,
    help="IAM role name to update (or derived from --bucket)",
)
@click.option(
    "--volume-name",
    "-v",
    envvar="EXTERNAL_VOLUME_NAME",
    default=None,
    help="Snowflake external volume name (or derived from --bucket)",
)
@click.pass_context
def update_trust(
    ctx: click.Context,
    bucket: str | None,
    role_name: str | None,
    volume_name: str | None,
) -> None:
    """
    Update IAM trust policy from existing external volume.

    Use this if you need to re-sync the trust policy after changes.

    \b
    Provide either --bucket (to derive names) or both --role-name and --volume-name.

    \b
    Example:
        extvolume update-trust --bucket iceberg-data
        extvolume update-trust --role-name my-role --volume-name MY_VOLUME
    """
    prefix = ctx.obj.get("prefix")

    # Determine role and volume names
    if bucket:
        aws_role_name = role_name or to_aws_name(f"{bucket}-snowflake-role", prefix)
        sf_volume_name = volume_name or to_sql_identifier(f"{bucket}_external_volume", prefix)
    elif role_name and volume_name:
        aws_role_name = role_name
        sf_volume_name = volume_name
    else:
        raise click.ClickException("Provide either --bucket or both --role-name and --volume-name")

    click.echo("=" * 60)
    click.echo("Snowflake External Volume Manager - Update Trust Policy")
    click.echo("=" * 60)
    click.echo()
    click.echo(f"IAM Role:        {aws_role_name}")
    click.echo(f"External Volume: {sf_volume_name}")
    click.echo()

    iam_client = boto3.client("iam")

    # Get Snowflake IAM user from external volume
    props = describe_external_volume(sf_volume_name)
    click.echo()

    # Update trust policy
    update_role_trust_policy(
        iam_client,
        aws_role_name,
        props["iam_user_arn"],
        props.get("external_id", ""),
    )

    click.echo()
    click.echo("=" * 60)
    click.echo("✓ Trust policy updated successfully!")
    click.echo("=" * 60)


if __name__ == "__main__":
    cli()
