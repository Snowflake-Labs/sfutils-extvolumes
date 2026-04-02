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
"""Pre-flight check for snow-utils shared infrastructure (database + schemas).

Checks whether the SNOW_UTILS_DB database exists (via Snowflake CLI). Does not
validate SA_ROLE or other skill-specific objects.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import click

DEFAULT_DB = "SNOW_UTILS"


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


def run_sql(query: str) -> list | None:
    """Execute SQL and return parsed JSON result. Uses active connection from env."""
    cmd = ["snow", "sql", "--query", query, "--format", "json"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None

    if result.stdout.strip():
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
    return None


def check_database_exists(db_name: str) -> bool:
    """Check if a database exists."""
    try:
        result = run_sql(f"SHOW DATABASES LIKE '{db_name}'")
        return result is not None and len(result) > 0
    except Exception:
        return False


def do_run_setup(db_name: str, script_dir: Path) -> bool:
    """Run the setup script with ACCOUNTADMIN."""
    setup_sql = script_dir / "snow-utils-setup.sql"
    if not setup_sql.exists():
        click.echo(click.style(f"Setup script not found: {setup_sql}", fg="red"))
        return False

    click.echo("\nRunning setup with ACCOUNTADMIN...")
    click.echo(f"  SNOW_UTILS_DB: {db_name}")
    click.echo()

    env = os.environ.copy()
    env["SNOW_UTILS_DB"] = db_name

    cmd = [
        "snow",
        "sql",
        "-f",
        str(setup_sql),
        "--enable-templating",
        "ALL",
        "--role",
        "ACCOUNTADMIN",
    ]

    result = subprocess.run(cmd, env=env, capture_output=False)

    if result.returncode == 0:
        click.echo(click.style("\n✓ Setup complete!", fg="green"))
        return True
    else:
        click.echo(click.style("\n✗ Setup failed", fg="red"))
        return False


@click.command()
@click.option("--database", "-d", help="Database name (or set SNOW_UTILS_DB env var)")
@click.option("--run-setup", is_flag=True, help="Run setup if infrastructure missing")
@click.option("--suggest", is_flag=True, help="Output suggested defaults as JSON")
def check(database: str | None, run_setup: bool, suggest: bool):
    """Check if snow-utils infrastructure is set up.

    Non-interactive - all values via CLI args or env vars.
    Designed to be called by Cortex Code skills.

    Exit codes:
      0 - Infrastructure ready
      1 - Infrastructure missing (setup not requested or failed)
      2 - Error during check (e.g. snow CLI missing)
    """
    script_dir = Path(__file__).resolve().parent

    require_snow_cli()

    user = os.environ.get("SNOWFLAKE_USER", "").upper()
    default_db = f"{user}_SNOW_UTILS" if user else DEFAULT_DB

    if suggest:
        db_to_check = database or os.environ.get("SNOW_UTILS_DB") or default_db
        db_exists = check_database_exists(db_to_check)
        click.echo(
            json.dumps(
                {
                    "user": user or None,
                    "suggested_database": default_db,
                    "database_exists": db_exists,
                    "ready": db_exists,
                }
            )
        )
        sys.exit(0)

    db_name = database or os.environ.get("SNOW_UTILS_DB") or default_db

    ver_result = subprocess.run(["snow", "--version"], capture_output=True, text=True)
    snow_version = ver_result.stdout.strip() if ver_result.returncode == 0 else "unknown"
    click.echo(f"Using {snow_version}")

    click.echo("Snow-utils infrastructure check\n")
    if user:
        click.echo(f"Detected user: {user}")
    click.echo(f"  SNOW_UTILS_DB: {db_name}\n")

    db_exists = check_database_exists(db_name)

    if db_exists:
        click.echo(click.style("✓ Infrastructure ready", fg="green"))
        click.echo(f"  Database: {db_name}")
        click.echo(f"  Schemas: {db_name}.NETWORKS, {db_name}.POLICIES")
        sys.exit(0)

    click.echo(click.style("⚠ Infrastructure not ready", fg="yellow"))
    click.echo(f"  ✗ Database {db_name} does not exist")

    if not run_setup:
        click.echo("\nTo create infrastructure, re-run with --run-setup")
        sys.exit(1)

    click.echo("\nRunning setup...")
    click.echo(f"  - Database: {db_name}")
    click.echo(f"  - Schemas: {db_name}.NETWORKS, {db_name}.POLICIES")

    success = do_run_setup(db_name, script_dir)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    check()
