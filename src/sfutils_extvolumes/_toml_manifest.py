"""TOML manifest helpers for sfutils-extvolumes multi-volume support.

Reads .sfutils/manifest.toml using stdlib tomllib (Python 3.11+, read-only).
Writes using a hand-rolled serializer scoped to the manifest schema — no
external dependencies required.

Schema:

    schema_version = "1"
    project_name   = "my-project"
    created_at     = "2026-05-02T10:00:00Z"

    [snowflake]
    connection   = "local-oauth"   # default connection for all volumes
    account      = "ABC12345"      # cached from snow connection test
    user         = "KAMESHS"
    account_url  = "https://abc12345.snowflakecomputing.com"
    admin_role   = "ACCOUNTADMIN"
    # NOTE: no sf_utils_db — external volumes are account-level Snowflake objects;
    # no database or schema objects are created or cleaned up.

    [prereqs]
    tools_verified = "2026-05-02"

    [volume.my-s3-volume]        # label = volume_name.lower().replace("_", "-")
    status               = "COMPLETE"
    volume_name          = "MY_S3_VOLUME"
    ...

    [volume.my-s3-volume.cleanup]
    volume_name = "MY_S3_VOLUME"
    # no db — cleanup is S3 + IAM + DROP EXTERNAL VOLUME only

# CSP auth selector per provider — stored per-volume, not in root [snowflake]:
#   S3:    aws_profile           → boto3 Session(profile_name=...) / aws --profile
#   Azure: azure_subscription_id → az --subscription (future)
#   GCS:   gcloud_config         → gcloud --configuration (future)
"""

from __future__ import annotations

import contextlib
import datetime
import os
import tomllib
from pathlib import Path

MANIFEST_PATH = ".sfutils/manifest.toml"
SCHEMA_VERSION = "1"

# Ordered field lists drive the serializer — order is preserved in output.
# Note: no "label" — the label is the TOML key, not a field inside the table.
_VOLUME_SCALAR_KEYS = [
    "status",
    "created_at",
    "updated_at",
    "removed_at",
    "volume_name",
    "storage_type",
    "bucket_url",
    "aws_region",
    "aws_profile",
    "storage_aws_role_arn",
    "external_id",
    "azure_tenant_id",
    "admin_role",
]

_SNOWFLAKE_KEYS = [
    "connection",
    "account",
    "user",
    "account_url",
    "admin_role",
    # no sf_utils_db — not needed for account-level external volume objects
]

_PREREQS_KEYS = [
    "tools_verified",
    # no infra_ready — external volumes are account-level objects; no database setup needed
]

_ROOT_KEYS = [
    "schema_version",
    "project_name",
    "created_at",
]

# Canonical status aliases — DELETED is treated as REMOVED
_STATUS_ALIASES: dict[str, str] = {"DELETED": "REMOVED"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today_iso() -> str:
    return datetime.date.today().isoformat()


def _escape_str(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _toml_value(v: object) -> str:
    """Serialize a Python value to a TOML literal string."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        items = ", ".join(f'"{_escape_str(str(i))}"' for i in v)
        return f"[{items}]"
    if isinstance(v, str):
        return f'"{_escape_str(v)}"'
    # Fallback — should not happen with our fixed schema
    return f'"{_escape_str(str(v))}"'


def _section_comment(title: str, width: int = 78) -> str:
    """Return a TOML comment line: '# ── {title} ──...──'."""
    fill = "─" * max(2, width - len(title) - 5)
    return f"# ── {title} {fill}"


def _write_table(section: dict, ordered_keys: list[str]) -> list[str]:
    """Serialize a flat dict in key-declaration order, then remaining keys."""
    lines: list[str] = []
    emitted: set[str] = set()
    for key in ordered_keys:
        if key in section:
            lines.append(f"{key:<20} = {_toml_value(section[key])}")
            emitted.add(key)
    for key, val in section.items():
        if key not in emitted:
            lines.append(f"{key:<20} = {_toml_value(val)}")
    return lines


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def ensure_manifest_defaults(data: dict, manifest_path: Path | str = MANIFEST_PATH) -> None:
    """Ensure *data* has all required top-level sections with sensible defaults.

    Called before writing a volume entry so the manifest is always well-formed,
    even when the prereqs init block was skipped.  Mutates *data* in place.

    Connection is NOT auto-filled here — that is the skill's responsibility
    (interactive picker at Step 1).  If SNOWFLAKE_DEFAULT_CONNECTION_NAME is
    already set in the environment, it is used as a silent fallback so CI/CD
    environments that export it don't need interactive prompting.
    """
    if "schema_version" not in data:
        data["schema_version"] = SCHEMA_VERSION
    if "project_name" not in data:
        # Derive from the project directory (parent of the .sfutils/ dir).
        data["project_name"] = Path(manifest_path).resolve().parent.parent.name
    if "created_at" not in data:
        data["created_at"] = _now_iso()

    if "snowflake" not in data:
        data["snowflake"] = {}
    sf = data["snowflake"]
    if not sf.get("connection"):
        sf["connection"] = os.environ.get("SNOWFLAKE_DEFAULT_CONNECTION_NAME", "")
    sf.setdefault("admin_role", "ACCOUNTADMIN")

    if "prereqs" not in data:
        data["prereqs"] = {"tools_verified": _today_iso()}
    data.setdefault("volume", {})


def load_manifest(path: Path | str = MANIFEST_PATH) -> dict:
    """Read manifest.toml.  Returns empty dict if the file is missing or
    cannot be parsed (tolerant — caller should not crash on missing manifest).
    """
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with p.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError:
        return {}


def save_manifest(path: Path | str, data: dict) -> None:
    """Write *data* to *path* as TOML.

    Creates the parent directory with mode 700 if needed.
    Sets the file mode to 600 after writing.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(p.parent, 0o700)

    lines: list[str] = ["# Machine-managed by Cortex Code. Do not hand-edit."]

    # Root-level scalars
    for key in _ROOT_KEYS:
        if key in data:
            lines.append(f"{key:<14} = {_toml_value(data[key])}")
    # Any extra root scalars not in the ordered list
    for key, val in data.items():
        if key not in _ROOT_KEYS and not isinstance(val, (dict, list)):
            lines.append(f"{key:<14} = {_toml_value(val)}")

    # [snowflake]
    if "snowflake" in data:
        _sc = _section_comment("Shared Snowflake connection (captured once, reused by all volumes)")
        lines += ["", _sc, "[snowflake]"]
        lines += _write_table(data["snowflake"], _SNOWFLAKE_KEYS)

    # [prereqs]
    if "prereqs" in data:
        lines += ["", _section_comment("Tool / infra pre-flight cache")]
        lines += ["[prereqs]"]
        lines += _write_table(data["prereqs"], _PREREQS_KEYS)

    # [volume.<label>] named tables — label is the TOML key, not a field
    for label, vol in data.get("volume", {}).items():
        lines += ["", _section_comment(f"Volume: {label}")]
        lines += [f"[volume.{label}]"]
        # Scalar fields in declared order
        emitted: set[str] = set()
        for key in _VOLUME_SCALAR_KEYS:
            if key in vol:
                lines.append(f"{key:<20} = {_toml_value(vol[key])}")
                emitted.add(key)
        for key, val in vol.items():
            if key not in emitted and not isinstance(val, dict):
                lines.append(f"{key:<20} = {_toml_value(val)}")

        # [volume.<label>.cleanup] subtable
        if "cleanup" in vol:
            lines += ["", f"[volume.{label}.cleanup]"]
            for k, v in vol["cleanup"].items():
                lines.append(f"{k:<20} = {_toml_value(v)}")

    content = "\n".join(lines) + "\n"
    p.write_text(content, encoding="utf-8")
    with contextlib.suppress(OSError):
        os.chmod(p, 0o600)


def get_volume_entry(
    data: dict,
    *,
    volume_name: str | None = None,
    label: str | None = None,
) -> dict | None:
    """Return the volume entry for *label* (O(1)) or the first entry matching
    *volume_name* (linear scan).  Returns None if not found.
    """
    volumes = data.get("volume", {})
    if label:
        return volumes.get(label)
    if volume_name:
        for entry in volumes.values():
            if entry.get("volume_name", "").upper() == volume_name.upper():
                return entry
    return None


def upsert_volume(data: dict, label: str, vol_config: dict) -> None:
    """Add or replace the volume entry for *label*.

    The label is the TOML key — it must not appear as a field inside
    *vol_config*.  Mutates *data* in place; caller must call save_manifest().
    """
    data.setdefault("volume", {})[label] = vol_config


def update_resource_status(data: dict, volume_name: str, status: str) -> None:
    """Set *status* on the volume entry matching *volume_name*.

    Sets *removed_at* when status is REMOVED (or its alias DELETED).
    Sets *updated_at* on every call.
    Mutates *data* in place — caller must call save_manifest() afterwards.
    """
    status = _STATUS_ALIASES.get(status.upper(), status.upper())
    now = _now_iso()
    for entry in data.get("volume", {}).values():
        if entry.get("volume_name", "").upper() == volume_name.upper():
            entry["status"] = status
            entry["updated_at"] = now
            if status == "REMOVED":
                entry["removed_at"] = now
            return


def validate_manifest(data: dict) -> list[str]:
    """Validate *data* against the expected manifest schema.

    Returns a list of human-readable error/warning strings.
    An empty list means the manifest is valid.
    """
    issues: list[str] = []

    # Root-level required fields
    for field in ("schema_version", "project_name", "created_at"):
        if not data.get(field):
            issues.append(f"missing root field: {field}")

    # [snowflake] section
    if "snowflake" not in data:
        issues.append("missing section: [snowflake]")
    else:
        sf = data["snowflake"]
        if not sf.get("connection"):
            issues.append("[snowflake].connection is empty — run 'vol setup-connection'")

    # [prereqs] section
    if "prereqs" not in data:
        issues.append("missing section: [prereqs]")
    else:
        prereqs = data["prereqs"]
        if not prereqs.get("tools_verified"):
            issues.append("[prereqs].tools_verified is empty — run 'vol check-setup'")

    # [volume.*] entries
    for label, vol in data.get("volume", {}).items():
        prefix = f"[volume.{label}]"
        for field in ("status", "volume_name", "storage_type"):
            if not vol.get(field):
                issues.append(f"{prefix} missing required field: {field}")
        valid_statuses = {"CREATE_IN_PROGRESS", "DELETE_IN_PROGRESS", "COMPLETE", "REMOVED", "DELETED"}
        if vol.get("status") and vol["status"] not in valid_statuses:
            issues.append(
                f"{prefix} invalid status '{vol['status']}' "
                f"(expected: {', '.join(sorted(valid_statuses))})"
            )
        cleanup = vol.get("cleanup", {})
        if not cleanup.get("volume_name"):
            issues.append(f"{prefix} [cleanup].volume_name is empty")

    return issues


# ---------------------------------------------------------------------------
# Resolution helpers (volume entry → root [snowflake] → env var)
# Note: no sf_utils_db resolver — external volumes are account-level objects.
# ---------------------------------------------------------------------------


def resolve_volume_connection(vol_entry: dict, manifest: dict) -> str | None:
    """Effective connection name: volume override → root snowflake → env var."""
    return (
        vol_entry.get("connection")
        or manifest.get("snowflake", {}).get("connection")
        or os.environ.get("SNOWFLAKE_DEFAULT_CONNECTION_NAME")
        or None
    )


def resolve_volume_admin_role(vol_entry: dict, manifest: dict) -> str:
    """Effective admin role: volume override → root snowflake → env var → ACCOUNTADMIN."""
    return (
        vol_entry.get("admin_role")
        or manifest.get("snowflake", {}).get("admin_role")
        or os.environ.get("SA_ROLE")
        or "ACCOUNTADMIN"
    )
