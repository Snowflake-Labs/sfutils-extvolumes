# sfutils-extvolumes

Create and manage Snowflake external volumes with S3 storage for Iceberg tables, data lakes, COPY INTO unload, and external stages. Handles the full AWS + Snowflake setup: S3 bucket, IAM policy, IAM role, trust policy, and external volume.

**10+ manual steps → single command.**

## Prerequisites

- [Snowflake CLI](https://docs.snowflake.com/developer-guide/snowflake-cli/index) (`snow`) installed and configured
- AWS CLI configured (`aws configure` or environment variables)
- Python 3.12+
- [Task](https://taskfile.dev) (optional, for task-based workflow)

## Install

```bash
uv sync          # or: pip install .
```

## Quick Start

```bash
# Create everything with defaults (bucket prefixed with your username)
sfutils-extvolumes create --bucket iceberg-demo
# Creates: ksampath-iceberg-demo (S3), KSAMPATH_ICEBERG_DEMO_EXTERNAL_VOLUME (Snowflake)

# Preview without creating anything
sfutils-extvolumes create --bucket iceberg-demo --dry-run

# No username prefix
sfutils-extvolumes --no-prefix create --bucket iceberg-demo

# Custom prefix
sfutils-extvolumes --prefix myproject create --bucket data-lake

# Delete everything
sfutils-extvolumes delete --bucket iceberg-demo --delete-bucket --force

# Verify external volume connectivity
sfutils-extvolumes verify --volume-name MY_EXTERNAL_VOLUME

# Re-sync IAM trust policy
sfutils-extvolumes update-trust --bucket iceberg-demo
```

## What `create` Does

1. Creates an S3 bucket with versioning enabled
2. Creates an IAM policy for S3 access (get, put, delete, list)
3. Creates an IAM role with initial trust policy
4. Creates a Snowflake external volume pointing to the bucket
5. Retrieves Snowflake's IAM user ARN from the volume
6. Updates the IAM trust policy with the actual Snowflake principal
7. Verifies the external volume connectivity

## Task Workflow

```bash
task up                              # Quick start with defaults
task up BUCKET=my-data               # Custom bucket name
task down                            # Tear down everything

task create BUCKET=my-data
task delete BUCKET=my-data
task verify VOLUME=MY_EXTERNAL_VOLUME
task describe VOLUME=MY_EXTERNAL_VOLUME
task update-trust BUCKET=my-data
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `create` | Create S3 bucket, IAM role/policy, and Snowflake external volume |
| `delete` | Delete external volume and associated AWS resources |
| `verify` | Verify external volume connectivity |
| `describe` | Show external volume properties (IAM user ARN, external ID) |
| `update-trust` | Re-sync IAM trust policy from external volume |

## Naming Conventions

Resources are prefixed with your username by default to avoid conflicts in shared AWS accounts.

| Resource | Pattern | Example |
|----------|---------|---------|
| S3 Bucket | `{prefix}-{bucket}` | `ksampath-iceberg-demo` |
| IAM Role | `{prefix}-{bucket}-snowflake-role` | `ksampath-iceberg-demo-snowflake-role` |
| IAM Policy | `{prefix}-{bucket}-snowflake-policy` | `ksampath-iceberg-demo-snowflake-policy` |
| External Volume | `{PREFIX}_{BUCKET}_EXTERNAL_VOLUME` | `KSAMPATH_ICEBERG_DEMO_EXTERNAL_VOLUME` |

Use `--no-prefix` to disable or `--prefix NAME` for a custom prefix.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `BUCKET` | S3 bucket base name |
| `EXTERNAL_VOLUME_NAME` | Snowflake external volume name |
| `AWS_REGION` | AWS region (default: `us-west-2`) |

## After Setup

Create Iceberg tables using your external volume:

```sql
CREATE OR REPLACE ICEBERG TABLE my_table (
    id INT,
    name STRING,
    created_at TIMESTAMP_NTZ
)
CATALOG = 'SNOWFLAKE'
EXTERNAL_VOLUME = 'KSAMPATH_ICEBERG_DEMO_EXTERNAL_VOLUME'
BASE_LOCATION = 'my_table';
```

## Related

- [sf-utils-skills](https://github.com/Snowflake-Labs/sf-utils-skills) — Cortex Code skill `sf-utils-volumes` (after repo rename from `snow-utils-skills`)

## License

Apache 2.0
