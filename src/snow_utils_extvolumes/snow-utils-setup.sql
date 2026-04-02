-- Copyright 2026 Snowflake Inc.
-- Generated with Cortex Code
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

--!jinja

-- =============================================================================
-- Snow-Utils Setup Script
-- =============================================================================
-- Creates the shared database and schemas for snow-utils skills.
-- Role creation is handled by individual skills (e.g., PAT skill creates
-- demo-specific roles like {PROJECT}_ACCESS).
--
-- Environment Variables (from .env):
--   SNOW_UTILS_DB  - Name of the database to create
--   SA_ADMIN_ROLE  - Admin role to run setup (default: ACCOUNTADMIN)
--
-- What this creates:
--   - SNOW_UTILS_DB database
--   - SNOW_UTILS_DB.NETWORKS schema (for network rules)
--   - SNOW_UTILS_DB.POLICIES schema (for auth policies)
--
-- What skills create (not this script):
--   - SA_ROLE ({PROJECT}_ACCESS) - consumer role
--   - SA_USER ({PROJECT}_RUNNER) - service user
--   - Network rules, policies, PATs
--
-- Prerequisites:
--   - Must be run by SA_ADMIN_ROLE (default: ACCOUNTADMIN)
--
-- Usage:
--   snow sql -f snow-utils-setup.sql --enable-templating ALL --role <SA_ADMIN_ROLE>
-- =============================================================================

USE ROLE <% ctx.env.get('SA_ADMIN_ROLE', 'ACCOUNTADMIN') %>;

-- =============================================================================
-- Step 1: Create Database and Schemas
-- =============================================================================

CREATE DATABASE IF NOT EXISTS <% ctx.env.SNOW_UTILS_DB %>
    COMMENT = 'Shared database for snow-utils skills (network rules, policies, etc.)';

CREATE SCHEMA IF NOT EXISTS <% ctx.env.SNOW_UTILS_DB %>.NETWORKS
    COMMENT = 'Schema for network rules';
CREATE SCHEMA IF NOT EXISTS <% ctx.env.SNOW_UTILS_DB %>.POLICIES
    COMMENT = 'Schema for authentication policies';

-- =============================================================================
-- Verification
-- =============================================================================

SELECT 'Snow-utils database setup complete: <% ctx.env.SNOW_UTILS_DB %>' AS status;
