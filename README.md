# OIN Migration

A local Flask web tool for migrating Okta applications to their OIN (Okta Integration Network) catalog equivalents. Identifies candidates, drives the conversion via the Okta API, and tracks per-app progress.

## Overview

Custom Okta SAML/OIDC apps that mirror well-known SaaS products often exist in the OIN catalog with vendor-blessed configuration. Migrating from a custom app to its OIN equivalent improves long-term maintenance (vendor handles config drift, certificate rotation prompts, etc.) but requires careful handling of metadata, group assignments, and policy mappings.

This tool:

1. Inventories candidate apps in the source environment
2. Matches each against the OIN catalog
3. Produces a planned conversion with side-by-side config diff
4. Executes the migration via Okta API on approval
5. Logs every action for audit + rollback

## Features

* **Catalog matching** — surface OIN candidates per source app
* **Per-app override database** — `oin-overrides.db` lets the user pin specific custom-to-OIN mappings that aren't auto-detected
* **Action logging** — every API mutation timestamped in `oin-actions.log`
* **Status awareness** — pre-filters by app activation state (Okta API rejects visibility/policy/routing mutations against deactivated apps)
* **No external database** — local SQLite for the override store; everything else stateless

## Technical Stack

* **Backend:** Python 3, Flask
* **Persistence:** SQLite (`oin-overrides.db`) for user-pinned mappings; flat log file for actions
* **Okta integration:** REST API
* **Frontend:** Jinja2 templates

## Running

```bash
python app.py
```

Default port: `5003`. Open `http://localhost:5003` to access the dashboard.

## Configuration

Tokens follow the same OS-keyring + `.env` fallback pattern as the other tools in this monorepo. See companion projects for the keyring service-name convention.
