# tap-jira

A [Singer](https://www.singer.io/) tap that extracts data from **Jira**. It is built with [hotglue-singer-sdk](https://github.com/hotgluexyz/HotglueSingerSDK) and speaks the standard Singer message protocol on stdout, so you can pair it with any compatible target.

## Features

- **REST**-style HTTP streams (see `client.py` / `streams.py`).
- **OAuth2** with access token support via Hotglue (`access_token_support` on the tap).

- **Basic Auth** for Jira Server / Data Center, selected automatically when no `client_id` is configured.
- Configurable **`api_url`** and **`start_date`** (see [Configuration](#configuration)).
- Incremental replication on `issues` and `worklogs`; all other streams are full-table.

### Streams

| Stream | Endpoint | Primary key | Replication |
| ------ | -------- | ----------- | ----------- |
| `projects` | `GET /rest/api/2/project` | `id` | full table |
| `versions` | `GET /rest/api/2/project/{project_id}/version` | `id` | full table (child of `projects`) |
| `components` | `GET /rest/api/2/project/{project_id}/component` | `id` | full table (child of `projects`) |
| `project_types` | `GET /rest/api/2/project/type` | `key` | full table |
| `project_categories` | `GET /rest/api/2/projectCategory` | `id` | full table |
| `issue_types` | `GET /rest/api/2/issuetype` | `id` | full table |
| `resolutions` | `GET /rest/api/2/resolution` | `id` | full table |
| `roles` | `GET /rest/api/2/role` | `id` | full table |
| `users` | `GET /rest/api/2/users/search` | `accountId` | full table |
| `statuses` | `GET /rest/api/2/statuses/search` | `id` | full table |
| `issue_priorities` | `GET /rest/api/2/priority/search` | `id` | full table |
| `issues` | `GET /rest/api/3/search/jql` | `id` | incremental on `fields.updated` |
| `issue_comments` | embedded in `issues` | `id` | emitted with `issues` |
| `changelogs` | embedded in `issues` | `id` | emitted with `issues` |
| `issue_transitions` | embedded in `issues` | `id` | emitted with `issues` |
| `worklogs` | `GET /rest/api/2/worklog/updated` + `POST /rest/api/2/worklog/list` | `id` | incremental on `updated` |

Schemas live in `tap_jira/schemas/` and are carried over unchanged from the pre-SDK tap.

**Stream dependencies.** `issue_comments`, `changelogs`, and `issue_transitions` are written directly by the `issues` sync rather than fetched on their own, so they require `issues` to be selected

**Sub-streams cost no extra requests.** A single pass over `/rest/api/3/search/jql` (with
`expand=changelog,transitions`) yields comments, changelogs, and transitions, which are emitted to their own
streams rather than re-fetched per issue.


**OAuth scopes.** `roles`, `users`, `statuses`, and `issue_priorities` need `read:jira-user` and the granular
status/priority scopes. When the token lacks a scope, that stream is skipped with a warning instead of
failing the run.

## Requirements

- Python **3.10+** (see `requires-python` in `pyproject.toml`).

## Installation

1. **Clone** this repository and `cd` into the project directory.
2. **Create `config.json`** in the project root with your credentials and settings (see [Configuration](#configuration) for the fields and an example).
3. **Create a virtual environment** and activate it:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows, use `.venv\Scripts\activate` instead of `source .venv/bin/activate`.

4. **Install the package** in editable mode:

```bash
pip install -e .
```

5. **Run the tap** (with the venv still activated):

```bash
tap-jira --help
```

## Configuration

The tap supports two authentication modes and picks one automatically: **OAuth** when `client_id` is set to a
non-empty value, otherwise **Basic Auth**.

| Setting | Type | Sensitive | Required | Default | Description |
| ------- | ---- | --------- | -------- | ------- | ----------- |
| `start_date` | datetime | no | no | `2000-01-01T00:00:00Z` | Earliest record date to sync. |
| `api_url` | string | no | no | `https://api.atlassian.com` | Atlassian API root. OAuth only. |
| `user_agent` | string | no | no | — | Sent as the `User-Agent` header. |
| **OAuth** | | | | | |
| `client_id` | string | **yes** | for OAuth | — | Presence of a non-empty value selects OAuth. |
| `client_secret` | string | **yes** | for OAuth | — | OAuth client secret. |
| `refresh_token` | string | **yes** | for OAuth | — | Rotated by Atlassian and written back on each refresh. |
| `access_token` | string | **yes** | no | — | Written back by the tap; refreshed automatically. |
| `expires_in` | integer | no | no | — | Absolute epoch expiry, written back by the tap. |
| `site_name` | string | no | no | first accessible site | Jira site to sync. |
| `cloud_id` | string | no | no | resolved from `site_name` | Skips the site lookup when set. |
| **Basic Auth** | | | | | |
| `username` | string | no | for Basic Auth | — | Jira username or account email. |
| `password` | string | **yes** | for Basic Auth | — | Password or API token. |
| `base_url` | string | no | for Basic Auth | — | e.g. `https://mycompany.atlassian.net`. |

Settings marked sensitive must never be committed. Keep them in `.secrets/config.json` (gitignored) or a
secrets manager.

Run `tap-jira --about` (or `--about --format=markdown`) for the authoritative schema for your installed version.

### Example `config.json` — OAuth

```json
{
  "start_date": "2000-01-01T00:00:00Z",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "refresh_token": "YOUR_REFRESH_TOKEN"
}
```

### Example `config.json` — Basic Auth

```json
{
  "start_date": "2000-01-01T00:00:00Z",
  "username": "you@example.com",
  "password": "YOUR_API_TOKEN",
  "base_url": "https://mycompany.atlassian.net"
}
```

### Hotglue access token endpoint

For OAuth connectors the tap can fetch tokens from Hotglue instead of refreshing against Atlassian. Set
`"_refresh_token_via_hg_api": true` in the config and provide the `TENANT`, `API_KEY`, `FLOW`, `ENV_ID`, and
`TAP` environment variables. `tap-jira --config config.json --access-token` refreshes the token and writes it
back to the config file.

Do not commit real credentials. Prefer environment variables or a secrets manager in production.

### Environment-based config

You can load settings from the process environment using `--config=ENV` (the SDK merges env into config). Env names follow the tap’s setting keys (see `tap-jira --about`).

## Usage

With your virtual environment **activated** and `config.json` in place:

Discover stream catalog:

```bash
tap-jira --config config.json --discover > catalog.json
```

Run a sync (with optional state):

```bash
tap-jira --config config.json --catalog catalog.json --state state.json
```

Pipe to any Singer target:

```bash
tap-jira --config config.json --catalog catalog.json | target-jsonl
```

Inspect built-in settings and stream metadata:

```bash
tap-jira --about
```

## API / documentation

| Host | Role |
| ---- | ---- |
| `https://auth.atlassian.com/oauth/token` | OAuth token endpoint (refresh) |
| `https://api.atlassian.com/oauth/token/accessible-resources` | Site / cloud id lookup |
| `https://api.atlassian.com/ex/jira/{cloudId}` | Jira REST API under OAuth |
| `https://<your-site>` (`base_url`) | Jira REST API under Basic Auth |

- [Jira Cloud REST API](https://developer.atlassian.com/cloud/jira/platform/rest/v3/)
- [Atlassian OAuth 2.0 (3LO)](https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/)


## License
See repository files; add a `LICENSE` if you distribute this package.
