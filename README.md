# tap-jira

A [Singer](https://www.singer.io/) tap that extracts data from **Jira**. It is built with [hotglue-singer-sdk](https://github.com/hotgluexyz/HotglueSingerSDK) and speaks the standard Singer message protocol on stdout, so you can pair it with any compatible target.

## Features

- **REST**-style HTTP streams (see `client.py` / `streams.py`).
- **OAuth2** with access token support via Hotglue (`access_token_support` on the tap).

- Configurable **`api_url`** and optional **`start_date`** (see [Configuration](#configuration)).
- Incremental sync is scaffolded with placeholder **`id`** (primary key) and **`modified_at`** (replication key); replace with real fields per stream in `streams.py`.

### Streams

| Stream | Endpoint / notes | Primary key | Replication key |
| ------ | ---------------- | ----------- | ----------------- |
| `project` | `GET` + `/project` (default path; TODO: confirm with API) | `id` (TODO) | `modified_at` (TODO) |

TODO: Describe pagination, rate limits, and any stream-specific query parameters in this section.

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

| Setting | Type | Required | Default | Description |
| ------- | ---- | -------- | ------- | ----------- |
| `start_date` | string (datetime) | no | `2000-01-01T00:00:00Z` | Earliest record date to sync. |
| `api_url` | string | no | `https://api.atlassian.com` | Base URL for the API. |
| `client_id` | string | yes | — | OAuth client ID. |
| `client_secret` | string | yes | — | OAuth client secret. |
| `refresh_token` | string | no | — | OAuth refresh token (if applicable). |

Run `tap-jira --about` (or `tap-jira --about --format=markdown`) for the authoritative schema for your installed version.

### Example `config.json`

```json
{
  "start_date": "2000-01-01T00:00:00Z",
  "api_url": "https://api.atlassian.com",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "refresh_token": ""
}
```

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

TODO: Add your vendor’s base URLs, auth docs, and links (compare to the “API hosts” section in a finished tap README).


## License
See repository files; add a `LICENSE` if you distribute this package.
