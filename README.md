# Garage Admin Panel

[![CI](https://github.com/jr551/garage-admin-panel/actions/workflows/ci.yml/badge.svg)](https://github.com/jr551/garage-admin-panel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A small, dependency-free, authenticated web control panel for
[Garage](https://garagehq.deuxfleurs.fr) S3 deployments. It combines Garage's
admin API with optional S3 reporting, browser, Restic, and Cloudflared
operations in one deliberately conservative interface.

## What it does

- Shows bucket counts, logical sizes, compact usage widgets, and the latest
  object with a freshness indicator.
- Provides copyable path-style public URLs and persistent friendly bucket
  names; the underlying Garage name remains visible on hover.
- Archives buckets only after an exact-name confirmation, hides them
  immediately, and purges them after a configurable recovery window.
- Re-authenticates before showing or deleting S3 keys; key deletion requires
  the exact access-key ID.
- Lets operators grant a Garage account access to a bucket with selectors and
  inline status, and automatically grants configured reporting keys to new
  buckets when enabled.
- Includes an authenticated bucket browser with bounded upload, download,
  rename, and delete operations when a separate read/write S3 key is supplied.
- Offers optional Cloudflared status/update controls and Restic repository
  detection with manual health checks.
- Keeps separate sign-in audit and operator activity logs.

## Quick start

Install the package with Python 3.11 or newer:

```bash
python -m pip install garage-admin-panel
```

Set the minimum required configuration, then start the panel:

```bash
export GARAGE_ADMIN_URL=http://127.0.0.1:3903
export GARAGE_ADMIN_TOKEN='<Garage admin token>'
export PANEL_PASSWORD='<long unique password>'
garage-admin-panel
```

It listens on `127.0.0.1:8088` by default. Put it behind a private reverse
proxy, VPN, or other authenticated administrative network; do not expose it
directly to the public internet.

For a source checkout without packaging, run:

```bash
python garage_panel.py
```

## Configuration

Store configuration in a root-readable environment file (mode `0600`) when
using a service manager. Do not commit it.

```dotenv
GARAGE_ADMIN_URL=http://127.0.0.1:3903
GARAGE_ADMIN_TOKEN=<Garage admin token>
PANEL_USER=admin
PANEL_PASSWORD=<long unique password>
PANEL_HOST=127.0.0.1
PANEL_PORT=8088

# 180 days by default. Set a stable secret for sessions that survive restarts.
PANEL_SESSION_HOURS=4320
PANEL_SESSION_SECRET=<random value>

# Optional reporting: enables latest-object and backup-age data.
S3_ENDPOINT=http://127.0.0.1:3900
S3_REGION=us-east-1
S3_ACCESS_KEY=<read-capable key>
S3_SECRET_KEY=<secret>
BACKUP_BUCKETS=
BACKUP_MAX_OBJECTS=5000
PANEL_LATEST_OBJECTS=5

# Optional browser mutations: use a distinct read/write key.
S3_BROWSER_ACCESS_KEY=<read-write key>
S3_BROWSER_SECRET_KEY=<secret>
PANEL_BROWSER_MAX_OBJECTS=500
PANEL_BROWSER_UPLOAD_MAX_BYTES=52428800

# Optional path-style public links, for example https://s3.example/<bucket>.
S3_PUBLIC_ENDPOINT=https://s3.example

# Optional safe bucket archival.
PANEL_BUCKET_ARCHIVE_DAYS=60
PANEL_AUTO_GRANT_READ=1

# Optional integrations; both are off unless explicitly enabled.
PANEL_CLOUDFLARED_ENABLED=0
PANEL_RESTIC_ENABLED=0
```

`S3_ACCESS_KEY` should normally be read-only. The browser never uses that key
for mutations: it requires the separate browser key. A bucket that lacks read
access for the reporting key still appears in Garage accounting, but its
latest-file and Restic details will explain the missing grant instead of
rendering a raw S3 error.

See the environment-variable comments near the top of
[`garage_panel.py`](garage_panel.py) for all optional paths, timeouts, and
integration settings.

## Run as a service

The included [`garage-panel.service`](garage-panel.service) is a hardened
systemd unit for a source installation at `/opt/garage-panel`. It expects
`/etc/garage-panel.env` and writes runtime state under `/var/lib/garage-panel`.

```bash
install -D -m 0755 garage_panel.py /opt/garage-panel/garage_panel.py
install -d -m 0755 /opt/garage-panel/static
install -m 0644 static/* /opt/garage-panel/static/
install -m 0644 garage-panel.service /etc/systemd/system/
install -d -m 0700 /var/lib/garage-panel
chmod 0600 /etc/garage-panel.env
systemctl daemon-reload
systemctl enable --now garage-panel.service
```

If Cloudflared updates are enabled, install
[`garage-cloudflared-update.service`](garage-cloudflared-update.service) as a
separate, least-privilege helper. Review its paths and permissions for the host
before enabling it.

## Safety model

- The panel refuses to start without both `GARAGE_ADMIN_TOKEN` and
  `PANEL_PASSWORD`.
- Sessions are HMAC-signed, `HttpOnly`, and `SameSite=Strict`; the password is
  not stored in the cookie.
- Viewing secrets requires the password again. The encrypted local secret store
  is only a fallback for legacy Garage keys that cannot be revealed by Garage.
- Bucket archival and key deletion require manually typed exact identifiers.
  Archived bucket data remains untouched during the recovery window.
- Restic and Cloudflared operations are disabled by default. Saved Restic
  passwords are encrypted using a key derived from `PANEL_PASSWORD` and are
  never returned through the API.
- The activity log records mutations separately from sign-in attempts.

## Storage placement

Garage separates metadata from object data, but its supported multi-directory
layout balances data blocks across configured directories. It does not provide
a safe per-bucket or per-repository HDD/SSD selector. For hard placement
boundaries, use separate Garage instances or endpoints; do not manually move
Garage-managed files. Consult Garage's [configuration
reference](https://garagehq.deuxfleurs.fr/documentation/reference-manual/configuration/)
and [multi-drive guidance](https://garagehq.deuxfleurs.fr/documentation/operations/multi-hdd/)
before changing a live storage layout.

## API

Signed-in users can open interactive API documentation at `/docs`; the
OpenAPI document is available at `/openapi.json`. Automation can use a panel
API key instead of a browser session:

```bash
curl -H 'Authorization: Bearer gp_...' http://127.0.0.1:8088/api/overview
```

Only a hash of an API key is stored. Revoke and replace a lost key; it cannot
be recovered.

## Development and release artifacts

The project has no runtime Python dependencies. Validate a checkout with:

```bash
python -m py_compile garage_panel.py
python -m pip install --upgrade build
python -m build
```

CI builds both a source distribution and a wheel, installs the wheel, and
checks the embedded dashboard JavaScript. Release artifacts are attached to
the corresponding GitHub release. Publishing to PyPI is intentionally not
automated.

## Attribution

The 2.2.0 dashboard redesign, session persistence, version checker, and OCI
images were built by **ox-alpha**, a free model available on
[OpenRouter](https://openrouter.ai/), under human direction.

## Security and contributing

Please report vulnerabilities under the process in [SECURITY.md](SECURITY.md).
Contribution guidance is in [CONTRIBUTING.md](CONTRIBUTING.md). The project is
released under the [MIT License](LICENSE).
