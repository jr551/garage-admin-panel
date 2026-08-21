# Changelog

## 2.2.1 — 2026-08-21

### Fixed: Access keys always visible, API keys table clearer

- The Access keys table now lists every Garage key (name, access key ID,
  created date) immediately on load instead of showing a single
  "Keys hidden." placeholder row.
- Secrets stay masked behind a re-entry of the panel password; "View keys"
  reveals them, "Hide keys" masks them again. Keys without a recoverable
  secret are labelled for rotation as before.
- The grant-access account selector and the API keys empty state were made
  clearer ("No API keys yet — create one above.").
- Repaired a broken `try`/`catch` in the dashboard's refresh cycle that
  could leave tables blank when any render step failed.

Validated against a live install serving 14 Garage keys.

## 2.2.0 — 2026-08-21

### New layout, sessions that last, and OCI images

- Complete layout remake: a fixed sidebar navigation (Overview, Buckets,
  Access keys, API keys, Nodes & versions, Activity) replaces the single
  long page; the active view is reflected in the URL hash. Collapses to a
  top nav bar on small screens.
- "Remember me" on the sign-in form extends the session to 30 days
  (`PANEL_REMEMBER_ME_DAYS`, 0 disables it).
- The session secret is now persisted (`PANEL_SESSION_SECRET_FILE`,
  `/var/lib/garage-panel/session-secret` by default), so signing in once
  keeps working across panel restarts instead of silently signing out.
- New "Garage version" card: shows the running release from the cluster
  status and checks the newest upstream tag every six hours, with an
  update-available indicator.
- Official OCI images published to GHCR on every release: a ~50 MB Alpine
  `garage-admin-panel` image for existing clusters, and a bundled
  `-garage` variant that runs Garage itself plus the panel in one
  container with a randomized RPC secret and a single `/data` volume.
- `/api/overview` degrades per-section: a bucket listing failure no longer
  blanks the whole dashboard.
- Fixed a crash when a Garage node has no assigned layout role yet.

Dashboard layout, sign-in flow, and images were tested end to end against
a mock Garage/S3 backend in headless Chromium.

### Attribution

This release was produced by **ox-alpha**, a free model available on
[OpenRouter](https://openrouter.ai/), working under human direction.

## 2.1.0 — 2026-08-21

### Interface overhaul

- Redesigned the dashboard with a token-based stylesheet: consistent color,
  spacing, and radius variables; refined typography and table styling; hover
  states, focus rings, and disabled affordances on every control.
- Moved the header into a sticky top bar with a product mark, live
  "refreshed" timestamp, and quick links to API docs and sign-out.
- Reordered sections by operator workflow: buckets and the browser first,
  then keys, grants, connection settings, and audit logs.
- Restyled the sign-in page to match the panel's visual language.
- Added an inline SVG favicon and theme color; removed inline style
  attributes from section markup.
- Tightened copy across panels: shorter explanations, consistent ellipsis
  convention for actions that open confirmation flows, "Actions" column
  headers, and spellcheck-off on identifier inputs.
- Fixed horizontal page overflow on narrow viewports; wide tables now scroll
  inside their own containers at every width.

## 2.0.0 — 2026-08-02

### Public release

- Established a clean public baseline with dependency-free Python packaging,
  an installable console command, release artifacts, and GitHub Actions CI.
- Documented secure deployment, configuration, optional integrations, storage
  placement limits, API access, and operational safety.
- Retained the dashboard's bucket management, browser, access-key safety,
  activity logging, long-lived sessions, optional Restic checks, and optional
  Cloudflared controls.

### Removed

- Deployment-specific names, addresses, topology, storage paths, and release
  observations from the public project history and documentation.
