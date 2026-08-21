# Changelog

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
