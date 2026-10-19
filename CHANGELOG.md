# Changelog

All notable changes are documented here. The project follows Semantic
Versioning while pre-1.0 APIs remain explicitly unstable.

## [Unreleased]

## [0.2.0] - 2026-10-19

- Add native Linux telemetry and pinned SIGTERM identities.
- Add notification-first all-session watchdog, opt-in orphan cleanup, persistent
  pause/resume, shared intentional controls and bounded local audit/state.
- Add watchdog status and inspector actions to the plugin menu.
- Add stable-path Linux user service and Linux/macOS release archives.
- Preserve upstream Apache-2.0 attribution and interactive manual stop previews.

## [0.1.3] - 2026-08-24

### Added

- Human-readable Herdr workspace, tab, pane-title, and working-directory
  attribution.
- Explicit relationship, lineage, activity, and leftover explanations.
- Stable workload identity across partial macOS `lsof` telemetry.
- Launch documentation, safety policy, CI, release packaging, and visual assets.

### Safety

- Meaningful-CPU threshold prevents housekeeping activity from keeping an idle
  workload active indefinitely.
- Stop previews continue to require exact PID/start-time and tree membership.

[Unreleased]: https://github.com/Grafton-Apparel/herdr-process-guard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Grafton-Apparel/herdr-process-guard/releases/tag/v0.2.0
[0.1.3]: https://github.com/Efeguclu1/herdr-process-guard/releases/tag/v0.1.3
