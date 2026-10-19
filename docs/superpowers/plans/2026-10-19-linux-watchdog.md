# Linux watchdog implementation plan

> For agentic workers: use superpowers:subagent-driven-development with test-driven development and task reviews. Continue through installation under the operator's approval.

**Goal:** Ship a Linux Process Guard watchdog that alerts and cleans only confirmed abandoned helper processes.

**Architecture:** Retain upstream attribution, manual previews and Bubble Tea dashboard. Add a Linux procfs collector, pidfd signal handles and a conservative watchdog with all-session discovery, durable per-session observations, notification cooldowns and a user service.

**Tech stack:** Go 1.24+, existing x/sys dependency, Linux procfs/pidfds, Herdr socket API, user systemd.

## Global constraints

- Follow `docs/superpowers/specs/2026-10-19-linux-watchdog-design.md`.
- Automatic SIGTERM is restricted to confirmed, previously attributed orphan helpers. Never terminate live agents, shells, panes, sessions, unrelated services or marked-intentional workloads.
- Missing telemetry, session failure, identity drift or process-tree growth disables automatic cleanup.
- Keep macOS manual inspection working. Automatic cleanup requires Linux pidfds.
- Keep raw commands and credentials out of notifications, logs and fixtures.
- Use Go at `/tmp/herdr-watchdog-toolchain/go/bin/go` with a quoted PATH assignment. Prefix shell commands with `rtk`.
- Repo checkout is isolated for this task on branch `feat/linux-watchdog`; other agents share it and own different files. Do not revert their work.

### Task 1: Linux telemetry and identity-safe signals

**Files:** `internal/platform/scanner*.go`, new Linux platform files and fixtures, `internal/model/model.go` for stable keys, platform signal tests.

**Interfaces:** Keep `Scanner.Processes() (map[int]model.Process, []string, error)` and the upstream `Scanner.Run` injection compatible. Add a narrow platform API to pin a process identity, verify its UID/start/boot/executable/command, send SIGTERM and close its pidfd. Define and document the exact API for Task 2 in the report. Linux identity uses boot ID and start ticks in addition to the display start timestamp; preserve the macOS key format. Add process I/O counters and completeness flags required to fail closed on missing socket or process telemetry.

- [ ] Write fixtures showing stat names with parentheses/spaces, disappearing processes, permission gaps, sockets and CPU/RSS/I/O counters. Add a test that discovers a real disposable process and rejects its changed identity.
- [ ] Run focused tests and record the expected missing-feature failure before implementation.
- [ ] Implement procfs collection without per-process `ps`/`lsof` subprocesses. Read boot time, boot ID and CLK_TCK safely; collect only the current UID. Keep bounded reads. Validate PID/start identity before and after related proc reads. Preserve warnings when sockets or metadata are inaccessible.
- [ ] Implement Linux pidfd pinning and verified SIGTERM; unsupported kernels fail closed. Verify a disposable child can be terminated and another process cannot be targeted through identity substitution. Preserve macOS collection.
- [ ] Run focused platform/model tests, then the full upstream suite and `go vet ./...`. Commit and report RED/GREEN evidence and exact new interfaces.

### Task 2: Background watchdog, conservative cleanup and operator controls

**Files:** new `internal/watchdog/` files/tests, `cmd/herdr-process-guard/main.go`, focused `internal/herdr` and `internal/store` extensions, `herdr-plugin.toml`, installer/service scripts, docs and GitHub workflows. Avoid unrelated rewrites of upstream classification.

**Interfaces:** Consume Task 1's collector and pinned signaling API. Use a testable pure observation/policy layer with injected clock, session snapshots, notifications and signal adapters; use real adapters in the command. Persist only necessary attribution/identity/activity metadata in per-socket state under the plugin state directory.

- [ ] Write failing policy tests for a previously agent-owned helper after its pane disappears; retained idle/blocked/working agents; resource alerts without termination; telemetry failure; PID reuse; mixed/changed trees; downtime; cooldown; intentional marks; and multiple sessions.
- [ ] Implement per-user exclusive watchdog locking, bounded all-session discovery and snapshot requests, 30-second polling, strict JSON config, persisted observations, cooldowns and bounded audit logs. Unknown/inaccessible sessions suppress cleanup. Start with notification-only defaults; operator deployment opts into orphan cleanup.
- [ ] Keep attribution conservative: record exact ancestry while a pane's agent exists. The owning pane/shell must disappear before the 30-minute orphan timer starts. Keep a valid idle pane and all descendants protected. Reject claimed ownership when a process now belongs to any live pane or protected ancestor. Inspect the complete tree, not just the root. Update CPU and I/O baselines on every observation and break continuity on gaps/restart. High CPU/RSS and stale idle panes notify only. Do not delete saved session data.
- [ ] Before SIGTERM, take fresh all-session/process snapshots, enforce intentional marks, compare identity/membership and activity, pin the whole target tree, then signal only validated members. Any failure blocks cleanup. Persist attempts so a surviving process gets an alert rather than repeated termination. Provide status and intentional-workload controls.
- [ ] Add Herdr notifications with sanitized host/session/pane/command-summary context and event-specific cooldown keys. Test exact wire methods against fake socket fixtures. Provide `watch`, `watch-once` and status/report CLI commands plus plugin actions and user service installation/start/stop controls. Startup/events deduplicate the watcher; user service uses fixed stable release paths and no plugin update can leave duplicate workers.
- [ ] Update fork README/safety/contributing documentation, version to `0.2.0`, Linux/macOS build/install/release workflows and fork download URLs. Preserve Apache-2.0 attribution and manual confirmation behavior. Do not use installers that download unverified artifacts.
- [ ] Run focused tests, a disposable orphan end-to-end fixture, the full race suite, vet, formatting and Linux/macOS cross builds. Commit and report RED/GREEN evidence, exact operational commands and remaining limitations.

### Task 3: Review, release and install

**Files:** review artifacts outside the repository; Grafton `plugins.toml` pin; machine-local plugin configuration/service unit.

- [ ] Review each task and the complete fork diff. Address all blocking findings and verify covering tests.
- [ ] Push a PR to the fork, wait for CI, merge, publish versioned Linux/macOS release archives with checksums and pin the reviewed release in Grafton's plugin set on desktop and gflinuxdev.
- [ ] Install through the existing team workflow, preserving unrelated configuration and development links. Enable orphan-only cleanup in both machine configs and verify one active watcher per machine.
- [ ] Verify version, service status, all-session reporting, live agent protection and a disposable orphan cleanup with notifications. Record command/fixture evidence; URL/domain/theme ID are not applicable.
- [ ] Report the installed version, enabled policy, alert thresholds, how to open the dashboard and how to pause cleanup.
