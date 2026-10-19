# Architecture

Process Guard is an out-of-process Herdr plugin written in Go. Operators can
install the Linux watchdog as a systemd user service.

```text
Herdr snapshot + pane process info
                │
                ▼
Linux procfs or macOS ps / lsof ──► process graph
                │                  │
                │                  ▼
                └──────────► attribution + lineage
                                   │
recorded observations ─────────────┤
                                   ▼
                         lifecycle classification
                                   │
                     ┌─────────────┴─────────────┐
                     ▼                           ▼
               text / JSON report          Bubble Tea UI
                                                 │
                                                 ▼
                                       explicit stop preview
```

## Components

- `internal/herdr`: typed client for Herdr's Unix-socket API
- `internal/platform`: process, working-directory, and socket collection
- `internal/guard`: graph construction, attribution, classification, policy,
  and stop-plan validation
- `internal/store`: locked per-socket manual observation and approval state
- `internal/watchdog`: pure policy, bounded all-session collection, persistence,
  pidfd orchestration, status UI and Linux user-service installation
- `internal/presentation`: shared human explanations
- `internal/ui`: interactive dashboard and typed stop confirmation

## State

The state file contains stable process identities, sanitized command summaries,
command hashes, ports, timestamps, agent intervals, intentional approvals, and
recent termination survivors. It does not contain file contents and is never
uploaded.

Exact live identity is always authoritative. Historical records can strengthen
attribution or keep a known workload visible during a telemetry miss, but they
cannot make an exited or PID-reused process a valid stop target.

The watchdog stores attribution/activity metadata, durable attempted identities,
alert cooldowns and pause state in `watchdog.json` under the plugin state root.
It shares per-socket `state.json` approval files with the manual engine. It
omits raw argv and working paths from watchdog persistence. A separate per-user
exclusive process lock prevents concurrent service/manual watchers.

The runner separates policy decisions from pin and signal adapters. It takes
fresh snapshots around pinning and after durable attempt writes, validates
complete membership and current policy, then uses Linux pidfds for SIGTERM.
The systemd unit executes a copied binary in a stable path outside the plugin
checkout. Startup hooks only ensure the installed unit.
