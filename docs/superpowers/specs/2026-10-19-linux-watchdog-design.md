# Linux watchdog

Extend the Apache-2.0 Process Guard fork at Grafton-Apparel/herdr-process-guard. Preserve its manual inspector and stop previews. Install on the operator's Linux desktop and gflinuxdev through Grafton's pinned plugin set.

## Policy

Observe all local Herdr sessions and current-user processes every 30 seconds with bounded requests. Attribute helpers through observed process ancestry, never executable name or working directory alone. Record PID, boot ID and kernel start ticks so PID reuse and reboot cannot transfer ownership. Keep state separate for each session socket and persist history across watchdog restarts. One watchdog per user owns an exclusive lock.

Warn about idle agent panes after four hours, stale/unreachable session sockets, orphan helpers, and sustained resource usage. A process consuming at least 100% of one CPU core or 2 GiB RSS for five minutes triggers an alert. These alerts describe observations, not a claim that CPU usage proves a runaway. Deduplicate identical notifications for 30 minutes. Use Herdr notifications and keep a bounded local audit log. Do not send messages to external systems.

Automatic cleanup is opt-in in configuration and will be enabled on these two machines. Only clean a helper observed under an agent before its owning pane or shell disappears, whose exact identity persists, with 30 minutes of mature orphan history, no meaningful recent CPU or I/O activity and no established network connection. Never close panes, stop an agent, remove a saved session/transcript, or signal unrelated services, CI containers, shells, Herdr, the watchdog or marked-intentional workloads. A disconnected client or idle agent does not establish orphanhood. An inaccessible session or incomplete ancestry graph suspends cleanup globally. Incomplete metadata, socket or I/O telemetry suspends cleanup of that process and its containing tree; unrelated telemetry warnings remain visible without disabling fully observed trees. Zombies remain in the process graph but are never cleanup targets.

Rescan all sessions and process identities before cleanup. Pin Linux process identities with pidfds and fail closed if unavailable; never fall back to an unguarded numeric PID signal. Validate the full target tree, owner, executable and command identity. Send SIGTERM only and record survivors. Never escalate to SIGKILL automatically. Recheck pins/intentional marks and new descendants immediately before signaling.

## Runtime

Provide `watch`, `watch-once`, and status/report actions, a Herdr dashboard action and startup/event integration that deduplicates watchers. Install a user systemd service so monitoring continues after client disconnects and upgrades. Keep polling, CPU, memory, grace and cooldown values configurable with strict validation. Persist observation continuity but do not count downtime as continuous orphan or resource evidence. Bound state and log retention.

## Verification

Use procfs fixtures and real disposable subprocesses for Linux identity/termination tests. Exercise live-agent protection, incomplete snapshots, new child processes, PID reuse, socket gaps, daemon restarts, intentional workloads and notification deduplication. CI covers Linux and macOS; automatic cleanup remains Linux-only. Verify installation with read-only reports and terminate only a disposable attributed orphan fixture during acceptance. Live targets are command-line/session sockets; page URL, domain and Shopify theme ID are not applicable.
