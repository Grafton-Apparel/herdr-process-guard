# Safety model

Process Guard treats classification and termination as separate systems. A
classification can suggest review; it never authorizes a signal by itself.

## Discovery invariants

- Only processes owned by the current user are inspected.
- Herdr pane shells, coding agents, and Process Guard are protected
  infrastructure.
- PID reuse is handled with a stable identity composed of PID and process start
  time.
- Direct live ancestry is stronger evidence than pane-session proximity or a
  historical agent activity window.
- Missing socket telemetry cannot silently erase a previously confirmed live
  workload identity.

## Manual inspector leftover eligibility

By default, `LEFTOVER: LIKELY` requires all of the following:

- policy is not `intentional`
- process is idle
- agent is `done`, `idle`, or no longer reported
- at least two observations exist
- the first observation is at least 30 minutes old
- attribution confidence is medium or high
- no established network connection is visible

A listening socket alone does not mean a service is in use. An established
connection does.

## Manual termination protocol

1. Rescan immediately before building a stop plan.
2. Capture every target's PID, start time, session ID, executable, and command
   hash.
3. Reject the plan if any identity or membership changes.
4. Display the full target tree and listening ports.
5. Require the user to type the exact confirmation phrase.
6. Send `SIGTERM` for a graceful stop.
7. Record exact survivors; do not escalate automatically.
8. Permit `SIGKILL` only through a separate force preview and confirmation for
   those recent exact survivors.

There is no rollback for process termination. This is why Process Guard favors
false negatives and additional observation over aggressive cleanup.

## Linux watchdog

The watchdog defaults to notifications. Enabling `cleanup` authorizes only
previously observed helpers beneath a named pane agent. It requires exact
PID/boot/start identity and executable device/inode plus command hash.
Generic executable names, directories and agent time windows cannot authorize
cleanup.

A live pane protects its shell/session and descendants in all agent states.
The original pane, shell and agent must disappear before the watchdog starts
30 minutes of continuous orphan observation. Any CPU advancement (default),
I/O change or established connection resets the quiet window. Restart,
observation gaps and incomplete session/ancestry snapshots reset continuity.
Incomplete telemetry blocks its containing tree, including unknown or foreign
kernel children. Shells, agents, service managers, Herdr and intentional trees
remain protected. PID 1 adoption alone does not protect an attributed helper.

Before signaling, the watchdog refreshes all sessions/processes, pins all
members, refreshes again, checks pause, and persists an attempt before the
first signal. It refreshes after those writes, checks pause and intentional
marks again, and revalidates all pins. A failure blocks cleanup. Each pidfd
SIGTERM call revalidates its member. Surviving identities receive an alert;
the watchdog does not retry or escalate. It closes no pane and deletes no
saved Herdr session or transcript.

Linux offers no atomic userspace operation that prevents exec/fork between
the last validation and signaling. Pidfds prevent PID substitution. The
watchdog handles observed tree changes by refusing the attempt; it may leave
survivors when membership changes during a signaling pass. See
[operation and limits](WATCHDOG.md).
