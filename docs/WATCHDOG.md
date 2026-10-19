# Linux watchdog operation

Process Guard v0.2.0 preserves the upstream manual inspector and adds a Linux
watchdog. Herdr 0.9.5 supplies session and pane process information. macOS keeps
the manual inspector; automatic cleanup requires Linux pidfds.

## State and configuration

The root is `HERDR_PLUGIN_STATE_DIR` when set, otherwise
`$XDG_STATE_HOME/herdr/plugins/herdr.process-guard` (default
`~/.local/state/herdr/plugins/herdr.process-guard`). Use the same root for the
plugin and service. `service-install` records the current resolved root in the
unit, along with current XDG and Herdr config overrides.

Files under that root:

- `watchdog-config.json`: strict JSON configuration; omitted fields use defaults.
- `watchdog.json`: helper attribution, activity baselines, attempted identities,
  cooldowns, pause state and last observation.
- `watchdog-audit.jsonl` and `.1`: at most two roughly 1 MiB event logs.
- `sessions/<socket-hash>/state.json`: manual observations and intentional
  approvals, shared by the manual engine and watchdog.

The watchdog stores hashes and sanitized summaries; it omits raw argv and working
paths from watchdog state. It retains live exact identities, caps observation
maps and expires cooldowns after 24 hours. Saved Herdr sessions/transcripts stay
outside its writes. Earlier upstream versions used a global approval file;
reapply intentional marks after upgrading to the per-socket namespace.

Run `herdr-process-guard watchdog-config` to inspect the effective config. The
full default config is:

```json
{
  "cleanup": false,
  "poll_seconds": 30,
  "orphan_seconds": 1800,
  "cooldown_seconds": 1800,
  "resource_seconds": 300,
  "idle_seconds": 14400,
  "cpu_percent": 100,
  "rss_bytes": 2147483648,
  "cpu_activity_ms": 0,
  "grace_seconds": 5,
  "max_records": 10000
}
```

Set `cleanup` to `true` to enable orphan cleanup. Configuration validation
requires at least 30 minutes of orphanhood. The default quiet policy resets on
any observed CPU advancement, disk/character I/O change or established
connection. `cpu_activity_ms` permits a per-observation CPU housekeeping budget
up to 1000 ms; zero gives the most conservative policy. Poll bounds are 5 to
300 seconds; resource/cooldown windows accept 60 to 86400 seconds; the orphan
window accepts 1800 to 604800 seconds. Invalid/unknown config keys stop the
watcher, and systemd retries after ten seconds. Alerts continue while cleanup
is paused.

To create a minimal opt-in config, write an atomic replacement in the state
root that matches your plugin installation:

```sh
state="$HOME/.local/state/herdr/plugins/herdr.process-guard"
mkdir -p "$state"
printf '%s\n' '{"cleanup":true}' > "$state/watchdog-config.json.tmp"
chmod 600 "$state/watchdog-config.json.tmp"
mv "$state/watchdog-config.json.tmp" "$state/watchdog-config.json"
```

The watcher reloads config on each poll. `--config <path>` overrides the config
file for `watch` and `watch-once`; the installed service uses the default file.

## Commands and installation

Use the verified release binary, or the binary from the installed plugin:

```sh
herdr-process-guard watch-once
herdr-process-guard watchdog-status
herdr-process-guard watchdog-report
herdr-process-guard watch
```

`watch-once` resets continuous windows and takes one observation. Repeated
one-shot invocations cannot mature an orphan timer. `watch` holds one per-user
exclusive lock at `$XDG_CACHE_HOME/herdr-process-guard/watchdog.lock` (default
`~/.cache/herdr-process-guard/watchdog.lock`). A second watcher, including a
one-shot observer, fails rather than running beside it. SIGTERM/interrupt stop
the loop and release the lock. Restart and gaps beyond twice the poll interval
reset all continuous evidence, while attribution and attempts survive.

Install a real Linux user service from the selected binary:

```sh
herdr-process-guard service-install
herdr-process-guard service-start
herdr-process-guard service-status
systemctl --user is-active herdr-process-guard.service
journalctl --user -u herdr-process-guard.service --since today
```

`service-install` copies the executable to
`~/.local/lib/herdr-process-guard/herdr-process-guard`, writes
`$XDG_CONFIG_HOME/systemd/user/herdr-process-guard.service`, and reloads the user
manager. It does not enable/start the service. `service-start` enables and starts
it. The unit uses the stable copied path, runs with no `HERDR_SOCKET_PATH`, and
restarts failed watchers. Startup and pane event hooks call `service-ensure`,
which asks systemd to start an installed unit without spawning a detached
worker. With no unit installed, hooks do nothing. macOS hooks do nothing.

The user systemd manager must stay active for monitoring after logout. Configure
user lingering through your host administrator when required; the plugin does
not change login policy.

After a plugin/release upgrade, replace the stable service binary and restart:

```sh
herdr-process-guard service-stop
herdr-process-guard service-install
herdr-process-guard service-start
```

`service-stop` disables/stops the unit, so later startup hooks cannot keep it
disabled: they ask systemd to start an installed unit. To keep it stopped across
Herdr startup/events, remove the unit with `service-uninstall`. That command
stops/disables the service, removes its unit and reloads systemd. It preserves
state, configuration and the stable binary.

## Operator controls

```sh
herdr-process-guard pause
herdr-process-guard resume
herdr-process-guard mark-intentional <pid>
herdr-process-guard unmark-intentional <pid>
herdr-process-guard watchdog-dashboard
```

Pause/resume persists across restarts and affects cleanup only. The watchdog
status popup offers the same controls through `p` and `r`; `q` closes it. The
Herdr plugin menu has actions for the watchdog popup, upstream workload
inspector and pause/resume.

Intentional marks use the same per-socket registry in the manual inspector and
watchdog. A mark protects exact member identities and descendants of a live
marked root, even when membership grows. `mark-intentional` also supports a
watchdog-recorded helper after its original pane disappears; unknown processes
fall back to the manual inspector. Marks do not count as cleanup approval.

## Discovery and safety limits

The collector discovers `herdr.sock` in the Herdr config directory and
`sessions/<name>/herdr.sock`. `HERDR_CONFIG_PATH` overrides that directory;
`XDG_CONFIG_HOME` and HOME provide defaults. It also accepts exact counterparts
under `$XDG_RUNTIME_DIR/herdr` and the canonicalized explicit
`HERDR_SOCKET_PATH`. It excludes `herdr-client.sock` and remote SSH bridges.
Saved session directories with no socket appear as saved/stopped. They do not
block cleanup or authorize deletion.

Each poll has at most 64 session sockets, 512 panes per session and four socket
workers. Each request has a two-second deadline; the session phase has a
20-second deadline. An inaccessible session or incomplete ancestry snapshot
blocks cleanup and resets orphan continuity. Initial stat absence does not count
as a live ancestry gap when native pidfd verification confirms exit; permission,
visibility and later identity-read failures still block cleanup. Frequent
unresolved gaps can prevent maturity on a busy host. The
watchdog favors retained helpers over incomplete evidence. A target telemetry
gap blocks its containing tree without blocking unrelated complete trees.

Ownership requires a previously observed exact ancestry chain beneath an agent
executable plus Herdr agent metadata. Generic `node`/`python` processes and
unrecognized agent wrappers cannot establish agent identity. Helpers under a
recognized agent can have any executable name and need no listener. Existing
pane shells protect their session and descendants in all agent states. The
original pane, shell and agent must disappear before the orphan window starts.
Protected ancestors and intentional trees block cleanup. Only PID 1 adoption
can bypass an absent same-user parent without a protected ancestor.

The runner refreshes sessions/processes before pinning, after pinning and after
durable attempt/audit writes. It compares the entire target tree, checks pause
and intentional policy, then revalidates all pidfds. It records an attempt
before the first signal. A write failure blocks cleanup; a surviving identity
gets no retry after restart. It sends SIGTERM only and reports survivors after
the grace interval. It deletes no saved session and closes no pane. Linux
cannot freeze exec/fork between userspace validation and signaling. A tree
that changes during the pass can leave survivors, which require human review.

Notifications use Herdr `notification.show` with `sound:"none"`. Host/session/
pane context and command summaries omit raw argv, control bytes and long text.
Event-specific cooldowns persist across restarts. The local audit records
notification failures when no Herdr socket accepts the notification.
