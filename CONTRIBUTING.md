# Contributing

Thanks for helping make agent process lifecycle behavior safer and easier to
understand.

## Development setup

Requirements: Linux or macOS, Go 1.24+, and Herdr 0.9.5+.

```sh
git clone https://github.com/Grafton-Apparel/herdr-process-guard.git
cd herdr-process-guard
make check
make build
herdr plugin link "$PWD"
```

Open the dashboard with:

```sh
herdr plugin pane open --plugin herdr.process-guard --entrypoint dashboard
```

## Pull requests

- Keep discovery and classification separate from termination.
- Add deterministic fixtures for new process-tree or agent signatures.
- Never weaken PID/start-time identity checks or typed confirmations.
- Do not include raw commands, tokens, usernames, or private paths in fixtures.
- Run `make check` before opening a pull request.

Changes to stop behavior should include both a dry-run test and a stale-preview
test. New classification evidence should be explainable in plain language and
represented in JSON.

## Adding agent or workload recognition

Open an issue first when a detector could match generic processes such as
`node`, `python`, or `java`. Include a sanitized ancestry tree, process start
times, listener state, and the Herdr agent lifecycle transition. Generic name
matching alone is not sufficient attribution evidence.

## Watchdog changes

Keep observation policy in `internal/watchdog` independent of host I/O. Start
with a failing policy or socket fixture. Use fake clocks for continuous
windows, and disposable subprocesses for Linux pidfd tests. Do not signal
operator panes or processes during acceptance.

Run `go test -race ./...`, `go vet ./...` and Linux/macOS cross builds. A macOS
cross build covers compilation; it does not establish Linux cleanup behavior.
Preserve incomplete-snapshot blocking, shared intentional stores, durable
attempt-before-signal ordering and startup deduplication. Review the
[watchdog safety policy](docs/WATCHDOG.md) with any change to those paths.
