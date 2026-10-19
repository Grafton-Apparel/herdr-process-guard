# Security policy

Process Guard inspects local processes and can send termination signals, so
safety regressions are treated as security issues.

## Reporting

Do not open a public issue for vulnerabilities that could cause Process Guard
to target the wrong process, expose unsanitized command data, bypass typed
confirmation, or escape its Herdr pane/workspace scope.

Use GitHub's private vulnerability reporting for this repository. Include:

- Process Guard and Herdr versions
- Linux kernel or macOS version and architecture
- the smallest reproducible process tree
- expected and observed target identities
- whether any signal was actually sent

If private vulnerability reporting is unavailable, open a minimal public issue
requesting a private maintainer contact without publishing exploit details.

## Supported versions

Security fixes are applied to the latest tagged release. This project is
pre-1.0; users should upgrade before reporting a fixed-version regression.

## Safety boundaries

Process Guard is a local developer tool, not a privilege boundary. It runs as
the current user and can only inspect or signal processes available to that
user. It never requests elevated privileges and does not send telemetry.

Automatic cleanup defaults off. The Linux watchdog uses kernel boot/start
identities, executable device/inode, argv hashes, complete tree validation and
pidfds. It sends SIGTERM only. Missing session or ancestry evidence suspends
cleanup; missing target telemetry blocks that tree. Report any case that
bypasses intentional marks, paused cleanup or durable attempt suppression.
