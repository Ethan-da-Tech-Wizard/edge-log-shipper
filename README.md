# Edge Log Shipper

A Python project for sending log messages to a remote syslog endpoint. It includes a CLI, TCP and UDP transport, message sanitization, and a disk-backed spool for messages awaiting transmission.

## What's included

- `send` sends a single message; `tail` reads a file or standard input.
- `spool-status` inspects the local queue, and `flush` attempts to send pending messages.
- The spool has configurable capacity limits; older entries can be evicted when limits are exceeded.
- `purge` deletes pending spool data. Use it only when that loss is intended.

## Explore

From the repository root:

```sh
python3 -m edgeshipper --help
```

Inspect the [CLI](edgeshipper/cli.py), [transport](edgeshipper/transport.py), [spooler](edgeshipper/spooler.py) and [tests](tests/) for details before configuring a destination.

## Limitations

A successful socket send is not proof that the receiver persisted a log. Queue limits, process failures, network conditions and destination behavior can cause loss or duplication. The transport uses TCP or UDP sockets; it does not by itself provide encrypted transport. Test the complete path and provide appropriate transport protection for sensitive logs.

See the [license](LICENSE).
