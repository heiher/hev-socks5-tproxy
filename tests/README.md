# Test suite

Black-box tests: the suite behaves like a normal user of a transparent
proxy gateway. It builds hev-socks5-tproxy, starts it with a YAML config,
installs the documented nftables `tproxy` + policy routing rules, and checks
what an application on the LAN side sees (TCP/UDP/DNS traffic, the config
file, signals, process options). No internal symbols are touched.

```sh
tests/run.sh func              # functional tests, ~50 s, pass/fail
tests/run.sh bench             # benchmarks, report numbers only
tests/run.sh all               # both (two independent sessions)
tests/run.sh list              # list tests / benchmarks
```

Options: `-b BIN` use an existing binary (default: `make`), `-k NAME` select
tests/benchmarks by substring (repeatable), `-x` stop at first failure,
`-v` verbose, `-d SECONDS` per-measurement duration (default 3,
`BENCH_DURATION`). Results are printed as they are measured; when
`GITHUB_STEP_SUMMARY` is set the tables are also appended to the job summary.

Functional and benchmark runs are separate commands, so a CI job can run
them independently. The exit code is non-zero if a functional test fails.
Benchmarks only fail when they cannot run; numbers are reported, never
compared with history.

## Requirements (Ubuntu)

root (the script re-executes itself through `sudo`), Python >= 3.12, a C
compiler, `make`, `iproute2`, and `nftables` (no tun device needed).
Everything runs in throw-away network namespaces; nothing on the host is
reconfigured.

```sh
sudo apt-get install -y iproute2 nftables python3 build-essential
```

## What is covered

| area | tests |
|---|---|
| TCP | IPv4/IPv6 echo, upload digest, download, concurrency, half-close, refused target, upstream down, abrupt close / RST |
| UDP | IPv4/IPv6, UDP-in-UDP and UDP-in-TCP, reply source, fullcone, max/oversize datagram, idle timeout, `udp-address` |
| DNS | forwarding to the upstream, IPv4/IPv6 resolver and upstream, reply source, many clients, garbage |
| SOCKS5 auth | valid / wrong / missing credentials, pipeline mode |
| config / process | every config key, listeners on/off, workers, timeouts, logging, `limit-nofile`, daemon + pid file, signals, bad config |
| benchmarks | TCP throughput + CPU (1 and 4 workers), UDP throughput/loss (both relay modes), TCP/UDP/DNS latency, connection rate, memory per session |

## Layout

```
tests/run.sh               entry point
tests/hevtest/             framework
  main.py                  CLI driver / discovery
  platform/base.py         platform-neutral testbed definition (topology)
  platform/linux.py        Linux back-end (netns + veth + nft tproxy)
  targets.py               echo/sink/source/reflect/dns services behind SOCKS5
  case.py config.py client.py benchlib.py report.py build.py
tests/tools/socks5d.c      SOCKS5 upstream (HevSocks5Core): auth, UDP, UDP-in-TCP
tests/functional/test_*.py unittest cases, one tproxy instance per test
tests/bench/bench_*.py     benchmarks: run(bed, report, args)
```

Topology (Linux): a *lan* namespace holds the test process, whose default
route is the *gateway* namespace. The gateway runs hev-socks5-tproxy and the
`tproxy` rules (TCP, UDP and UDP/53 from the lan are handed to the listening
ports of the config). A *server* namespace holds `socks5d`, the plain DNS
upstream and the target services. The target addresses (`203.0.113.10`,
`2001:db8::10`) exist only in the server namespace, so a connection can
succeed only if it really went through tproxy and the SOCKS5 server.

## Adding a platform

Create `hevtest/platform/<name>.py` with a `Bed` class deriving from
`base.Bed` (set up the environments, `spawn_client/spawn_gateway/spawn_server`,
`redirect`, `start_tproxy`, `mark_packets`, `proc_stats`, `nofile_limit`,
`listening`) and register it in `hevtest/platform/__init__.py`. Tests and
benchmarks use only the `Bed` API. Add an entry to the `Tests` matrix in
`.github/workflows/ci.yml`.

## Adding a test

Functional: add `tests/functional/test_<x>.py`, derive from
`TProxyTestCase`, call `self.tproxy(section={...})` and use `hevtest.client`.
Benchmark: add `tests/bench/bench_<x>.py` with `run(bed, rep, args)` using
`benchlib.running(...)`, and register its name in `bench_modules()` order.
