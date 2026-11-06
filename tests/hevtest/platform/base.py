"""Platform independent testbed definition.

Topology (every back-end must provide the same logical layout)::

  +---- lan env ----+     +------------- gateway env -------------+     +--------- server env ---------+
  | test process    |     |                                       |     | socks5d  (SOCKS5 upstream)   |
  | (the "user")    |link | redirect rules: tcp/udp -> tproxy     |link | targets  (echo/sink/dns ...) |
  | default route --+---->+ hev-socks5-tproxy  --- socks5 -------->+---->+                              |
  +-----------------+     +---------------------------------------+     | target4/6  (reachable ONLY   |
                                                                          | through tproxy + socks5d)    |
                                                                          +------------------------------+

The lan side is an ordinary host whose default gateway is the box that runs
hev-socks5-tproxy, exactly like the deployment in the README.  The target
addresses live only in the server environment, so a connection can succeed
only if it was really redirected and relayed.
"""
import os
import signal
import subprocess
import tempfile
import time


class Proc:
    """A background process with captured output."""

    def __init__(self, argv, log_path, popen):
        self.argv = argv
        self.log_path = log_path
        self.popen = popen
        self.pid_override = None      # daemons: pid read from the pid file

    @property
    def pid(self):
        return self.pid_override or self.popen.pid

    def alive(self):
        if self.pid_override:
            return os.path.exists("/proc/%d" % self.pid_override)
        return self.popen.poll() is None

    def log(self):
        try:
            with open(self.log_path, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def stop(self, sig=signal.SIGTERM, timeout=5.0):
        if self.pid_override:
            return self._stop_daemon(sig, timeout)
        if self.popen.poll() is None:
            try:
                self.popen.send_signal(sig)
            except ProcessLookupError:
                pass
            try:
                self.popen.wait(timeout)
            except subprocess.TimeoutExpired:
                self.popen.kill()
                self.popen.wait()
        return self.popen.returncode

    def _stop_daemon(self, sig, timeout):
        try:
            os.kill(self.pid_override, sig)
        except ProcessLookupError:
            return 0
        end = time.time() + timeout
        while time.time() < end and self.alive():
            time.sleep(0.02)
        if self.alive():
            os.kill(self.pid_override, signal.SIGKILL)
        return 0

    def wait(self, timeout=None):
        return self.popen.wait(timeout)


class Bed:
    """Abstract testbed."""

    name = "base"

    # --- addressing (back-ends may override) ---------------------------
    lan_addr = "10.201.1.2"           # the "user" host
    lan_addr6 = "fd00:201:1::2"
    gw_addr = "10.201.1.1"            # the box running tproxy (lan side)
    gw_addr6 = "fd00:201:1::1"
    socks_addr = "10.201.0.2"         # where tproxy finds the SOCKS5 server
    socks_addr6 = "fd00:201::2"
    socks_port = 1080
    dns_upstream = "10.201.0.2"       # plain DNS server (port 53)
    target4 = "203.0.113.10"          # only reachable through tproxy+socks5d
    target6 = "2001:db8::10"
    dns_server4 = "198.51.100.53"     # a "public resolver" the user asks
    dns_server6 = "2001:db8:53::53"
    tcp_port = 1088                   # default tproxy listening ports
    udp_port = 1088
    dns_port = 1053
    mark = 438                        # socks5.mark used by tests

    # target service ports (see targets.py)
    P_ECHO = 7001
    P_SINK = 7002
    P_SOURCE = 7003
    P_DIGEST = 7004
    P_COUNT = 7005
    P_REFLECT = 7006                  # UDP: answers from another port
    P_REFLECT_FROM = 7007
    P_CTRL = 7100

    def __init__(self, tproxy_bin, tools_dir, workdir=None, verbose=False):
        self.tproxy_bin = os.path.abspath(tproxy_bin)
        self.tools_dir = tools_dir
        self.verbose = verbose
        self._tmp = tempfile.TemporaryDirectory(prefix="hevtest-", dir=workdir)
        self.workdir = self._tmp.name
        self._procs = []
        self._seq = 0

    # --- lifecycle -----------------------------------------------------
    def setup(self):
        raise NotImplementedError

    def teardown(self):
        for p in reversed(self._procs):
            p.stop()
        self._procs = []
        self._tmp.cleanup()

    def enter_client(self):
        """Move the calling thread into the lan environment."""
        raise NotImplementedError

    # --- processes -----------------------------------------------------
    def tmpfile(self, name):
        self._seq += 1
        return os.path.join(self.workdir, "%d-%s" % (self._seq, name))

    def spawn_client(self, argv, name=None, **kw):
        raise NotImplementedError

    def spawn_gateway(self, argv, name=None, **kw):
        raise NotImplementedError

    def spawn_server(self, argv, name=None, **kw):
        raise NotImplementedError

    def _track(self, proc):
        self._procs.append(proc)
        return proc

    # --- services ------------------------------------------------------
    def start_socks(self, user=None, password=None, port=None):
        argv = [os.path.join(self.tools_dir, "socks5d"), "-l", "::",
                "-p", str(port or self.socks_port)]
        if user is not None:
            argv += ["-u", user, "-w", password]
        proc = self.spawn_server(argv, "socks5d")
        self.wait_ready(proc)
        return proc

    def start_targets(self):
        import sys
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        argv = [sys.executable, "-I", os.path.join(here, "targets.py")]
        proc = self.spawn_server(argv, "targets")
        self.wait_ready(proc)
        return proc

    def wait_ready(self, proc, timeout=10.0):
        end = time.time() + timeout
        while time.time() < end:
            if "READY" in proc.log():
                return
            if not proc.alive():
                raise RuntimeError("%s exited early:\n%s" %
                                   (proc.argv[0], proc.log()))
            time.sleep(0.01)
        raise RuntimeError("%s did not become ready" % proc.argv[0])

    # --- tproxy --------------------------------------------------------
    def redirect(self, tcp=None, udp=None, dns=None):
        """(Re)install the gateway's redirect rules: lan TCP -> ``tcp``,
        lan UDP -> ``udp``, lan UDP/53 -> ``dns`` (None = not redirected)."""
        raise NotImplementedError

    def start_tproxy(self, config_path, extra_args=(), wait=True, ports=None,
                     pid_file=None):
        """Install the redirect rules for ``ports`` and start tproxy in the
        gateway env."""
        raise NotImplementedError

    def stop_tproxy(self, proc, sig=signal.SIGTERM):
        return proc.stop(sig)

    def mark_packets(self, mark=None):
        """Packets the gateway sent with the given socket mark."""
        raise NotImplementedError

    # --- introspection -------------------------------------------------
    def proc_stats(self, pid):
        """Return dict(rss_kb=, peak_rss_kb=, cpu_s=) for a process."""
        raise NotImplementedError

    def nofile_limit(self, pid):
        raise NotImplementedError

    def listening(self, pid, proto, port):
        """True if the process listens on ``port`` (proto tcp|udp)."""
        raise NotImplementedError
