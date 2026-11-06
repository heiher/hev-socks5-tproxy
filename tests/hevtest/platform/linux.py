"""Linux back-end: three network namespaces (lan - gateway - server).

The gateway uses nftables ``tproxy`` + policy routing, the recommended setup
from the README, to hand lan traffic to hev-socks5-tproxy.
"""
import os
import re
import subprocess
import time

from . import base

TPROXY_MARK = 1
TPROXY_TABLE = 100


def sh(*argv, check=True, stdin=None):
    r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, input=stdin)
    if check and r.returncode != 0:
        raise RuntimeError("%s failed (%d): %s" %
                           (" ".join(argv), r.returncode, r.stdout.strip()))
    return r


class Bed(base.Bed):
    name = "linux"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        tag = "hevt%d" % os.getpid()
        self.ns_c = tag + "c"          # lan
        self.ns_g = tag + "g"          # gateway
        self.ns_s = tag + "s"          # server
        self._created = []

    # --- lifecycle -----------------------------------------------------
    def setup(self):
        if os.geteuid() != 0:
            raise SystemExit("hevtest: root privileges are required "
                             "(IP_TRANSPARENT + network namespaces)")
        if subprocess.run(["which", "nft"], stdout=subprocess.DEVNULL
                          ).returncode != 0:
            raise SystemExit("hevtest: nft (nftables) is required")
        for ns in (self.ns_c, self.ns_g, self.ns_s):
            sh("ip", "netns", "add", ns)
            self._created.append(ns)
            sh("ip", "-n", ns, "link", "set", "lo", "up")

        c = ["ip", "-n", self.ns_c]
        g = ["ip", "-n", self.ns_g]
        s = ["ip", "-n", self.ns_s]

        # lan <-> gateway
        sh("ip", "link", "add", "hvl0", "netns", self.ns_c, "type", "veth",
           "peer", "name", "hvg1", "netns", self.ns_g)
        sh(*c, "addr", "add", self.lan_addr + "/24", "dev", "hvl0")
        sh(*c, "addr", "add", self.lan_addr6 + "/64", "dev", "hvl0", "nodad")
        sh(*g, "addr", "add", self.gw_addr + "/24", "dev", "hvg1")
        sh(*g, "addr", "add", self.gw_addr6 + "/64", "dev", "hvg1", "nodad")
        sh(*c, "link", "set", "hvl0", "up")
        sh(*g, "link", "set", "hvg1", "up")
        sh(*c, "-4", "route", "add", "default", "via", self.gw_addr)
        sh(*c, "-6", "route", "add", "default", "via", self.gw_addr6)

        # gateway <-> server
        sh("ip", "link", "add", "hvg0", "netns", self.ns_g, "type", "veth",
           "peer", "name", "hvs0", "netns", self.ns_s)
        sh(*g, "addr", "add", "10.201.0.1/24", "dev", "hvg0")
        sh(*g, "addr", "add", "fd00:201::1/64", "dev", "hvg0", "nodad")
        sh(*s, "addr", "add", self.socks_addr + "/24", "dev", "hvs0")
        sh(*s, "addr", "add", self.socks_addr6 + "/64", "dev", "hvs0", "nodad")
        sh(*g, "link", "set", "hvg0", "up")
        sh(*s, "link", "set", "hvs0", "up")

        # remote "internet": exists only inside the server environment
        sh(*s, "addr", "add", self.target4 + "/32", "dev", "lo")
        sh(*s, "addr", "add", self.target6 + "/128", "dev", "lo", "nodad")

        # tproxy delivery: marked packets are routed to the local stack
        for fam in ("-4", "-6"):
            sh(*g, fam, "rule", "add", "fwmark", str(TPROXY_MARK), "lookup",
               str(TPROXY_TABLE), "pref", "100")
            sh(*g, fam, "route", "add", "local", "default", "dev", "lo",
               "table", str(TPROXY_TABLE))
        self.redirect()

    def teardown(self):
        super().teardown()
        for ns in self._created:
            sh("ip", "netns", "del", ns, check=False)
        self._created = []

    def enter_client(self):
        fd = os.open("/run/netns/" + self.ns_c, os.O_RDONLY)
        try:
            os.setns(fd, os.CLONE_NEWNET)
        finally:
            os.close(fd)

    # --- processes -----------------------------------------------------
    def _spawn(self, argv, name, **kw):
        log = self.tmpfile((name or os.path.basename(argv[0])) + ".log")
        f = open(log, "wb")
        popen = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=f,
                                 stderr=subprocess.STDOUT, **kw)
        f.close()
        return self._track(base.Proc(argv, log, popen))

    def spawn_client(self, argv, name=None, **kw):
        # the calling thread already lives in the lan namespace
        return self._spawn(argv, name, **kw)

    def spawn_gateway(self, argv, name=None, **kw):
        return self._spawn(["ip", "netns", "exec", self.ns_g] + list(argv),
                           name, **kw)

    def spawn_server(self, argv, name=None, **kw):
        return self._spawn(["ip", "netns", "exec", self.ns_s] + list(argv),
                           name, **kw)

    # --- tproxy --------------------------------------------------------
    def redirect(self, tcp=None, udp=None, dns=None):
        # tcp/udp default to None = not redirected, except at setup where
        # the defaults are installed so "tproxy not running" is observable.
        if tcp is None and udp is None and dns is None:
            tcp, udp, dns = self.tcp_port, self.udp_port, self.dns_port
        rules = []
        for fam, nf, lo in (("ip", "ipv4", "ip"), ("ip6", "ipv6", "ip6")):
            def rule(proto, port, to):
                return ("iifname hvg1 meta nfproto %s %s dport %s "
                        "tproxy %s to :%d meta mark set %d accept" %
                        (nf, proto, to, fam, port, TPROXY_MARK))
            if dns:
                rules.append(rule("udp", dns, "53"))
            if udp:
                rules.append(rule("udp", udp, "1-65535"))
            if tcp:
                rules.append(rule("tcp", tcp, "1-65535"))
        text = """
flush ruleset
table inet hevt {
  counter sockmark { }
  chain pre {
    type filter hook prerouting priority mangle; policy accept;
    iifname hvg1 fib daddr type local accept
    %s
  }
  chain out {
    type filter hook output priority mangle; policy accept;
    meta mark %d counter name sockmark
  }
}
""" % ("\n    ".join(rules), self.mark)
        sh("ip", "netns", "exec", self.ns_g, "nft", "-f", "-", stdin=text)

    def start_tproxy(self, config_path, extra_args=(), wait=True, ports=None,
                     pid_file=None):
        if ports is not None:
            self.redirect(**ports)
        proc = self.spawn_gateway([self.tproxy_bin, config_path] +
                                  list(extra_args), "tproxy")
        if wait:
            self.wait_listen(proc, ports or {}, pid_file)
        return proc

    def wait_listen(self, proc, ports, pid_file=None, timeout=10.0):
        end = time.time() + timeout
        pid = proc.pid
        while time.time() < end:
            if pid_file:
                try:
                    with open(pid_file) as f:
                        pid = int(f.read().strip())
                    proc.pid_override = pid
                except (OSError, ValueError):
                    time.sleep(0.02)
                    continue
            elif not proc.alive():
                raise RuntimeError("tproxy exited early (%s):\n%s" %
                                   (proc.popen.returncode, proc.log()))
            want = [("tcp", ports.get("tcp")), ("udp", ports.get("udp")),
                    ("udp", ports.get("dns"))]
            if all(self.listening(pid, p, n) for p, n in want if n):
                return
            time.sleep(0.02)
        raise RuntimeError("tproxy is not listening:\n" + proc.log())

    def mark_packets(self, mark=None):
        r = sh("ip", "netns", "exec", self.ns_g, "nft", "list", "counter",
               "inet", "hevt", "sockmark")
        m = re.search(r"packets (\d+)", r.stdout)
        return int(m.group(1)) if m else 0

    # --- introspection -------------------------------------------------
    def proc_stats(self, pid):
        out = {}
        try:
            with open("/proc/%d/status" % pid) as f:
                for line in f:
                    m = re.match(r"(VmRSS|VmHWM):\s+(\d+) kB", line)
                    if m:
                        out["rss_kb" if m.group(1) == "VmRSS" else
                            "peak_rss_kb"] = int(m.group(2))
            with open("/proc/%d/stat" % pid) as f:
                rest = f.read().rsplit(")", 1)[1].split()
            tck = os.sysconf("SC_CLK_TCK")
            out["cpu_s"] = (int(rest[11]) + int(rest[12])) / tck
        except (OSError, IndexError):
            pass
        return out

    def nofile_limit(self, pid):
        with open("/proc/%d/limits" % pid) as f:
            for line in f:
                if line.startswith("Max open files"):
                    return int(line.split()[3])
        return None

    def listening(self, pid, proto, port):
        # /proc/<pid>/net shows the network namespace of that process
        state = "0A" if proto == "tcp" else "07"
        hexport = ":%04X " % port
        for t in (proto, proto + "6"):
            try:
                with open("/proc/%d/net/%s" % (pid, t)) as f:
                    for line in f.readlines()[1:]:
                        cols = line.split()
                        if cols[3] == state and cols[1].endswith(
                                hexport.strip()):
                            return True
            except OSError:
                pass
        return False
