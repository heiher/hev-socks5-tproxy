"""Base class of the functional tests."""
import unittest

from . import config


class TProxy:
    def __init__(self, bed, proc, cfg_path, cfg):
        self.bed = bed
        self.proc = proc
        self.cfg_path = cfg_path
        self.cfg = cfg

    def stop(self, *a, **kw):
        return self.bed.stop_tproxy(self.proc, *a, **kw)

    def log(self):
        return self.proc.log()


class TProxyTestCase(unittest.TestCase):
    """Each test gets an isolated tproxy instance via ``self.tproxy()``.

    ``bed`` is injected by the runner.  The shared server side (SOCKS5
    server without authentication and the target services) is always up.
    """
    bed = None

    def setUp(self):
        self.t4 = self.bed.target4
        self.t6 = self.bed.target6

    def write_config(self, cfg):
        path = self.bed.tmpfile("tproxy.yml")
        with open(path, "w") as f:
            f.write(config.dump(cfg))
        return path

    def tproxy(self, wait=True, extra_args=(), raw=None, **over):
        """Start tproxy.  ``over`` overrides config sections, e.g.
        ``self.tproxy(socks5={'udp': 'tcp'}, dns=None)``.  The gateway's
        redirect rules follow the ports in the resulting config."""
        cfg = config.build(self.bed, **over)
        ports = config.ports(cfg)
        if raw is not None:
            path = self.bed.tmpfile("tproxy.yml")
            with open(path, "w") as f:
                f.write(raw)
            ports = None
        else:
            path = self.write_config(cfg)
        pid_file = cfg.get("misc", {}).get("pid-file")
        proc = self.bed.start_tproxy(path, extra_args, wait=wait, ports=ports,
                                     pid_file=pid_file)
        t = TProxy(self.bed, proc, path, cfg)
        self.addCleanup(t.stop)
        return t

    def require(self, cond, why):
        if not cond:
            self.skipTest(why)

    def fail_with_log(self, tp, msg):
        self.fail("%s\n--- tproxy log ---\n%s" % (msg, tp.log()))
