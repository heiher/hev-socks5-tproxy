"""Configuration file options, process options and lifecycle."""
import os
import signal
import subprocess
import time

from hevtest import client, config
from hevtest.case import TProxyTestCase


class ConfigTest(TProxyTestCase):

    def echo_ok(self, host=None):
        return client.tcp_echo(host or self.t4, self.bed.P_ECHO, 10000)

    # --- socks5 section ------------------------------------------------
    def test_pipeline_handshake(self):
        self.tproxy(socks5={"pipeline": True})
        self.assertTrue(self.echo_ok())
        self.assertTrue(self.echo_ok(self.t6))

    def test_tcp_fastopen(self):
        self.tproxy(socks5={"tcp-fastopen": True})
        self.assertTrue(self.echo_ok())

    def test_socket_mark(self):
        # sockets towards the SOCKS5 server carry the configured mark
        before = self.bed.mark_packets()
        self.tproxy(socks5={"mark": self.bed.mark})
        self.assertTrue(self.echo_ok())
        self.assertGreater(self.bed.mark_packets(), before)

    def test_no_mark_by_default(self):
        self.tproxy()
        self.assertTrue(self.echo_ok())
        self.assertEqual(self.bed.mark_packets(), 0)

    def test_socks5_ipv6_server(self):
        self.tproxy(socks5={"address": self.bed.socks_addr6})
        self.assertTrue(self.echo_ok())

    # --- listeners -----------------------------------------------------
    def test_custom_ports(self):
        self.tproxy(tcp={"port": 2088}, udp={"port": 2099}, dns={"port": 2053})
        self.assertTrue(self.echo_ok())
        self.assertTrue(self.echo_ok(self.t6))
        d = b"custom-port"
        self.assertEqual(client.udp_echo(self.t4, self.bed.P_ECHO, d), d)
        r, _ = client.dns_query(self.bed.dns_server4, "custom.test")
        self.assertIsNotNone(r)

    def test_ipv4_only_listeners(self):
        self.tproxy(tcp={"address": "0.0.0.0"}, udp={"address": "0.0.0.0"})
        self.assertTrue(self.echo_ok())
        self.assertTrue(client.tcp_blocked(self.t6, self.bed.P_ECHO, 3.0))

    def test_udp_section_absent(self):
        self.tproxy(udp=None)
        self.assertTrue(self.echo_ok())
        self.assertIsNone(client.udp_echo(self.t4, self.bed.P_ECHO, b"x",
                                          1.0, 1))

    def test_tcp_section_absent(self):
        self.tproxy(tcp=None)
        self.assertTrue(client.tcp_blocked(self.t4, self.bed.P_ECHO, 3.0))
        d = b"udp-only"
        self.assertEqual(client.udp_echo(self.t4, self.bed.P_ECHO, d), d)

    def test_dns_section_absent(self):
        self.tproxy(dns=None)
        r, _ = client.dns_query(self.bed.dns_server4, "x.test", timeout=0.8,
                                retries=1)
        self.assertIsNone(r)
        self.assertTrue(self.echo_ok())

    # --- workers -------------------------------------------------------
    def test_multiple_workers(self):
        import concurrent.futures as cf
        self.tproxy(main={"workers": 4})
        with cf.ThreadPoolExecutor(32) as ex:
            futs = [ex.submit(client.tcp_echo, self.t4, self.bed.P_ECHO,
                              50000) for _ in range(128)]
            self.assertTrue(all(f.result() for f in futs))
        d = b"multi-worker-udp"
        self.assertEqual(client.udp_echo(self.t4, self.bed.P_ECHO, d), d)

    # --- misc section --------------------------------------------------
    def test_tcp_read_write_timeout(self):
        self.tproxy(misc={"tcp-read-write-timeout": 1000})
        s = client.tcp_connect(self.t4, self.bed.P_ECHO)
        try:
            s.sendall(b"a")
            self.assertEqual(s.recv(1), b"a")
            s.settimeout(6)
            self.assertEqual(s.recv(1), b"", "idle connection not closed")
        finally:
            s.close()

    def test_connection_kept_while_active(self):
        self.tproxy(misc={"tcp-read-write-timeout": 1500})
        s = client.tcp_connect(self.t4, self.bed.P_ECHO)
        try:
            for _ in range(5):
                time.sleep(0.8)
                s.sendall(b"k")
                self.assertEqual(s.recv(1), b"k")
        finally:
            s.close()

    def test_limit_nofile(self):
        tp = self.tproxy(misc={"limit-nofile": 4321})
        self.assertTrue(client.wait_for(
            lambda: self.bed.nofile_limit(tp.proc.pid) == 4321, 3))

    def test_log_file(self):
        path = self.bed.tmpfile("tproxy.log")
        self.tproxy(misc={"log-file": path, "log-level": "debug"})
        self.assertTrue(self.echo_ok())
        self.assertTrue(client.wait_for(
            lambda: os.path.exists(path) and os.path.getsize(path) > 0, 3),
            "debug log is empty")

    def test_log_level_quiet(self):
        tp = self.tproxy(misc={"log-level": "error"})
        self.assertTrue(self.echo_ok())
        self.assertEqual(tp.log().strip(), "")

    def test_log_level_debug_stderr(self):
        tp = self.tproxy(misc={"log-level": "debug"})
        self.assertTrue(self.echo_ok())
        self.assertTrue(client.wait_for(lambda: tp.log().strip() != "", 3))

    def test_log_file_null(self):
        tp = self.tproxy(misc={"log-file": "null", "log-level": "debug"})
        self.assertTrue(self.echo_ok())
        self.assertEqual(tp.log().strip(), "")

    def test_small_task_stack(self):
        self.tproxy(misc={"task-stack-size": 65536})
        self.assertTrue(self.echo_ok())

    def test_connect_timeout_option(self):
        self.tproxy(misc={"connect-timeout": 2000})
        self.assertTrue(self.echo_ok())

    def test_udp_buffer_options(self):
        self.tproxy(misc={"udp-recv-buffer-size": 262144,
                          "udp-copy-buffer-nums": 4})
        d = b"udp-opts"
        self.assertEqual(client.udp_echo(self.t4, self.bed.P_ECHO, d), d)

    # --- process -------------------------------------------------------
    def test_no_arguments_prints_usage(self):
        r = subprocess.run([self.bed.tproxy_bin], capture_output=True,
                           text=True, timeout=5)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("CONFIG_PATH", r.stdout + r.stderr)

    def test_missing_config_file(self):
        r = subprocess.run([self.bed.tproxy_bin, "/nonexistent/x.yml"],
                           capture_output=True, text=True, timeout=5)
        self.assertNotEqual(r.returncode, 0)

    def test_invalid_config_file(self):
        path = self.bed.tmpfile("bad.yml")
        with open(path, "w") as f:
            f.write("tcp: [unterminated\n  : : :\n")
        r = subprocess.run([self.bed.tproxy_bin, path],
                           capture_output=True, text=True, timeout=5)
        self.assertNotEqual(r.returncode, 0)

    def test_sigint_exits_cleanly(self):
        tp = self.tproxy()
        self.assertTrue(self.echo_ok())
        rc = tp.stop(signal.SIGINT)
        self.assertEqual(rc, 0, tp.log())
        self.assertTrue(client.tcp_blocked(self.t4, self.bed.P_ECHO, 2.0))

    def test_sigint_with_active_sessions(self):
        tp = self.tproxy()
        socks = [client.tcp_connect(self.t4, self.bed.P_ECHO)
                 for _ in range(20)]
        for s in socks:
            s.sendall(b"x")
            s.recv(1)
        rc = tp.stop(signal.SIGINT)
        for s in socks:
            s.close()
        self.assertEqual(rc, 0, tp.log())

    def test_sigterm_stops(self):
        tp = self.tproxy()
        tp.stop(signal.SIGTERM)
        self.assertFalse(tp.proc.alive())

    def test_restart_same_ports(self):
        for _ in range(3):
            tp = self.tproxy()
            self.assertTrue(self.echo_ok())
            tp.stop(signal.SIGINT)

    def test_daemon_pid_file(self):
        pid_file = self.bed.tmpfile("tproxy.pid")
        tp = self.tproxy(misc={"pid-file": pid_file, "log-file": "null"})
        with open(pid_file) as f:
            pid = int(f.read().strip())
        self.assertTrue(os.path.exists("/proc/%d" % pid))
        self.assertTrue(self.echo_ok())
        tp.stop(signal.SIGINT)
        self.assertTrue(client.wait_for(
            lambda: not os.path.exists("/proc/%d" % pid), 5),
            "daemon did not exit")
