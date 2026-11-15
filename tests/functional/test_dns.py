"""DNS: queries to any resolver are forwarded to the configured upstream."""
import os
import subprocess
import socket

from hevtest import client, config
from hevtest.case import TProxyTestCase


class DnsTest(TProxyTestCase):

    def upstream_count(self):
        return int(client.tcp_ctrl(self.t4, self.bed.P_CTRL, "dns-count"))

    def test_unanswered_without_tproxy(self):
        r, _ = client.dns_query(self.bed.dns_server4, "a.test", timeout=0.6,
                                retries=2)
        self.assertIsNone(r)

    def test_query_ipv4_and_ipv6_resolver(self):
        self.tproxy()
        for srv in (self.bed.dns_server4, self.bed.dns_server6):
            with self.subTest(server=srv):
                r, src = client.dns_query(srv, "example.test")
                self.assertIsNotNone(r, "no reply from " + srv)
                self.assertEqual(len(r), 1)
                self.assertTrue(r[0].startswith("192.0.2."))
                # the user must see the resolver it asked
                self.assertEqual(src, (srv, 53))

    def test_aaaa(self):
        self.tproxy()
        r, _ = client.dns_query(self.bed.dns_server4, "example.test", qtype=28)
        self.assertIsNotNone(r)
        self.assertEqual(len(r), 1)
        self.assertTrue(r[0].startswith("20010db8"))

    def test_forwarded_to_upstream(self):
        self.tproxy()
        before = self.upstream_count()
        for i in range(5):
            client.dns_query(self.bed.dns_server4, "count%d.test" % i)
        self.assertGreaterEqual(self.upstream_count() - before, 5)

    def test_answers_are_consistent(self):
        self.tproxy()
        a, _ = client.dns_query(self.bed.dns_server4, "stable.test")
        b, _ = client.dns_query(self.bed.dns_server6, "stable.test")
        self.assertEqual(a, b)

    def test_many_clients(self):
        self.tproxy()
        socks = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                 for _ in range(50)]
        try:
            qs = []
            for i, s in enumerate(socks):
                q = client.dns_packet("many%d.test" % i)
                s.settimeout(3)
                s.sendto(q, (self.bed.dns_server4, 53))
                qs.append(q)
            for s, q in zip(socks, qs):
                resp, _ = s.recvfrom(4096)
                self.assertEqual(resp[:2], q[:2])
        finally:
            for s in socks:
                s.close()

    def test_non_dns_udp_is_not_dns(self):
        # UDP to another port goes to the SOCKS5 path, not to the resolver
        self.tproxy()
        d = os.urandom(40)
        self.assertEqual(client.udp_echo(self.t4, self.bed.P_ECHO, d), d)

    def test_upstream_down(self):
        # an unreachable resolver means no answer, and no damage
        self.tproxy(dns={"upstream": "10.201.0.99"})
        r, _ = client.dns_query(self.bed.dns_server4, "x.test", timeout=1.0,
                                retries=1)
        self.assertIsNone(r)
        self.assertTrue(client.tcp_echo(self.t4, self.bed.P_ECHO, 1000))

    def test_ipv6_upstream(self):
        self.tproxy(dns={"upstream": self.bed.socks_addr6})
        r, _ = client.dns_query(self.bed.dns_server4, "v6up.test")
        self.assertIsNotNone(r)

    def test_garbage_does_not_crash(self):
        tp = self.tproxy()
        for junk in (b"", b"\x00" * 3, b"\xff" * 64, os.urandom(300)):
            client.udp_echo(self.bed.dns_server4, 53, junk, 0.3, 1)
        self.assertTrue(tp.proc.alive(), tp.log())
        r, _ = client.dns_query(self.bed.dns_server4, "after-junk.test")
        self.assertIsNotNone(r)

    def test_upstream_port(self):
        self.tproxy(dns={"upstream-port": 5353})
        r, _ = client.dns_query(self.bed.dns_server4, "port.test")
        self.assertIsNotNone(r)
        self.assertTrue(r[0].startswith("192.0.2."))

    def test_upstream_port_closed(self):
        self.tproxy(dns={"upstream-port": 5354})
        r, _ = client.dns_query(self.bed.dns_server4, "closed.test",
                                timeout=1.0, retries=1)
        self.assertIsNone(r)

    def test_list_single_entry(self):
        self.tproxy(dns=[{"port": self.bed.dns_port, "address": "::",
                          "upstream": self.bed.dns_upstream}])
        r, _ = client.dns_query(self.bed.dns_server4, "list.test")
        self.assertIsNotNone(r)

    def test_multiple_instances(self):
        # two listeners, each with its own upstream; steer port 53 to each
        bad, good = self.bed.dns_port, 2053
        tp = self.tproxy(dns=[
            {"port": bad, "address": "::", "upstream": "10.201.0.99"},
            {"port": good, "address": "::", "upstream": self.bed.dns_upstream,
             "upstream-port": 5353},
        ])
        self.assertTrue(self.bed.listening(tp.proc.pid, "udp", good))
        r, _ = client.dns_query(self.bed.dns_server4, "bad.test",
                                timeout=1.0, retries=1)
        self.assertIsNone(r)
        self.bed.redirect(tcp=self.bed.tcp_port, udp=self.bed.udp_port,
                          dns=good)
        for srv in (self.bed.dns_server4, self.bed.dns_server6):
            r, src = client.dns_query(srv, "good.test")
            self.assertIsNotNone(r, "no reply from " + srv)
            self.assertEqual(src, (srv, 53))

    def test_invalid_upstream_rejected(self):
        for dns in ({"upstream": "not-an-ip"}, {"upstream-port": 0},
                    {"upstream-port": 70000}):
            with self.subTest(dns=dns):
                cfg = config.build(self.bed, dns=dns)
                path = self.write_config(cfg)
                r = subprocess.run([self.bed.tproxy_bin, path],
                                   capture_output=True, text=True, timeout=5)
                self.assertNotEqual(r.returncode, 0)
