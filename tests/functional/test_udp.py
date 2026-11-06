"""UDP redirection: fullcone NAT, UDP-in-UDP and UDP-in-TCP."""
import concurrent.futures as cf
import os
import socket

from hevtest import client
from hevtest.case import TProxyTestCase

MODES = ("udp", "tcp")


class UdpTest(TProxyTestCase):

    def test_unreachable_without_tproxy(self):
        self.assertIsNone(client.udp_echo(self.t4, self.bed.P_ECHO, b"x",
                                          0.6, 2))

    def echo(self, host, size=100, **kw):
        data = os.urandom(size)
        r, src = client.udp_request(host, self.bed.P_ECHO, data, **kw)
        return r == data, src

    def test_echo_both_modes_both_families(self):
        for mode in MODES:
            tp = self.tproxy(socks5={"udp": mode})
            for host in (self.t4, self.t6):
                for size in (1, 100, 1400):
                    with self.subTest(mode=mode, host=host, size=size):
                        ok, _ = self.echo(host, size)
                        self.assertTrue(ok)
            tp.stop()

    def test_max_size_datagram(self):
        self.tproxy()
        for host in (self.t4, self.t6):
            ok, _ = self.echo(host, 1472 if host == self.t4 else 1452)
            self.assertTrue(ok)

    def test_oversize_datagram_is_dropped(self):
        # datagrams beyond the 1500 byte buffer are discarded, the session
        # keeps working
        tp = self.tproxy()
        ok, _ = self.echo(self.t4, 8000, timeout=1.0, retries=1)
        self.assertFalse(ok)
        self.assertTrue(tp.proc.alive(), tp.log())
        ok, _ = self.echo(self.t4, 100)
        self.assertTrue(ok)

    def test_reply_comes_from_original_destination(self):
        # the user must see replies from the address it talked to, not from
        # the proxy
        for mode in MODES:
            with self.subTest(mode=mode):
                tp = self.tproxy(socks5={"udp": mode})
                for host in (self.t4, self.t6):
                    _, src = self.echo(host)
                    self.assertEqual(src, (host, self.bed.P_ECHO))
                tp.stop()

    def test_one_socket_many_destinations(self):
        self.tproxy()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for port in (self.bed.P_ECHO, self.bed.P_REFLECT):
                d = os.urandom(64)
                r, src = client.udp_request(self.t4, port, d, sock=s)
                self.assertEqual(r, d)
        finally:
            s.close()

    def test_fullcone(self):
        # The target answers from a different port than the one it was
        # contacted on.  A fullcone NAT delivers that to the user socket.
        for mode in MODES:
            with self.subTest(mode=mode):
                tp = self.tproxy(socks5={"udp": mode})
                d = os.urandom(64)
                r, src = client.udp_request(self.t4, self.bed.P_REFLECT, d)
                self.assertEqual(r, d, "no reply from another port")
                self.assertEqual(src, (self.t4, self.bed.P_REFLECT_FROM))
                tp.stop()

    def test_concurrent_sockets(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                tp = self.tproxy(socks5={"udp": mode})
                with cf.ThreadPoolExecutor(32) as ex:
                    futs = [ex.submit(self.echo, self.t4 if i % 2 else self.t6,
                                      200) for i in range(128)]
                    self.assertTrue(all(f.result()[0] for f in futs))
                tp.stop()

    def test_session_survives_idle_timeout(self):
        # a short UDP timeout closes idle sessions; new traffic must work
        self.tproxy(misc={"udp-read-write-timeout": 1000})
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            d = os.urandom(32)
            self.assertEqual(client.udp_request(self.t4, self.bed.P_ECHO, d,
                                                sock=s)[0], d)
            import time
            time.sleep(2.5)
            d = os.urandom(32)
            self.assertEqual(client.udp_request(self.t4, self.bed.P_ECHO, d,
                                                sock=s)[0], d)
        finally:
            s.close()

    def test_udp_address_override(self):
        # udp-address replaces the relay address announced by the server
        self.tproxy(socks5={"udp-address": self.bed.socks_addr})
        ok, _ = self.echo(self.t4)
        self.assertTrue(ok)

    def test_udp_address_wrong(self):
        # a relay address that is not reachable must break UDP, not TCP
        self.tproxy(socks5={"udp-address": "192.0.2.77"})
        ok, _ = self.echo(self.t4, timeout=1.5, retries=1)
        self.assertFalse(ok)
        self.assertTrue(client.tcp_echo(self.t4, self.bed.P_ECHO, 100))

    def test_upstream_down(self):
        self.tproxy(socks5={"port": 1099})
        ok, _ = self.echo(self.t4, timeout=1.5, retries=1)
        self.assertFalse(ok)
