"""TCP redirection through tproxy."""
import concurrent.futures as cf

from hevtest import client
from hevtest.case import TProxyTestCase


class TcpTest(TProxyTestCase):

    def test_unreachable_without_tproxy(self):
        # negative control: the targets exist only behind the SOCKS5 server
        self.assertTrue(client.tcp_blocked(self.t4, self.bed.P_ECHO, 1.0))

    def test_echo_ipv4(self):
        self.tproxy()
        for size in (1, 100, 1460, 65536, 4 << 20):
            with self.subTest(size=size):
                self.assertTrue(client.tcp_echo(self.t4, self.bed.P_ECHO, size))

    def test_echo_ipv6(self):
        self.tproxy()
        for size in (1, 100, 1460, 65536, 4 << 20):
            with self.subTest(size=size):
                self.assertTrue(client.tcp_echo(self.t6, self.bed.P_ECHO, size))

    def test_upload_integrity(self):
        self.tproxy()
        for host in (self.t4, self.t6):
            with self.subTest(host=host):
                self.assertTrue(client.tcp_upload_digest(
                    host, self.bed.P_DIGEST, 32 << 20))

    def test_download_stream(self):
        self.tproxy()
        for host in (self.t4, self.t6):
            with self.subTest(host=host):
                s = client.tcp_connect(host, self.bed.P_SOURCE)
                try:
                    got = len(client.recv_exact(s, 16 << 20))
                finally:
                    s.close()
                self.assertEqual(got, 16 << 20)

    def test_original_destination_port(self):
        # the destination is recovered per connection, whatever the port is
        self.tproxy()
        for port in (self.bed.P_ECHO, self.bed.P_DIGEST):
            with self.subTest(port=port):
                self.assertTrue(client.tcp_upload_digest(self.t4, port, 100)
                                if port == self.bed.P_DIGEST else
                                client.tcp_echo(self.t4, port, 100))

    def test_concurrent_connections(self):
        self.tproxy()
        with cf.ThreadPoolExecutor(64) as ex:
            futs = [ex.submit(client.tcp_echo,
                              self.t4 if i % 2 else self.t6,
                              self.bed.P_ECHO, 100000) for i in range(256)]
            self.assertTrue(all(f.result() for f in futs))

    def test_half_close(self):
        # shutdown(WR) must propagate while the reverse direction still works
        self.tproxy()
        for host in (self.t4, self.t6):
            self.assertTrue(client.tcp_upload_digest(host, self.bed.P_DIGEST,
                                                     1000))

    def test_refused_target_closes_connection(self):
        self.tproxy()
        for host in (self.t4, self.t6):
            self.assertTrue(client.tcp_blocked(host, 7999, 5.0))

    def test_upstream_down(self):
        # SOCKS5 server port nobody listens on
        self.tproxy(socks5={"port": 1099})
        self.assertTrue(client.tcp_blocked(self.t4, self.bed.P_ECHO, 5.0))

    def test_survives_abrupt_client_close(self):
        self.tproxy()
        for _ in range(20):
            s = client.tcp_connect(self.t4, self.bed.P_ECHO)
            s.sendall(b"x" * 100000)
            s.close()
        self.assertTrue(client.tcp_echo(self.t4, self.bed.P_ECHO, 1000))

    def test_survives_reset(self):
        self.tproxy()
        import socket
        import struct
        for _ in range(20):
            s = client.tcp_connect(self.t6, self.bed.P_ECHO)
            s.sendall(b"x" * 1000)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack("ii", 1, 0))
            s.close()
        self.assertTrue(client.tcp_echo(self.t6, self.bed.P_ECHO, 1000))
