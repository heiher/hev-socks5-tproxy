"""SOCKS5 username/password authentication."""
from hevtest import client
from hevtest.case import TProxyTestCase

AUTH_PORT = 1081


class AuthTest(TProxyTestCase):

    def setUp(self):
        super().setUp()
        p = self.bed.start_socks("alice", "s3cret", port=AUTH_PORT)
        self.addCleanup(p.stop)

    def auth_cfg(self, user, pw, mode="udp"):
        return dict(socks5={"port": AUTH_PORT, "username": user,
                            "password": pw, "udp": mode})

    def test_correct_credentials_tcp(self):
        self.tproxy(**self.auth_cfg("alice", "s3cret"))
        for host in (self.t4, self.t6):
            self.assertTrue(client.tcp_echo(host, self.bed.P_ECHO, 10000))

    def test_correct_credentials_udp(self):
        for mode in ("udp", "tcp"):
            with self.subTest(mode=mode):
                tp = self.tproxy(**self.auth_cfg("alice", "s3cret", mode))
                d = b"hello-auth"
                self.assertEqual(client.udp_echo(self.t4, self.bed.P_ECHO, d),
                                 d)
                tp.stop()

    def test_wrong_password(self):
        self.tproxy(**self.auth_cfg("alice", "wrong"))
        self.assertTrue(client.tcp_blocked(self.t4, self.bed.P_ECHO, 5.0))
        self.assertIsNone(client.udp_echo(self.t4, self.bed.P_ECHO, b"x",
                                          1.0, 1))

    def test_wrong_user(self):
        self.tproxy(**self.auth_cfg("mallory", "s3cret"))
        self.assertTrue(client.tcp_blocked(self.t4, self.bed.P_ECHO, 5.0))

    def test_no_credentials(self):
        self.tproxy(socks5={"port": AUTH_PORT})
        self.assertTrue(client.tcp_blocked(self.t4, self.bed.P_ECHO, 5.0))

    def test_credentials_with_pipeline(self):
        cfg = self.auth_cfg("alice", "s3cret")
        cfg["socks5"]["pipeline"] = True
        self.tproxy(**cfg)
        self.assertTrue(client.tcp_echo(self.t4, self.bed.P_ECHO, 10000))
