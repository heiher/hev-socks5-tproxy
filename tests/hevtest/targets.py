"""Target services that live on the far side of tproxy + the SOCKS5 server.

Runs inside the server environment (stdlib only).  Everything listens on
``::`` (dual stack) so the same service answers IPv4 and IPv6.

  TCP 7001 echo           UDP 7001 echo
  TCP 7002 sink           UDP 7002 sink  (counted, see ctrl)
  TCP 7003 source         UDP 7003 source  ("SRC <size> <seconds>\\n")
  TCP 7004 digest  (read to EOF, answer "<bytes> <sha256>\\n")
  TCP 7005 count   (read to EOF, answer "<bytes>\\n")
  UDP 7006 reflect (remember the sender, answer from UDP 7007 to it)
  UDP 53   dns     (A/AAAA stub resolver, deterministic answers)
  TCP 7100 ctrl    ("udp-sink\\n" -> "<bytes> <packets>\\n", then resets;
                    "dns-count\\n" -> "<queries>\\n")
"""
import hashlib
import socket
import threading
import time

BUF = 256 * 1024
stats = {"bytes": 0, "pkts": 0, "dns": 0}
stats_lock = threading.Lock()


def tcp_listener(port, handler):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(("::", port))
    s.listen(4096)

    def loop():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=run, args=(c,), daemon=True).start()

    def run(c):
        try:
            handler(c)
        except OSError:
            pass
        finally:
            c.close()

    threading.Thread(target=loop, daemon=True).start()


def udp_listener(port, handler):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    s.bind(("::", port))
    threading.Thread(target=handler, args=(s,), daemon=True).start()


def h_echo(c):
    while True:
        d = c.recv(BUF)
        if not d:
            return
        c.sendall(d)


def h_sink(c):
    buf = bytearray(BUF)
    while c.recv_into(buf):
        pass


def h_source(c):
    d = b"\x5a" * BUF
    while True:
        c.sendall(d)


def h_digest(c):
    h = hashlib.sha256()
    n = 0
    buf = bytearray(BUF)
    mv = memoryview(buf)
    while True:
        r = c.recv_into(buf)
        if not r:
            break
        n += r
        h.update(mv[:r])
    c.sendall(("%d %s\n" % (n, h.hexdigest())).encode())


def h_count(c):
    n = 0
    buf = bytearray(BUF)
    while True:
        r = c.recv_into(buf)
        if not r:
            break
        n += r
    c.sendall(("%d\n" % n).encode())


def h_ctrl(c):
    f = c.makefile("rwb")
    for line in f:
        cmd = line.strip().decode()
        if cmd == "udp-sink":
            with stats_lock:
                out = "%d %d\n" % (stats["bytes"], stats["pkts"])
                stats["bytes"] = stats["pkts"] = 0
            f.write(out.encode())
            f.flush()
        elif cmd == "dns-count":
            with stats_lock:
                out = "%d\n" % stats["dns"]
            f.write(out.encode())
            f.flush()
        else:
            f.write(b"ERR\n")
            f.flush()


def u_echo(s):
    while True:
        d, a = s.recvfrom(65535)
        s.sendto(d, a)


def u_sink(s):
    while True:
        d, _ = s.recvfrom(65535)
        with stats_lock:
            stats["bytes"] += len(d)
            stats["pkts"] += 1


def u_source(s):
    while True:
        d, a = s.recvfrom(65535)
        try:
            _, size, secs = d.split()
            size, secs = int(size), float(secs)
        except ValueError:
            continue
        threading.Thread(target=blast, args=(s, a, size, secs),
                         daemon=True).start()


def u_reflect(s):
    out = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    out.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    out.bind(("::", 7007))
    while True:
        d, a = s.recvfrom(65535)
        out.sendto(d, a)


def dns_answer(q):
    """Minimal authoritative stub: every A/AAAA name has a stable answer."""
    import struct
    if len(q) < 17:
        return None
    try:
        off = 12
        while q[off]:
            off += q[off] + 1
        qtype = struct.unpack(">H", q[off + 1:off + 3])[0]
        end = off + 5
    except (IndexError, struct.error):
        return None
    h = hashlib.sha256(q[12:off]).digest()
    head = q[:2] + struct.pack(">HHHHH", 0x8180, 1, 0, 0, 0)
    rr = b""
    if qtype == 1:
        rr = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) +
              bytes([192, 0, 2, h[0] or 1]))
    elif qtype == 28:
        rr = (b"\xc0\x0c" + struct.pack(">HHIH", 28, 1, 60, 16) +
              bytes([0x20, 0x01, 0x0d, 0xb8]) + h[:12])
    n = 1 if rr else 0
    head = q[:2] + struct.pack(">HHHHH", 0x8180, 1, n, 0, 0)
    return head + q[12:end] + rr


def u_dns(s):
    while True:
        d, a = s.recvfrom(65535)
        with stats_lock:
            stats["dns"] += 1
        r = dns_answer(d)
        if r:
            s.sendto(r, a)


def blast(s, addr, size, secs):
    pkt = b"\xa5" * size
    end = time.time() + secs
    n = 0
    while True:
        if n % 128 == 0 and time.time() >= end:
            break
        try:
            s.sendto(pkt, addr)
        except OSError:
            time.sleep(0.0005)
        n += 1


def main():
    tcp_listener(7001, h_echo)
    tcp_listener(7002, h_sink)
    tcp_listener(7003, h_source)
    tcp_listener(7004, h_digest)
    tcp_listener(7005, h_count)
    tcp_listener(7100, h_ctrl)
    udp_listener(7001, u_echo)
    udp_listener(7002, u_sink)
    udp_listener(7003, u_source)
    udp_listener(7006, u_reflect)
    udp_listener(53, u_dns)
    print("READY", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
