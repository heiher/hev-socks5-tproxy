# HevSocks5TProxy

[![status](https://github.com/heiher/hev-socks5-tproxy/actions/workflows/build.yaml/badge.svg?branch=master&event=push)](https://github.com/heiher/hev-socks5-tproxy)

HevSocks5TProxy is a simple, lightweight transparent proxy for Linux.

**Features**
* IPv4/IPv6. (dual stack)
* Redirect TCP connections.
* Redirect UDP packets. (Fullcone NAT, UDP in UDP/TCP)

```
                +---------------+      +---------------+
                | Socks5 Server |      | Upstream  DNS |
                +---------------+      +---------------+
                         ^                     ^
                         |                     |
                         +----------+----------+
                             uplink | (eth1)
                +-------------------o<-----------------+ (direct dns)
                |                   ^                  |
                |            socks5 |                  |
set ether daddr |    dns    +---------------+          |
rule routing    |?--------->| Socks5 TProxy |<---------+ (proxy dns)
ipset/tproxy    |  tcp/udp  +---------------+   tproxy |
                |                   | dns              |
                |                   v                  |
                |           +---------------+    dns   |
                |           |    DNSMasq    |----------+
   [nat/bridge] |           +---------------+
                |
                +-------------------o
                           downlink | (eth0)
                                    v
                            +---------------+
                            |   LAN  Host   |
                            +---------------+
```

## How to Build

### Linux

```bash
git clone --recursive https://github.com/heiher/hev-socks5-tproxy
cd hev-socks5-tproxy
make
```

### Android

```bash
mkdir hev-socks5-tproxy
cd hev-socks5-tproxy
git clone --recursive https://github.com/heiher/hev-socks5-tproxy jni
cd jni
ndk-build
```

## How to Use

### Config

```yaml
main:
  workers: 1

socks5:
  port: 1080
  address: 127.0.0.1
  # Socks5 UDP relay mode (tcp|udp)
  udp: 'udp'
  # Socks5 handshake using pipeline mode
# pipeline: false
  # Socks5 server username
  username: 'username'
  # Socks5 server password
  password: 'password'
  # Socket mark
  mark: 0x438

tcp:
  port: 1088
  address: '::'

udp:
  port: 1088
  address: '::'

# Proxy DNS for bridged mode
#   [address]:port <-> [upstream]:53 (dnsmasq)
dns:
  # DNS port
  port: 1053
  # DNS address
  address: '::'
  # DNS upstream
  upstream: 127.0.0.1

#misc:
#  task-stack-size: 16384 # task stack size (bytes)
#  connect-timeout: 5000 # connect timeout (ms)
#  read-write-timeout: 60000 # read-write timeout (ms)
#  log-file: stderr # stdout or file-path
#  log-level: warn # debug, info or error
#  pid-file: /run/hev-socks5-tproxy.pid
#  limit-nofile: 65535
```

### Run

```bash
# Capabilities
setcap cap_net_admin,cap_net_bind_service+ep bin/hev-socks5-tproxy

bin/hev-socks5-tproxy conf/main.yml
```

### Redirect rules

#### Type 1: NfTables

##### Netfilter

```
table inet mangle {
    set byp4 {
        typeof ip daddr
        flags interval
        elements = {
            0.0.0.0/8,
            10.0.0.0/8,
            100.64.0.0/10,
            127.0.0.0/8,
            169.254.0.0/16,
            172.16.0.0/12,
            192.0.0.0/24,
            192.0.2.0/24,
            192.88.99.0/24,
            192.168.0.0/16,
            198.18.0.0/15,
            198.51.100.0/24,
            203.0.113.0/24,
            224.0.0.0/4,
            240.0.0.0/4
        }
    }

    set byp6 {
        typeof ip6 daddr
        flags interval
        elements = {
            ::/128,
            ::1/128,
            ::ffff:0:0:0/96,
            64:ff9b::/96,
            100::/64,
            2001::/32,
            2001:20::/28,
            2001:db8::/32,
            2002::/16,
            fc00::/7,
            fe80::/10,
            ff00::/8
        }
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        meta mark 0x438 return
        ip daddr @byp4 return
        ip6 daddr @byp6 return
        meta l4proto { tcp, udp } tproxy to :1088 meta mark set 0x440 accept
    }

    # Only for local mode
    chain output {
        type route hook output priority mangle; policy accept;
        meta mark 0x438 return
        ip daddr @byp4 return
        ip6 daddr @byp6 return
        meta l4proto { tcp, udp } meta mark set 0x440
    }
}
```

##### Routing

```bash
ip rule add fwmark 1088 table 100
ip route add local default dev lo table 100

ip -6 rule add fwmark 1088 table 100
ip -6 route add local default dev lo table 100
```

#### Type 2: IPTables

##### Bypass ipset

```bash
# IPv4
ipset create byp4 hash:net family inet hashsize 2048 maxelem 65536
ipset add byp4 0.0.0.0/8
ipset add byp4 10.0.0.0/8
ipset add byp4 100.64.0.0/10
ipset add byp4 127.0.0.0/8
ipset add byp4 169.254.0.0/16
ipset add byp4 172.16.0.0/12
ipset add byp4 192.0.0.0/24
ipset add byp4 192.0.2.0/24
ipset add byp4 192.88.99.0/24
ipset add byp4 192.168.0.0/16
ipset add byp4 198.18.0.0/15
ipset add byp4 198.51.100.0/24
ipset add byp4 203.0.113.0/24
ipset add byp4 224.0.0.0/4
ipset add byp4 240.0.0.0/4

# IPv6
ipset create byp6 hash:net family inet6 hashsize 1024 maxelem 65536
ipset add byp6 ::/128
ipset add byp6 ::1/128
ipset add byp6 ::ffff:0:0:0/96
ipset add byp6 64:ff9b::/96
ipset add byp6 100::/64
ipset add byp6 2001::/32
ipset add byp6 2001:20::/28
ipset add byp6 2001:db8::/32
ipset add byp6 2002::/16
ipset add byp6 fc00::/7
ipset add byp6 fe80::/10
ipset add byp6 ff00::/8
```

##### Netfilter and Routing

Gateway and Local modes

```bash
# IPv4
iptables -t mangle -A PREROUTING -m mark --mark 0x438 -j RETURN
iptables -t mangle -A PREROUTING -m set --match-set byp4 dst -j RETURN
iptables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 1088 --tproxy-mark 1088
iptables -t mangle -A PREROUTING -p udp -j TPROXY --on-port 1088 --tproxy-mark 1088

ip rule add fwmark 1088 table 100
ip route add local default dev lo table 100

# Only for local mode
iptables -t mangle -A OUTPUT -m mark --mark 0x438 -j RETURN
iptables -t mangle -A OUTPUT -m set --match-set byp4 dst -j RETURN
iptables -t mangle -A OUTPUT -p tcp -j MARK --set-mark 1088
iptables -t mangle -A OUTPUT -p udp -j MARK --set-mark 1088

# IPv6
ip6tables -t mangle -A PREROUTING -m mark --mark 0x438 -j RETURN
ip6tables -t mangle -A PREROUTING -m set --match-set byp6 dst -j RETURN
ip6tables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 1088 --tproxy-mark 1088
ip6tables -t mangle -A PREROUTING -p udp -j TPROXY --on-port 1088 --tproxy-mark 1088

ip -6 rule add fwmark 1088 table 100
ip -6 route add local default dev lo table 100

# Only for local mode
ip6tables -t mangle -A OUTPUT -m mark --mark 0x438 -j RETURN
ip6tables -t mangle -A OUTPUT -m set --match-set byp6 dst -j RETURN
ip6tables -t mangle -A OUTPUT -p tcp -j MARK --set-mark 1088
ip6tables -t mangle -A OUTPUT -p udp -j MARK --set-mark 1088
```

## Contributors

* **hev** - https://hev.cc
* **ihipop** - https://ihipop.com
* **pexcn** - <i@pexcn.me>
* **spider84** - https://github.com/spider84

## License

MIT
