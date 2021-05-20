# HevSocks5Tproxy

[![status](https://gitlab.com/hev/hev-socks5-tproxy/badges/master/pipeline.svg)](https://gitlab.com/hev/hev-socks5-tproxy/commits/master)

HevSocks5Tproxy is a simple, lightweight transparent proxy for Linux.

**Features**
* IPv4/IPv6. (dual stack)
* Redirect TCP connections.
* Redirect UDP packets. (UDP over TCP)

## How to Build

**Linux**:
```bash
git clone --recursive git://github.com/heiher/hev-socks5-tproxy
cd hev-socks5-tproxy
make
```

**Android**:
```bash
mkdir hev-socks5-tproxy
cd hev-socks5-tproxy
git clone --recursive git://github.com/heiher/hev-socks5-tproxy jni
cd jni
ndk-build
```

## How to Use

### Config

```yaml
main:
socks5:
  port: 1080
  address: 127.0.0.1

tcp:
  port: 1088
  address: '::'

udp:
  port: 1088
  address: '::'

#misc:
#  log-file: stderr # stdout or file-path
#  log-level: warn # debug, info or error
#  pid-file: /run/hev-socks5-tproxy.pid
#  limit-nofile: -1
```

### Run

```bash
# Capabilities
setcap cap_net_admin,cap_net_bind_service+ep bin/hev-socks5-tproxy

bin/hev-socks5-tproxy conf/main.yml
```

### Redirect rules

#### Bypass ipset

DON'T FORGOT TO ADD UPSTREAM ADDRESS TO BYPASS IPSET!!

Or use iptables uid-owner match to exclude proxy process.

```bash
# IPv4
ipset create byp4 hash:net family inet hashsize 2048 maxelem 65536
ipset add byp4 0.0.0.0/8
ipset add byp4 10.0.0.0/8
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
ipset add byp4 255.255.255.255

# IPv6
ipset create byp6 hash:net family inet6 hashsize 1024 maxelem 65536
ipset add byp6 ::
ipset add byp6 ::1
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

#### Netfilter and Routing

Gateway and Local modes

```bash
# IPv4
iptables -t mangle -A PREROUTING -m set --match-set byp4 dst -j RETURN
iptables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 1088 --tproxy-mark 1088
iptables -t mangle -A PREROUTING -p udp -j TPROXY --on-port 1088 --tproxy-mark 1088

ip rule add fwmark 1088 table 100
ip route add local default dev lo table 100

# Only for local mode
iptables -t mangle -A OUTPUT -m set --match-set byp4 dst -j RETURN
iptables -t mangle -A OUTPUT -p tcp -j MARK --set-mark 1088
iptables -t mangle -A OUTPUT -p udp -j MARK --set-mark 1088

# IPv6
ip6tables -t mangle -A PREROUTING -m set --match-set byp6 dst -j RETURN
ip6tables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 1088 --tproxy-mark 1088
ip6tables -t mangle -A PREROUTING -p udp -j TPROXY --on-port 1088 --tproxy-mark 1088

ip -6 rule add fwmark 1088 table 100
ip -6 route add local default dev lo table 100

# Only for local mode
ip6tables -t mangle -A OUTPUT -m set --match-set byp6 dst -j RETURN
ip6tables -t mangle -A OUTPUT -p tcp -j MARK --set-mark 1088
ip6tables -t mangle -A OUTPUT -p udp -j MARK --set-mark 1088
```

## Authors
* **Heiher** - https://hev.cc

## License
LGPL
