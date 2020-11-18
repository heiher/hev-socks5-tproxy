# HevSocks5Tproxy

[![status](https://gitlab.com/hev/hev-socks5-tproxy/badges/master/pipeline.svg)](https://gitlab.com/hev/hev-socks5-tproxy/commits/master)

HevSocks5Tproxy is a simple, lightweight transparent proxy for Linux.

**Features**
* Redirect TCP connections.
* Redirect DNS queries. (see [server](https://gitlab.com/hev/hev-socks5-server))
* IPv4/IPv6. (dual stack)

## How to Build

**Linux**:
```bash
git clone git://github.com/heiher/hev-socks5-tproxy
cd hev-socks5-tproxy
git submodule init
git submodule update
make
```

**Android**:
```bash
mkdir hev-socks5-tproxy
cd hev-socks5-tproxy
git clone git://github.com/heiher/hev-socks5-tproxy jni
cd jni
git submodule init
git submodule update
ndk-build
```

## How to Use

### Config

```yaml
main:
  workers: 4

socks5:
  port: 1080
  address: 127.0.0.1

tcp:
  port: 1088
  listen-address: 0.0.0.0

dns:
  port: 5300
  listen-address: 0.0.0.0

#misc:
#  log-file: null # stdout, stderr or file-path
#  log-level: warn # debug, info or error
#  pid-file: /run/hev-socks5-tproxy.pid
#  limit-nofile: -1
```

### Run

```bash
bin/hev-socks5-tproxy conf/main.yml
```

### Redirect rules

#### Global mode
```bash
# IPv4
# Base rules
iptables -t nat -N HTPROXY
iptables -t nat -A HTPROXY -d 0.0.0.0/8 -j RETURN
iptables -t nat -A HTPROXY -d 127.0.0.0/8 -j RETURN
iptables -t nat -A HTPROXY -d 169.254.0.0/16 -j RETURN
iptables -t nat -A HTPROXY -d 224.0.0.0/4 -j RETURN
iptables -t nat -A HTPROXY -d 240.0.0.0/4 -j RETURN
iptables -t nat -A HTPROXY -p udp --dport 53 -j REDIRECT --to-ports 5300
iptables -t nat -A HTPROXY -p tcp -j REDIRECT --to-ports 1088

# Bypass socks5 servers
iptables -t nat -A HTPROXY -d [SOCKS5_SERVER_ADDRESS] -j RETURN

# For local host
iptables -t nat -I OUTPUT -j HTPROXY

# For other hosts (tproxy gateway)
iptables -t nat -I PREROUTING -j HTPROXY

# IPv6
# Base rules
ip6tables -t nat -N HTPROXY
ip6tables -t nat -A HTPROXY -d ::1 -j RETURN
ip6tables -t nat -A HTPROXY -p udp --dport 53 -j REDIRECT --to-ports 5300
ip6tables -t nat -A HTPROXY -p tcp -j REDIRECT --to-ports 1088

# Bypass socks5 servers
ip6tables -t nat -A HTPROXY -d [SOCKS5_SERVER_ADDRESS] -j RETURN

# For local host
ip6tables -t nat -I OUTPUT -j HTPROXY

# For other hosts (tproxy gateway)
ip6tables -t nat -I PREROUTING -j HTPROXY
```

#### Per app mode

```bash
#!/bin/bash
# /usr/local/bin/tproxy

NET_CLS_DIR="/sys/fs/cgroup/net_cls/tproxy"
NET_CLS_ID=88
TP_TCP_PORT=1088
TP_DNS_PORT=5300

if [ ! -e ${NET_CLS_DIR} ]; then
	sudo sh -c "mkdir -p ${NET_CLS_DIR}; \
		chmod 0666 ${NET_CLS_DIR}/cgroup.procs; \
		echo ${NET_CLS_ID} > ${NET_CLS_DIR}/net_cls.classid; \
		iptables -t nat -D OUTPUT -p tcp \
			-m cgroup --cgroup ${NET_CLS_ID} \
			-j REDIRECT --to-ports ${TP_TCP_PORT}; \
		iptables -t nat -D OUTPUT -p udp --dport 53 \
			-m cgroup --cgroup ${NET_CLS_ID} \
			-j REDIRECT --to-ports ${TP_DNS_PORT}; \
		ip6tables -t nat -D OUTPUT -p tcp \
			-m cgroup --cgroup ${NET_CLS_ID} \
			-j REDIRECT --to-ports ${TP_TCP_PORT}; \
		ip6tables -t nat -D OUTPUT -p udp --dport 53 \
			-m cgroup --cgroup ${NET_CLS_ID} \
			-j REDIRECT --to-ports ${TP_DNS_PORT}; \
		iptables -t nat -I OUTPUT -p tcp \
			-m cgroup --cgroup ${NET_CLS_ID} \
			-j REDIRECT --to-ports ${TP_TCP_PORT}; \
		iptables -t nat -I OUTPUT -p udp --dport 53 \
			-m cgroup --cgroup ${NET_CLS_ID} \
			-j REDIRECT --to-ports ${TP_DNS_PORT}; \
		ip6tables -t nat -I OUTPUT -p tcp \
			-m cgroup --cgroup ${NET_CLS_ID} \
			-j REDIRECT --to-ports ${TP_TCP_PORT}; \
		ip6tables -t nat -I OUTPUT -p udp --dport 53 \
			-m cgroup --cgroup ${NET_CLS_ID} \
			-j REDIRECT --to-ports ${TP_DNS_PORT};" 2>&1 2> /dev/null
fi

echo $$ > ${NET_CLS_DIR}/cgroup.procs

exec "$@"
```

```bash
tproxy wget URL
tproxy git clone URL
```

## Authors
* **Heiher** - https://hev.cc

## License
LGPL

