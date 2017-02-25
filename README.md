#HevSocks5Tproxy

HevSocks5Tproxy is a simple, lightweight transparent proxy for Linux.

**Features**
* Redirect TCP connections.
* Redirect DNS queries.

##How to Build

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
nkd-build
```

## Authors
* **Heiher** - https://hev.cc

##License
LGPL

