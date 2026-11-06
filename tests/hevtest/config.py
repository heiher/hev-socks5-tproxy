"""TProxy configuration builder (no YAML dependency)."""
import copy


def _scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return "'%s'" % str(v).replace("'", "''")


def dump(cfg):
    out = []
    for sect, body in cfg.items():
        out.append("%s:" % sect)
        for k, v in body.items():
            if v is None:
                continue
            out.append("  %s: %s" % (k, _scalar(v)))
    return "\n".join(out) + "\n"


def default(bed):
    return {
        "main": {"workers": 1},
        "socks5": {
            "port": bed.socks_port,
            "address": bed.socks_addr,
            "udp": "udp",
        },
        "tcp": {"port": bed.tcp_port, "address": "::"},
        "udp": {"port": bed.udp_port, "address": "::"},
        "dns": {"port": bed.dns_port, "address": "::",
                "upstream": bed.dns_upstream},
        "misc": {
            "log-file": "stderr",
            "log-level": "warn",
        },
    }


def build(bed, **over):
    """``build(bed, socks5={'udp': 'tcp'}, dns=None)``; a value of None
    removes the key, a section of None removes the section."""
    cfg = default(bed)
    for sect, body in over.items():
        if body is None:
            cfg.pop(sect, None)
            continue
        cfg.setdefault(sect, {}).update(copy.deepcopy(body))
    return cfg


def ports(cfg):
    """Listening ports of a config as {'tcp':, 'udp':, 'dns':} (None when the
    section is absent): the testbed redirects traffic to exactly these."""
    out = {}
    for k in ("tcp", "udp", "dns"):
        p = cfg.get(k, {}).get("port")
        out[k] = int(p) if p is not None else None
    return out
