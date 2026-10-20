The repo isn't local — the user just wants the raw script output. Writing it now.

```python
#!/usr/bin/env python3
"""
018_interface_stats.py — RESTCONF Interface Statistics Monitor

Polls real-time operational counters from Cisco IOS-XE devices via RESTCONF
using the Cisco-IOS-XE-interfaces-oper YANG model. Computes per-interface
utilization, error rates, and packet-drop ratios. Supports single-shot
reporting and continuous polling with configurable threshold alerting.

Usage:
    # Single poll, all interfaces:
    python 018_interface_stats.py --host 192.168.1.1 --user admin --password secret

    # Continuous poll every 30s, GigabitEthernet interfaces only:
    python 018_interface_stats.py --host 192.168.1.1 --user admin --password secret \
        --filter GigabitEthernet --interval 30

    # Alert when error rate exceeds 1% or utilization exceeds 80%:
    python 018_interface_stats.py --host 192.168.1.1 --user admin --password secret \
        --error-threshold 1.0 --util-threshold 80.0

    # Output raw counters as JSON:
    python 018_interface_stats.py --host 192.168.1.1 --user admin --password secret \
        --format json

Prerequisites:
    pip install requests
    IOS-XE device with RESTCONF enabled (ip http secure-server, restconf)
    User with privilege 15 or NETCONF/RESTCONF read access
"""

import argparse
import json
import logging
import sys
import time
import urllib3
from dataclasses import dataclass, field
from typing import Optional

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

RESTCONF_BASE = "https://{host}/restconf/data"
OPER_PATH = "Cisco-IOS-XE-interfaces-oper:interfaces/interface"
HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}


@dataclass
class InterfaceSnapshot:
    name: str
    admin_status: str
    oper_status: str
    speed: int  # bits/sec
    in_octets: int
    out_octets: int
    in_errors: int
    out_errors: int
    in_discards: int
    out_discards: int
    in_pkts: int
    out_pkts: int
    timestamp: float = field(default_factory=time.monotonic)


def build_session(user: str, password: str, timeout: int) -> requests.Session:
    s = requests.Session()
    s.auth = (user, password)
    s.headers.update(HEADERS)
    s.verify = False
    s.timeout = timeout
    return s


def fetch_interfaces(session: requests.Session, host: str, name_filter: Optional[str]) -> list[dict]:
    url = f"{RESTCONF_BASE.format(host=host)}/{OPER_PATH}"
    try:
        resp = session.get(url)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        log.error("Cannot reach %s — check IP and RESTCONF enablement", host)
        sys.exit(1)
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP %s from device: %s", exc.response.status_code, exc.response.text[:200])
        sys.exit(1)

    data = resp.json()
    interfaces = data.get("Cisco-IOS-XE-interfaces-oper:interface", [])
    if name_filter:
        interfaces = [i for i in interfaces if name_filter.lower() in i.get("name", "").lower()]
    return interfaces


def parse_snapshot(raw: dict) -> InterfaceSnapshot:
    stats = raw.get("statistics", {})
    return InterfaceSnapshot(
        name=raw.get("name", "unknown"),
        admin_status=raw.get("admin-status", "unknown"),
        oper_status=raw.get("oper-status", "unknown"),
        speed=int(raw.get("speed", 0)),
        in_octets=int(stats.get("in-octets", 0)),
        out_octets=int(stats.get("out-octets", 0)),
        in_errors=int(stats.get("in-errors", 0)),
        out_errors=int(stats.get("out-errors", 0)),
        in_discards=int(stats.get("in-discards", 0)),
        out_discards=int(stats.get("out-discards", 0)),
        in_pkts=int(stats.get("in-unicast-pkts", 0)) + int(stats.get("in-multicast-pkts", 0)),
        out_pkts=int(stats.get("out-unicast-pkts", 0)) + int(stats.get("out-multicast-pkts", 0)),
    )


def compute_rates(prev: InterfaceSnapshot, curr: InterfaceSnapshot) -> dict:
    elapsed = curr.timestamp - prev.timestamp
    if elapsed <= 0:
        return {}

    def rate(a, b):
        delta = b - a
        return max(delta, 0) / elapsed

    in_bps = rate(prev.in_octets, curr.in_octets) * 8
    out_bps = rate(prev.out_octets, curr.out_octets) * 8
    speed = curr.speed or 1
    in_util = (in_bps / speed) * 100
    out_util = (out_bps / speed) * 100
    total_pkts = (curr.in_pkts + curr.out_pkts) - (prev.in_pkts + prev.out_pkts)
    total_errs = (curr.in_errors + curr.out_errors + curr.in_discards + curr.out_discards) - (
        prev.in_errors + prev.out_errors + prev.in_discards + prev.out_discards
    )
    error_rate = (total_errs / total_pkts * 100) if total_pkts > 0 else 0.0

    return {
        "in_mbps": round(in_bps / 1_000_000, 2),
        "out_mbps": round(out_bps / 1_000_000, 2),
        "in_util_pct": round(in_util, 2),
        "out_util_pct": round(out_util, 2),
        "error_rate_pct": round(error_rate, 4),
    }


def print_table(snapshots: list[InterfaceSnapshot], prev_map: dict, args: argparse.Namespace):
    fmt = "{:<28} {:<6} {:<6} {:>8} {:>8} {:>8} {:>8} {:>10}"
    print("\n" + fmt.format("Interface", "Admin", "Oper", "In Mbps", "Out Mbps", "In Util%", "Out Util%", "Err Rate%"))
    print("-" * 90)

    alerts = []
    for snap in snapshots:
        prev = prev_map.get(snap.name)
        rates = compute_rates(prev, snap) if prev else {}
        in_m = rates.get("in_mbps", "-")
        out_m = rates.get("out_mbps", "-")
        in_u = rates.get("in_util_pct", "-")
        out_u = rates.get("out_util_pct", "-")
        err = rates.get("error_rate_pct", "-")

        print(fmt.format(
            snap.name[:28], snap.admin_status[:6], snap.oper_status[:6],
            in_m, out_m, in_u, out_u, err,
        ))

        if rates and args.util_threshold and max(rates["in_util_pct"], rates["out_util_pct"]) >= args.util_threshold:
            alerts.append(f"ALERT [{snap.name}] utilization {max(rates['in_util_pct'], rates['out_util_pct']):.1f}% >= {args.util_threshold}%")
        if rates and args.error_threshold and rates["error_rate_pct"] >= args.error_threshold:
            alerts.append(f"ALERT [{snap.name}] error rate {rates['error_rate_pct']:.4f}% >= {args.error_threshold}%")

    for alert in alerts:
        log.warning(alert)


def poll_once(session, host, args, prev_map):
    raw_list = fetch_interfaces(session, host, args.filter)
    snapshots = [parse_snapshot(r) for r in raw_list]

    if args.format == "json":
        out = []
        for snap in snapshots:
            entry = snap.__dict__.copy()
            prev = prev_map.get(snap.name)
            if prev:
                entry["rates"] = compute_rates(prev, snap)
            out.append(entry)
        print(json.dumps(out, indent=2))
    else:
        print_table(snapshots, prev_map, args)

    return {s.name: s for s in snapshots}


def main():
    parser = argparse.ArgumentParser(description="RESTCONF interface statistics monitor for IOS-XE")
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--user", required=True, help="RESTCONF username")
    parser.add_argument("--password", required=True, help="RESTCONF password")
    parser.add_argument("--filter", metavar="PATTERN", help="Filter interfaces by name substring (e.g. GigabitEthernet)")
    parser.add_argument("--interval", type=int, default=0, help="Poll interval in seconds (0 = single shot)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds")
    parser.add_argument("--util-threshold", type=float, metavar="PCT", help="Alert when utilization exceeds this percentage")
    parser.add_argument("--error-threshold", type=float, metavar="PCT", help="Alert when error rate exceeds this percentage")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    session = build_session(args.user, args.password, args.timeout)
    prev_map = {}

    if args.interval > 0:
        log.info("Polling %s every %ds — Ctrl-C to stop", args.host, args.interval)
        try:
            while True:
                prev_map = poll_once(session, args.host, args, prev_map)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            log.info("Stopped.")
    else:
        log.info("Baseline poll (rates require a second poll via --interval)")
        poll_once(session, args.host, args, prev_map)


if __name__ == "__main__":
    main()
```