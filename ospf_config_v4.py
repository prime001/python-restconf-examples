The repo context is clear — this is a code generation request for an external portfolio repo. Writing the script now.

```python
"""
OSPF Neighbor Adjacency Monitor via RESTCONF

Purpose:
    Queries a Cisco IOS-XE device over RESTCONF to retrieve live OSPF neighbor
    state, surfaces any non-FULL adjacencies, and exits non-zero when problems
    are found — making it suitable for monitoring pipelines and CI health checks.

Usage:
    python 035_ospf_neighbor_monitor.py --device 192.168.1.1 \
        --username admin --password secret

    python 035_ospf_neighbor_monitor.py --device 192.168.1.1 \
        --username admin --password secret \
        --process-id 1 --json --fail-on-non-full

Prerequisites:
    - IOS-XE 16.6+ with RESTCONF enabled  (ip restconf / restconf)
    - YANG model available: Cisco-IOS-XE-ospf-oper
    - pip install requests
    - Device reachable on port 443 (override with --port)
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

RESTCONF_BASE = "https://{host}:{port}/restconf/data"
NEIGHBOR_PATH = (
    "/Cisco-IOS-XE-ospf-oper:ospf-oper-data/ospf-neighbor-detail"
)


@dataclass
class OspfNeighbor:
    neighbor_id: str
    ip_address: str
    interface: str
    state: str
    process_id: int
    area_id: str
    priority: int
    dead_timer: str

    @property
    def is_full(self) -> bool:
        return self.state.upper() == "FULL"


def build_session(username: str, password: str, timeout: int) -> requests.Session:
    s = requests.Session()
    s.auth = (username, password)
    s.headers.update({
        "Accept": "application/yang-data+json",
        "Content-Type": "application/yang-data+json",
    })
    s.verify = False
    s.timeout = timeout
    return s


def fetch_neighbors(
    session: requests.Session,
    base_url: str,
    process_id: Optional[int],
) -> list:
    url = base_url + NEIGHBOR_PATH
    log.debug("GET %s", url)
    try:
        resp = session.get(url)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as exc:
        log.error("Connection failed to %s: %s", url, exc)
        sys.exit(2)
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP %s from %s: %s", resp.status_code, url, exc)
        sys.exit(2)

    raw = resp.json().get(
        "Cisco-IOS-XE-ospf-oper:ospf-neighbor-detail", []
    )

    neighbors = []
    for entry in raw:
        pid = entry.get("process-id", 0)
        if process_id is not None and pid != process_id:
            continue
        detail = entry.get("neighbor-detail", {})
        neighbors.append(OspfNeighbor(
            neighbor_id=entry.get("neighbor-id", ""),
            ip_address=entry.get("neighbor-address", ""),
            interface=entry.get("interface", ""),
            state=detail.get("state", "unknown"),
            process_id=pid,
            area_id=entry.get("area-id", ""),
            priority=detail.get("priority", 0),
            dead_timer=detail.get("dead-timer", ""),
        ))

    log.debug("Found %d neighbor(s) after process filter", len(neighbors))
    return neighbors


def print_table(neighbors: list, device: str) -> None:
    total = len(neighbors)
    full_count = sum(1 for n in neighbors if n.is_full)
    non_full = [n for n in neighbors if not n.is_full]

    print(f"\nOSPF Neighbor Report  —  {device}")
    print("=" * 70)
    print(f"  Total : {total}")
    print(f"  FULL  : {full_count}")
    print(f"  Other : {len(non_full)}")
    print()

    if not neighbors:
        print("  No OSPF neighbors found.")
        return

    header = f"{'Neighbor ID':<18} {'Address':<16} {'Interface':<22} {'State':<14} {'Area':<12} PID"
    print(header)
    print("-" * len(header))
    for n in neighbors:
        flag = "" if n.is_full else "  !"
        print(
            f"{n.neighbor_id:<18} {n.ip_address:<16} {n.interface:<22}"
            f" {n.state:<14} {n.area_id:<12} {n.process_id}{flag}"
        )

    if non_full:
        print(f"\n[WARN] {len(non_full)} non-FULL adjacency(ies) detected:")
        for n in non_full:
            print(f"  - {n.neighbor_id} on {n.interface} is {n.state!r}"
                  f"  (dead timer: {n.dead_timer or 'n/a'})")


def print_json_report(neighbors: list, device: str) -> None:
    total = len(neighbors)
    full_count = sum(1 for n in neighbors if n.is_full)
    report = {
        "device": device,
        "summary": {
            "total": total,
            "full": full_count,
            "non_full": total - full_count,
            "healthy": full_count == total and total > 0,
        },
        "neighbors": [
            {
                "neighbor_id": n.neighbor_id,
                "ip_address": n.ip_address,
                "interface": n.interface,
                "state": n.state,
                "is_full": n.is_full,
                "area_id": n.area_id,
                "process_id": n.process_id,
                "priority": n.priority,
                "dead_timer": n.dead_timer,
            }
            for n in neighbors
        ],
    }
    print(json.dumps(report, indent=2))


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Monitor OSPF neighbor adjacency states via RESTCONF"
    )
    p.add_argument("--device", required=True, help="Device IP or FQDN")
    p.add_argument("--username", required=True, help="RESTCONF username")
    p.add_argument("--password", required=True, help="RESTCONF password")
    p.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    p.add_argument("--process-id", type=int, metavar="PID",
                   help="Filter results to a specific OSPF process ID")
    p.add_argument("--json", action="store_true", dest="json_output",
                   help="Emit JSON instead of a human-readable table")
    p.add_argument("--fail-on-non-full", action="store_true",
                   help="Exit with status 1 if any neighbor is not FULL")
    p.add_argument("--timeout", type=int, default=10,
                   help="Per-request timeout in seconds (default: 10)")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
    )

    session = build_session(args.username, args.password, args.timeout)
    base_url = RESTCONF_BASE.format(host=args.device, port=args.port)

    neighbors = fetch_neighbors(session, base_url, process_id=args.process_id)

    if args.json_output:
        print_json_report(neighbors, args.device)
    else:
        print_table(neighbors, args.device)

    if args.fail_on_non_full and any(not n.is_full for n in neighbors):
        sys.exit(1)
```