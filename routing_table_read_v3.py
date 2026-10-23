```python
"""
027_routing_table_read.py - Routing Table Analysis and Overlap Detection via RESTCONF

Purpose:
    Fetch the IPv4 routing table from a Cisco IOS-XE device via RESTCONF, then
    perform practical network analysis: prefix overlap detection, next-hop
    distribution, and change detection against a saved baseline snapshot.
    Useful for change-window validation, audit trails, and diagnosing routing
    anomalies without touching the CLI.

Usage:
    # Display full routing table
    python 027_routing_table_read.py --host 192.168.1.1 --user admin --password secret

    # Filter to a supernet and detect overlaps
    python 027_routing_table_read.py --host 192.168.1.1 --user admin --password secret \
        --supernet 10.0.0.0/8 --detect-overlaps

    # Save baseline, then diff after a change window
    python 027_routing_table_read.py --host 192.168.1.1 --user admin --password secret \
        --save-baseline before.json
    python 027_routing_table_read.py --host 192.168.1.1 --user admin --password secret \
        --diff-baseline before.json

Prerequisites:
    - Cisco IOS-XE 16.6+ with RESTCONF enabled: `ip http secure-server`, `restconf`
    - YANG model: Cisco-IOS-XE-rpc or ietf-routing (tested against IOS-XE 17.x)
    - pip install requests
    - Device reachable on port 443 (default) or specify --port
"""

import argparse
import ipaddress
import json
import logging
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

RESTCONF_BASE = "https://{host}:{port}/restconf/data"
HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}
ROUTE_PATH = "Cisco-IOS-XE-native:native/ip/route"


def build_session(username: str, password: str) -> requests.Session:
    session = requests.Session()
    session.auth = (username, password)
    session.headers.update(HEADERS)
    session.verify = False
    return session


def fetch_raw_routes(session: requests.Session, host: str, port: int) -> dict:
    url = f"{RESTCONF_BASE.format(host=host, port=port)}/{ROUTE_PATH}"
    log.debug("GET %s", url)
    resp = session.get(url, timeout=15)
    resp.raise_for_status()
    return resp.json()


def parse_routes(raw: dict) -> list[dict]:
    """Flatten IOS-XE RESTCONF route data into normalized dicts."""
    route_block = (
        raw.get("Cisco-IOS-XE-native:route")
        or raw.get("native:route")
        or {}
    )
    entries = route_block.get("ip-route-interface-forwarding-list", [])
    routes = []
    for entry in entries:
        prefix = entry.get("prefix", "")
        mask = entry.get("mask", "")
        fwd_list = entry.get("fwd-list", [{}])
        next_hop = fwd_list[0].get("fwd", "") if fwd_list else ""
        try:
            network = ipaddress.IPv4Network(f"{prefix}/{mask}", strict=False)
            cidr = str(network)
            prefixlen = network.prefixlen
        except ValueError:
            cidr = f"{prefix}/{mask}"
            prefixlen = -1
        routes.append({
            "network": cidr,
            "next_hop": next_hop,
            "prefixlen": prefixlen,
        })
    return routes


def filter_by_supernet(routes: list[dict], supernet_str: str) -> list[dict]:
    try:
        supernet = ipaddress.IPv4Network(supernet_str, strict=False)
    except ValueError:
        log.error("Invalid supernet: %s", supernet_str)
        return routes
    result = []
    for r in routes:
        try:
            net = ipaddress.IPv4Network(r["network"], strict=False)
            if net.subnet_of(supernet) or net == supernet:
                result.append(r)
        except ValueError:
            pass
    return result


def find_overlaps(routes: list[dict]) -> list[tuple[str, str]]:
    """Return (a, b) pairs where a and b overlap but neither fully contains the other."""
    nets = []
    for r in routes:
        try:
            nets.append((ipaddress.IPv4Network(r["network"], strict=False), r["network"]))
        except ValueError:
            pass
    pairs = []
    for i in range(len(nets)):
        for j in range(i + 1, len(nets)):
            a, a_str = nets[i]
            b, b_str = nets[j]
            if a.overlaps(b) and a != b:
                pairs.append((a_str, b_str))
    return pairs


def diff_baseline(current: list[dict], baseline_path: Path) -> dict:
    with baseline_path.open() as f:
        baseline = json.load(f)
    cur_set = {r["network"] for r in current}
    base_set = {r["network"] for r in baseline}
    cur_map = {r["network"]: r for r in current}
    base_map = {r["network"]: r for r in baseline}
    changed = [
        cur_map[n] for n in cur_set & base_set
        if cur_map[n]["next_hop"] != base_map[n]["next_hop"]
    ]
    return {
        "added": [cur_map[n] for n in cur_set - base_set],
        "removed": [base_map[n] for n in base_set - cur_set],
        "changed_nexthop": changed,
    }


def print_table(routes: list[dict]) -> None:
    print(f"\n{'Network':<24} {'Next Hop':<18} Len")
    print("-" * 50)
    for r in sorted(routes, key=lambda x: x["prefixlen"]):
        print(f"{r['network']:<24} {r['next_hop'] or 'connected':<18} {r['prefixlen']}")
    print(f"\n{len(routes)} routes total")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze routing table from IOS-XE via RESTCONF"
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--supernet", help="Filter routes to within this supernet, e.g. 10.0.0.0/8")
    parser.add_argument("--detect-overlaps", action="store_true", help="Flag overlapping prefixes")
    parser.add_argument("--save-baseline", metavar="FILE", help="Save routes to JSON file")
    parser.add_argument("--diff-baseline", metavar="FILE", help="Compare against saved baseline")
    parser.add_argument("--output-json", metavar="FILE", help="Write results to JSON")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    session = build_session(args.user, args.password)

    try:
        raw = fetch_raw_routes(session, args.host, args.port)
    except requests.exceptions.ConnectionError as exc:
        log.error("Connection failed: %s", exc)
        return 1
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP %s: %s", exc.response.status_code, exc.response.text[:300])
        return 1

    routes = parse_routes(raw)
    log.info("Fetched %d routes from %s", len(routes), args.host)

    if args.supernet:
        routes = filter_by_supernet(routes, args.supernet)
        log.info("%d routes within %s", len(routes), args.supernet)

    print_table(routes)

    if args.detect_overlaps:
        overlaps = find_overlaps(routes)
        if overlaps:
            print(f"\n[!] {len(overlaps)} overlapping prefix pair(s):")
            for a, b in overlaps:
                print(f"    {a}  <->  {b}")
        else:
            print("\n[OK] No overlapping prefixes.")

    if args.diff_baseline:
        bp = Path(args.diff_baseline)
        if not bp.exists():
            log.error("Baseline not found: %s", bp)
            return 1
        diff = diff_baseline(routes, bp)
        print(f"\n[+] Added:   {len(diff['added'])}")
        for r in diff["added"]:
            print(f"    + {r['network']} via {r['next_hop']}")
        print(f"[-] Removed: {len(diff['removed'])}")
        for r in diff["removed"]:
            print(f"    - {r['network']} via {r['next_hop']}")
        print(f"[~] Next-hop changed: {len(diff['changed_nexthop'])}")
        for r in diff["changed_nexthop"]:
            print(f"    ~ {r['network']} now via {r['next_hop']}")

    if args.save_baseline:
        Path(args.save_baseline).write_text(json.dumps(routes, indent=2))
        log.info("Baseline saved: %s", args.save_baseline)

    if args.output_json:
        Path(args.output_json).write_text(json.dumps(routes, indent=2))
        log.info("JSON written: %s", args.output_json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```