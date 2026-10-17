```python
"""
015_ospf_config.py — OSPF Neighbor Adjacency Monitor

Queries OSPF operational state via RESTCONF and reports on neighbor
adjacency health. Flags non-FULL adjacencies and provides per-area,
per-interface neighbor breakdowns useful for post-change verification.

Usage:
    python 015_ospf_config.py --host 192.168.1.1 -u admin -p secret
    python 015_ospf_config.py --host 192.168.1.1 -u admin -p secret --process-id 1
    python 015_ospf_config.py --host 192.168.1.1 -u admin -p secret --area 0 --alert-only

Prerequisites:
    - RESTCONF enabled: ip http secure-server + restconf
    - Privilege-15 user or read access to Cisco-IOS-XE-ospf-oper
    - pip install requests
    - Tested against Cisco IOS-XE 16.9+, Python 3.10+

Exit codes:
    0 — all neighbors healthy (or none found)
    1 — connection / HTTP error
    2 — one or more neighbors not in FULL or 2WAY state
"""

import argparse
import logging
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RESTCONF_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}
OSPF_OPER_PATH = "/restconf/data/Cisco-IOS-XE-ospf-oper:ospf-oper-data"
HEALTHY_STATES = {"full", "two-way"}


def setup_logging(verbose: bool) -> logging.Logger:
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG if verbose else logging.INFO,
    )
    return logging.getLogger(__name__)


def fetch_ospf_oper(session: requests.Session, base_url: str) -> dict:
    resp = session.get(f"{base_url}{OSPF_OPER_PATH}", timeout=15)
    resp.raise_for_status()
    return resp.json()


def extract_neighbors(
    ospf_data: dict,
    process_id: int | None,
    area_filter: str | None,
) -> list[dict]:
    neighbors = []
    processes = (
        ospf_data
        .get("Cisco-IOS-XE-ospf-oper:ospf-oper-data", {})
        .get("ospf-state", [])
    )
    for proc in processes:
        pid = proc.get("process-id")
        if process_id is not None and pid != process_id:
            continue
        for area in proc.get("ospf-area", []):
            area_id = str(area.get("area-id", ""))
            if area_filter is not None and area_id != area_filter:
                continue
            for iface in area.get("ospf-interface", []):
                iface_name = iface.get("name", "unknown")
                for nbr in iface.get("ospf-neighbor", []):
                    neighbors.append({
                        "pid": pid,
                        "area": area_id,
                        "interface": iface_name,
                        "neighbor_id": nbr.get("neighbor-id", "?"),
                        "address": nbr.get("address", "?"),
                        "state": nbr.get("state", "unknown"),
                        "dead_timer": nbr.get("dead-timer", "?"),
                        "priority": nbr.get("priority", 0),
                    })
    return neighbors


def render_table(neighbors: list[dict], alert_only: bool) -> int:
    col = "{:<3}{:>7}  {:>16}  {:<22}  {:>15}  {:>15}  {:<12}  {}"
    header = col.format(
        "", "PID", "Area", "Interface", "Neighbor ID", "Address", "State", "Dead"
    )
    print(header)
    print("-" * len(header))

    unhealthy_count = 0
    for nbr in neighbors:
        state_norm = nbr["state"].lower().replace("_", "-")
        healthy = state_norm in HEALTHY_STATES
        if not healthy:
            unhealthy_count += 1
        if alert_only and healthy:
            continue
        flag = "   " if healthy else "!  "
        print(col.format(
            flag,
            nbr["pid"],
            nbr["area"],
            nbr["interface"],
            nbr["neighbor_id"],
            nbr["address"],
            nbr["state"],
            nbr["dead_timer"],
        ))

    return unhealthy_count


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor OSPF neighbor adjacency health via RESTCONF",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", required=True, help="Device hostname or IP")
    p.add_argument("--username", "-u", required=True, help="RESTCONF username")
    p.add_argument("--password", "-p", required=True, help="RESTCONF password")
    p.add_argument("--port", type=int, default=443, help="HTTPS port")
    p.add_argument("--process-id", type=int, default=None, help="Filter by OSPF process ID")
    p.add_argument("--area", default=None, help="Filter by area ID (e.g. 0, 0.0.0.1)")
    p.add_argument("--alert-only", action="store_true", help="Show only non-FULL neighbors")
    p.add_argument("--no-verify", action="store_true", help="Skip TLS certificate validation")
    p.add_argument("--verbose", "-v", action="store_true", help="Debug output")
    return p


def main() -> int:
    args = build_parser().parse_args()
    log = setup_logging(args.verbose)

    base_url = f"https://{args.host}:{args.port}"
    session = requests.Session()
    session.auth = (args.username, args.password)
    session.headers.update(RESTCONF_HEADERS)
    session.verify = not args.no_verify

    log.debug("Querying OSPF operational data from %s", base_url)
    try:
        ospf_data = fetch_ospf_oper(session, base_url)
    except requests.exceptions.ConnectionError as exc:
        log.error("Connection failed: %s", exc)
        return 1
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP %s — %s", exc.response.status_code, exc.response.text[:300])
        return 1

    neighbors = extract_neighbors(ospf_data, args.process_id, args.area)
    if not neighbors:
        log.warning("No OSPF neighbors found — check process-id/area filters")
        return 0

    log.info("Found %d neighbor(s)", len(neighbors))
    print()
    unhealthy = render_table(neighbors, args.alert_only)
    print()

    if unhealthy:
        log.warning("%d neighbor(s) NOT in FULL/2WAY state", unhealthy)
        return 2

    log.info("All neighbors healthy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```