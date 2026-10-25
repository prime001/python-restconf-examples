The user wants a standalone script output. Writing the BGP neighbor monitoring script now — this focuses on operational state health checking via RESTCONF, which is distinct from the basic bgp_config scripts already in the repo.

```python
"""
BGP Neighbor State Monitor via RESTCONF
=======================================
Queries BGP neighbor operational state from Cisco IOS-XE devices using RESTCONF
and the Cisco-IOS-XE-bgp-oper YANG model. Useful for health checks, alerting on
downed sessions, and auditing prefix counts across neighbors.

Usage:
    python 034_bgp_neighbor_monitor.py --host 192.168.1.1 --user admin --password secret
    python 034_bgp_neighbor_monitor.py --host 192.168.1.1 -u admin -p secret --vrf MGMT
    python 034_bgp_neighbor_monitor.py --host 192.168.1.1 -u admin -p secret --alert-only
    python 034_bgp_neighbor_monitor.py --host 192.168.1.1 -u admin -p secret --json

Prerequisites:
    - IOS-XE 16.6+ with RESTCONF enabled (ip http secure-server, restconf)
    - Valid credentials with at least read privilege (level 1)
    - pip install requests
"""

import argparse
import json
import logging
import sys
from datetime import timedelta

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RESTCONF_BASE = "https://{host}/restconf/data"
BGP_OPER_PATH = "/Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors"
HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}
ESTABLISHED = "fsm-established"

log = logging.getLogger(__name__)


def build_session(user: str, password: str, timeout: int) -> requests.Session:
    session = requests.Session()
    session.auth = (user, password)
    session.headers.update(HEADERS)
    session.verify = False
    session.timeout = timeout
    return session


def fetch_neighbors(session: requests.Session, host: str) -> list[dict]:
    url = RESTCONF_BASE.format(host=host) + BGP_OPER_PATH
    log.debug("GET %s", url)
    try:
        resp = session.get(url)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        log.error("Cannot reach %s — check connectivity and RESTCONF config", host)
        sys.exit(1)
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP %s from %s: %s", exc.response.status_code, host, exc.response.text[:200])
        sys.exit(1)
    except requests.exceptions.Timeout:
        log.error("Request to %s timed out", host)
        sys.exit(1)

    data = resp.json()
    wrapper = data.get("Cisco-IOS-XE-bgp-oper:neighbors", {})
    return wrapper.get("neighbor", [])


def format_uptime(seconds: int) -> str:
    if seconds < 0:
        return "never"
    return str(timedelta(seconds=seconds))


def summarize_neighbor(n: dict) -> dict:
    conn = n.get("connection", {})
    prefixes = n.get("prefix-activity", {}).get("received", {})
    return {
        "neighbor": n.get("neighbor-id", "unknown"),
        "vrf": n.get("vrf-name", "default"),
        "as": n.get("remote-as", "?"),
        "state": conn.get("state", "unknown"),
        "established": conn.get("state", "") == ESTABLISHED,
        "uptime_sec": conn.get("up-time", -1),
        "prefixes_received": prefixes.get("current-prefixes", 0),
        "prefixes_best": prefixes.get("best-paths", 0),
    }


def print_table(summaries: list[dict]) -> None:
    fmt = "{:<18} {:<12} {:<8} {:<15} {:<12} {:<10} {:<10}"
    print(fmt.format("Neighbor", "VRF", "AS", "State", "Uptime", "Rcvd", "Best"))
    print("-" * 85)
    for s in summaries:
        uptime = format_uptime(s["uptime_sec"]) if s["established"] else "-"
        print(fmt.format(
            s["neighbor"], s["vrf"], s["as"],
            s["state"], uptime,
            s["prefixes_received"], s["prefixes_best"],
        ))


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor BGP neighbor state via RESTCONF")
    parser.add_argument("--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--user", required=True, help="RESTCONF username")
    parser.add_argument("-p", "--password", required=True, help="RESTCONF password")
    parser.add_argument("--port", type=int, default=443, help="RESTCONF port (default 443)")
    parser.add_argument("--vrf", help="Filter by VRF name")
    parser.add_argument("--neighbor", help="Filter by neighbor IP")
    parser.add_argument("--alert-only", action="store_true", help="Show only non-established sessions")
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output as JSON")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    host_port = f"{args.host}:{args.port}" if args.port != 443 else args.host
    session = build_session(args.user, args.password, args.timeout)
    raw = fetch_neighbors(session, host_port)

    if not raw:
        log.info("No BGP neighbors found on %s", args.host)
        sys.exit(0)

    summaries = [summarize_neighbor(n) for n in raw]

    if args.vrf:
        summaries = [s for s in summaries if s["vrf"].lower() == args.vrf.lower()]
    if args.neighbor:
        summaries = [s for s in summaries if s["neighbor"] == args.neighbor]
    if args.alert_only:
        summaries = [s for s in summaries if not s["established"]]

    if not summaries:
        log.info("No neighbors match the given filters")
        sys.exit(0)

    down_count = sum(1 for s in summaries if not s["established"])

    if args.output_json:
        print(json.dumps(summaries, indent=2))
    else:
        print(f"\nBGP Neighbors on {args.host}  ({len(summaries)} shown, {down_count} down)\n")
        print_table(summaries)
        print()

    if down_count:
        log.warning("%d neighbor(s) not in Established state", down_count)
        sys.exit(2)


if __name__ == "__main__":
    main()
```