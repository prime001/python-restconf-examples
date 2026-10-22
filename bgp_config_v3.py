```python
"""
024_bgp_config.py - BGP Neighbor Health Monitor via RESTCONF

Purpose:
    Query BGP neighbor operational state from Cisco IOS-XE devices using
    RESTCONF. Reports session state, uptime, prefix counts, and notification
    counts. Exits non-zero when any session is not Established — suitable
    for use in monitoring scripts or CI pre-deployment checks.

Usage:
    python 024_bgp_config.py --host 192.168.1.1 --user admin --password secret
    python 024_bgp_config.py --host 192.168.1.1 --user admin --password secret \
        --neighbor 10.0.0.2
    python 024_bgp_config.py --host 192.168.1.1 --user admin --password secret \
        --as 65001 --json
    python 024_bgp_config.py --host 192.168.1.1 --user admin --password secret \
        --verbose

Prerequisites:
    - IOS-XE 16.6+ with RESTCONF enabled:
        ip http secure-server
        restconf
    - User account with privilege 15 or the netconf-yang role
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

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}
_BGP_OPER_PATH = "data/Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors"
_ESTABLISHED = "fsm-established"


def _build_session(username: str, password: str) -> requests.Session:
    s = requests.Session()
    s.auth = (username, password)
    s.headers.update(_HEADERS)
    s.verify = False
    return s


def _fetch_neighbors(session: requests.Session, host: str, port: int) -> list:
    url = f"https://{host}:{port}/restconf/{_BGP_OPER_PATH}"
    log.debug("GET %s", url)
    try:
        resp = session.get(url, timeout=15)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError as exc:
        log.error("Cannot reach %s:%s — %s", host, port, exc)
        sys.exit(1)
    except requests.exceptions.HTTPError:
        log.error("HTTP %s from %s: %s", resp.status_code, host, resp.text[:300])
        sys.exit(1)

    payload = resp.json()
    neighbors = payload.get("Cisco-IOS-XE-bgp-oper:neighbors", {})
    return neighbors.get("neighbor", [])


def _seconds_to_uptime(seconds) -> str:
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return "—"
    if seconds < 0:
        return "never"
    td = timedelta(seconds=seconds)
    h, rem = divmod(td.seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{td.days}d {h:02d}h {m:02d}m" if td.days else f"{h:02d}h {m:02d}m {s:02d}s"


def _parse(raw: dict) -> dict:
    counters = raw.get("bgp-neighbor-counters", {})
    sent = counters.get("sent", {})
    recv = counters.get("received", {})
    return {
        "neighbor": raw.get("neighbor-id", "unknown"),
        "remote_as": raw.get("as", "?"),
        "state": raw.get("session-state", "unknown"),
        "up_time": raw.get("up-time", -1),
        "prefixes_rx": recv.get("prefixes", 0),
        "prefixes_tx": sent.get("prefixes", 0),
        "notif_rx": recv.get("notifications", 0),
        "notif_tx": sent.get("notifications", 0),
        "description": raw.get("description", ""),
    }


def _filter(neighbors: list, neighbor_ip: str, remote_as: str) -> list:
    out = []
    for raw in neighbors:
        n = _parse(raw)
        if neighbor_ip and n["neighbor"] != neighbor_ip:
            continue
        if remote_as and str(n["remote_as"]) != str(remote_as):
            continue
        out.append(n)
    return out


def _print_table(neighbors: list) -> int:
    if not neighbors:
        print("No BGP neighbors match the specified filter.")
        return 0

    W = {"addr": 18, "as": 8, "state": 15, "up": 15, "prx": 7, "ptx": 7, "notif": 7}
    hdr = (
        f"{'Neighbor':<{W['addr']}} {'RemoteAS':<{W['as']}} {'State':<{W['state']}} "
        f"{'Uptime':<{W['up']}} {'Pfx/Rx':<{W['prx']}} {'Pfx/Tx':<{W['ptx']}} "
        f"{'Notif':<{W['notif']}} Description"
    )
    print(hdr)
    print("—" * len(hdr))

    degraded = 0
    for n in neighbors:
        established = n["state"] == _ESTABLISHED
        if not established:
            degraded += 1
        uptime = _seconds_to_uptime(n["up_time"]) if established else "—"
        notif = n["notif_rx"] + n["notif_tx"]
        flag = " !" if not established else ""
        print(
            f"{n['neighbor']:<{W['addr']}} {n['remote_as']:<{W['as']}} "
            f"{n['state']:<{W['state']}} {uptime:<{W['up']}} "
            f"{n['prefixes_rx']:<{W['prx']}} {n['prefixes_tx']:<{W['ptx']}} "
            f"{notif:<{W['notif']}} {n['description']}{flag}"
        )

    if degraded:
        print(f"\nWARNING: {degraded} session(s) not Established  [marked !]")
    return degraded


def main():
    parser = argparse.ArgumentParser(
        description="BGP neighbor health monitor via RESTCONF (IOS-XE)"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--user", required=True, help="RESTCONF username")
    parser.add_argument("--password", required=True, help="RESTCONF password")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument("--neighbor", metavar="IP", help="Filter output to a single neighbor IP")
    parser.add_argument("--as", dest="remote_as", metavar="ASN", help="Filter by remote AS number")
    parser.add_argument("--json", dest="json_out", action="store_true",
                        help="Emit JSON instead of a table (useful for piping)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    session = _build_session(args.user, args.password)
    raw = _fetch_neighbors(session, args.host, args.port)

    if not raw:
        print("Device returned no BGP neighbor data. Is BGP configured and running?")
        sys.exit(0)

    neighbors = _filter(raw, args.neighbor, args.remote_as)

    if args.json_out:
        print(json.dumps(neighbors, indent=2))
        sys.exit(0)

    degraded = _print_table(neighbors)
    sys.exit(1 if degraded else 0)


if __name__ == "__main__":
    main()
```