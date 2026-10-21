021_static_route_management.py - Bulk static route management via RESTCONF

Purpose:
    Manage IPv4 static routes on Cisco IOS-XE devices using RESTCONF.
    Supports listing, adding, and removing routes individually or in bulk
    from a JSON file. Useful for provisioning summary routes, black-holes,
    and management-plane routes across a fleet without touching the CLI.

Usage:
    # List all configured static routes
    python 021_static_route_management.py --host 192.168.1.1 --list

    # Add a single static route
    python 021_static_route_management.py --host 192.168.1.1 \
        --add --prefix 10.0.0.0 --mask 255.255.255.0 --nexthop 192.168.1.254

    # Bulk-load routes from a JSON file
    python 021_static_route_management.py --host 192.168.1.1 \
        --bulk-add routes.json

    # Remove a static route
    python 021_static_route_management.py --host 192.168.1.1 \
        --remove --prefix 10.0.0.0 --mask 255.255.255.0 --nexthop 192.168.1.254

Prerequisites:
    - Cisco IOS-XE 16.6+ with RESTCONF enabled:
        ip http secure-server
        restconf
    - pip install requests
    - User with privilege level 15
    - Bulk JSON format: list of {"prefix","mask","nexthop"[,"name","distance"]}
"""

import argparse
import json
import logging
import sys
from typing import Optional

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

ROUTE_PATH = "Cisco-IOS-XE-native:native/ip/route"
HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}


def make_session(username: str, password: str) -> requests.Session:
    s = requests.Session()
    s.auth = HTTPBasicAuth(username, password)
    s.headers.update(HEADERS)
    s.verify = False
    return s


def base_url(host: str, port: int) -> str:
    return f"https://{host}:{port}/restconf/data"


def get_routes(session: requests.Session, base: str) -> Optional[dict]:
    try:
        resp = session.get(f"{base}/{ROUTE_PATH}", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP %s fetching routes", exc.response.status_code)
    except requests.exceptions.ConnectionError:
        log.error("Cannot reach device at %s", base)
    except requests.exceptions.Timeout:
        log.error("Request timed out")
    return None


def list_routes(session: requests.Session, base: str) -> None:
    data = get_routes(session, base)
    if data is None:
        return

    fwd_list = (
        data.get("Cisco-IOS-XE-native:route", {})
        .get("ip-route-interface-forwarding-list", [])
    )
    if not fwd_list:
        log.info("No static routes configured")
        return

    print(f"\n{'Prefix':<20} {'Mask':<18} {'Next-Hop':<18} {'AD':<5} {'Name'}")
    print("-" * 78)
    for entry in fwd_list:
        prefix = entry.get("prefix", "")
        mask = entry.get("mask", "")
        for fwd in entry.get("fwd-list", []):
            nexthop = fwd.get("fwd", "")
            distance = str(fwd.get("metric", ""))
            name = fwd.get("name", "")
            print(f"{prefix:<20} {mask:<18} {nexthop:<18} {distance:<5} {name}")
    print()


def add_route(
    session: requests.Session,
    base: str,
    prefix: str,
    mask: str,
    nexthop: str,
    name: str = "",
    distance: Optional[int] = None,
) -> bool:
    fwd_entry: dict = {"fwd": nexthop}
    if name:
        fwd_entry["name"] = name
    if distance is not None:
        fwd_entry["metric"] = distance

    payload = {
        "Cisco-IOS-XE-native:route": {
            "ip-route-interface-forwarding-list": [
                {"prefix": prefix, "mask": mask, "fwd-list": [fwd_entry]}
            ]
        }
    }
    try:
        resp = session.patch(f"{base}/{ROUTE_PATH}", json=payload, timeout=10)
        resp.raise_for_status()
        log.info("Added: %s %s via %s", prefix, mask, nexthop)
        return True
    except requests.exceptions.HTTPError as exc:
        log.error("Failed to add %s %s: HTTP %s", prefix, mask, exc.response.status_code)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
        log.error("Transport error adding %s %s: %s", prefix, mask, exc)
    return False


def remove_route(
    session: requests.Session,
    base: str,
    prefix: str,
    mask: str,
    nexthop: str,
) -> bool:
    url = (
        f"{base}/{ROUTE_PATH}"
        f"/ip-route-interface-forwarding-list={prefix},{mask}"
        f"/fwd-list={nexthop}"
    )
    try:
        resp = session.delete(url, timeout=10)
        resp.raise_for_status()
        log.info("Removed: %s %s via %s", prefix, mask, nexthop)
        return True
    except requests.exceptions.HTTPError as exc:
        code = exc.response.status_code
        if code == 404:
            log.warning("Route not found: %s %s via %s", prefix, mask, nexthop)
        else:
            log.error("Failed to remove %s %s: HTTP %s", prefix, mask, code)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
        log.error("Transport error removing %s %s: %s", prefix, mask, exc)
    return False


def bulk_add(session: requests.Session, base: str, filepath: str) -> None:
    try:
        with open(filepath) as fh:
            routes = json.load(fh)
    except FileNotFoundError:
        log.error("File not found: %s", filepath)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        log.error("Invalid JSON in %s: %s", filepath, exc)
        sys.exit(1)

    success = failed = 0
    for r in routes:
        ok = add_route(
            session, base,
            r["prefix"], r["mask"], r["nexthop"],
            r.get("name", ""), r.get("distance"),
        )
        if ok:
            success += 1
        else:
            failed += 1

    log.info("Bulk complete — added: %d  failed: %d", success, failed)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Manage IOS-XE static routes via RESTCONF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--host", required=True, help="Device hostname or IP")
    p.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    p.add_argument("--username", "-u", default="admin", help="RESTCONF username")
    p.add_argument("--password", "-p", default="admin", help="RESTCONF password")
    p.add_argument("--debug", action="store_true", help="Enable DEBUG logging")

    action = p.add_mutually_exclusive_group(required=True)
    action.add_argument("--list", action="store_true", help="List static routes")
    action.add_argument("--add", action="store_true", help="Add a static route")
    action.add_argument("--remove", action="store_true", help="Remove a static route")
    action.add_argument("--bulk-add", metavar="FILE", help="Add routes from JSON file")

    p.add_argument("--prefix", help="Network address (e.g. 10.0.0.0)")
    p.add_argument("--mask", help="Subnet mask (e.g. 255.255.255.0)")
    p.add_argument("--nexthop", help="Next-hop IP or interface")
    p.add_argument("--name", default="", help="Route name/description tag")
    p.add_argument("--distance", type=int, help="Administrative distance (1-255)")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if (args.add or args.remove) and not all([args.prefix, args.mask, args.nexthop]):
        print("error: --add and --remove require --prefix, --mask, and --nexthop")
        sys.exit(1)

    session = make_session(args.username, args.password)
    base = base_url(args.host, args.port)

    if args.list:
        list_routes(session, base)
    elif args.add:
        sys.exit(0 if add_route(session, base, args.prefix, args.mask,
                                args.nexthop, args.name, args.distance) else 1)
    elif args.remove:
        sys.exit(0 if remove_route(session, base, args.prefix, args.mask,
                                   args.nexthop) else 1)
    elif args.bulk_add:
        bulk_add(session, base, args.bulk_add)