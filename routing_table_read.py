The user has provided complete, explicit specs and instructed "Output ONLY the script content, no markdown fences, no explanation." That user instruction overrides the brainstorming workflow. Writing the script now.

#!/usr/bin/env python3
"""
007_routing_table.py — Read and display the IP routing table via RESTCONF.

Purpose:
    Query IPv4 or IPv6 routing table entries from Cisco IOS-XE devices using
    the IETF routing YANG model over RESTCONF. Supports filtering by protocol
    or destination prefix and can output a formatted table or raw JSON.

Usage:
    python 007_routing_table.py --device 192.168.1.1 --user admin --password cisco
    python 007_routing_table.py --device 192.168.1.1 --user admin --password cisco \\
        --rib ipv6-unicast --protocol ospf
    python 007_routing_table.py --device 192.168.1.1 --user admin --password cisco \\
        --prefix 10.0.0.0/8 --json

Prerequisites:
    pip install requests
    IOS-XE 16.6+ with RESTCONF enabled:
        ip http secure-server
        restconf
    Credentials with privilege 1+ (read access to ietf-routing data).
"""

import argparse
import json
import logging
import sys
from ipaddress import ip_network
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
    level=logging.WARNING,
)
log = logging.getLogger(__name__)

_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}
_RIB_PATH = "ietf-routing:routing/ribs/rib={rib}/routes"


def _url(device: str, port: int, path: str) -> str:
    return f"https://{device}:{port}/restconf/data/{path}"


def fetch_routes(
    device: str,
    username: str,
    password: str,
    port: int = 443,
    rib: str = "ipv4-unicast",
) -> Optional[dict]:
    url = _url(device, port, _RIB_PATH.format(rib=rib))
    log.debug("GET %s", url)
    try:
        resp = requests.get(
            url,
            auth=HTTPBasicAuth(username, password),
            headers=_HEADERS,
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        log.error("Cannot connect to %s:%s — check host and port", device, port)
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code
        if status == 401:
            log.error("Authentication failed — verify credentials")
        elif status == 404:
            log.error("RIB '%s' not found — device may not support ietf-routing YANG", rib)
        else:
            log.error("HTTP %s from %s", status, device)
    except requests.exceptions.Timeout:
        log.error("Request to %s timed out", device)
    return None


def parse_routes(data: dict) -> list[dict]:
    return data.get("ietf-routing:routes", {}).get("route", [])


def _prefix_within(dest: str, target: "ip_network") -> bool:
    try:
        net = ip_network(dest, strict=False)
        return net == target or net.subnet_of(target)
    except (ValueError, TypeError):
        return False


def filter_routes(
    routes: list[dict],
    protocol: Optional[str] = None,
    prefix: Optional[str] = None,
) -> list[dict]:
    result = routes

    if protocol:
        needle = protocol.lower()
        result = [r for r in result if needle in r.get("source-protocol", "").lower()]

    if prefix:
        try:
            target = ip_network(prefix, strict=False)
            result = [r for r in result if _prefix_within(r.get("destination-prefix", ""), target)]
        except ValueError:
            log.error("Invalid prefix '%s' — skipping prefix filter", prefix)

    return result


def print_table(routes: list[dict]) -> None:
    if not routes:
        print("No matching routes.")
        return

    rows = []
    for r in routes:
        dest = r.get("destination-prefix", "—")
        proto = r.get("source-protocol", "—")
        nh_block = r.get("next-hop", {})
        next_hop = nh_block.get("next-hop-address") or nh_block.get("outgoing-interface", "—")
        metric = str(r.get("route-preference", "—"))
        rows.append((dest, proto, next_hop, metric))

    headers = ("Destination", "Protocol", "Next-Hop", "Metric")
    widths = [max(len(h), max(len(row[i]) for row in rows)) for i, h in enumerate(headers)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)

    print(fmt.format(*headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt.format(*row))
    print(f"\n{len(rows)} route(s) displayed.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read IP routing table from IOS-XE via RESTCONF",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--device", required=True, help="Device hostname or IP address")
    p.add_argument("--user", required=True, help="RESTCONF username")
    p.add_argument("--password", required=True, help="RESTCONF password")
    p.add_argument("--port", type=int, default=443, help="HTTPS port")
    p.add_argument(
        "--rib",
        default="ipv4-unicast",
        choices=["ipv4-unicast", "ipv6-unicast"],
        help="Routing information base to query",
    )
    p.add_argument(
        "--protocol",
        metavar="PROTO",
        help="Filter by source protocol, e.g. ospf, bgp, connected, static",
    )
    p.add_argument(
        "--prefix",
        metavar="NET/LEN",
        help="Show only routes within this supernet, e.g. 10.0.0.0/8",
    )
    p.add_argument("--json", dest="json_out", action="store_true", help="Emit raw JSON")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    data = fetch_routes(args.device, args.user, args.password, args.port, args.rib)
    if data is None:
        return 1

    routes = parse_routes(data)
    routes = filter_routes(routes, protocol=args.protocol, prefix=args.prefix)

    if args.json_out:
        print(json.dumps(routes, indent=2))
    else:
        print_table(routes)

    return 0


if __name__ == "__main__":
    sys.exit(main())