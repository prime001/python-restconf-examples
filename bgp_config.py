BGP Configuration Manager via RESTCONF
=======================================
Purpose:
    Manage BGP neighbors and network advertisements on Cisco IOS-XE devices
    using RESTCONF. Supports listing neighbors, adding/removing peers, and
    controlling which prefixes are originated into BGP.

Usage:
    python 004_bgp_config.py --host 192.168.1.1 -u admin -p secret \
        --local-as 65001 --action list-neighbors

    python 004_bgp_config.py --host 192.168.1.1 -u admin -p secret \
        --local-as 65001 --action add-neighbor \
        --neighbor 10.0.0.2 --remote-as 65002 --description "WAN peer"

    python 004_bgp_config.py --host 192.168.1.1 -u admin -p secret \
        --local-as 65001 --action advertise-network \
        --network 10.1.0.0 --mask 255.255.0.0

    python 004_bgp_config.py --host 192.168.1.1 -u admin -p secret \
        --local-as 65001 --action remove-neighbor --neighbor 10.0.0.2

Prerequisites:
    - Cisco IOS-XE 16.6+ with RESTCONF enabled:
          ip http secure-server
          restconf
    - Credentials with privilege 15 (config write access)
    - BGP process pre-configured with --local-as number on the device
    - pip install requests
"""

import argparse
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

_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}
_BGP_PATH = "restconf/data/Cisco-IOS-XE-native:native/router/bgp"


def _url(host: str, path: str) -> str:
    return f"https://{host}/{path}"


def _get_bgp(session: requests.Session, host: str, local_as: int) -> Optional[dict]:
    try:
        resp = session.get(_url(host, f"{_BGP_PATH}={local_as}"))
        resp.raise_for_status()
        return resp.json()
    except requests.HTTPError as exc:
        log.error("GET BGP AS %d failed (%s): %s", local_as, exc.response.status_code, exc.response.text[:200])
        return None
    except requests.RequestException as exc:
        log.error("Connection error: %s", exc)
        return None


def list_neighbors(session: requests.Session, host: str, local_as: int) -> int:
    data = _get_bgp(session, host, local_as)
    if data is None:
        return 1

    bgp_block = data.get("Cisco-IOS-XE-native:bgp", [{}])
    neighbors = bgp_block[0].get("neighbor", []) if bgp_block else []

    if not neighbors:
        log.info("No neighbors configured under BGP AS %d", local_as)
        return 0

    print(f"\nBGP AS {local_as} — Neighbors")
    print(f"{'Address':<20} {'Remote-AS':<12} Description")
    print("-" * 56)
    for nbr in neighbors:
        print(
            f"{nbr.get('id', '?'):<20}"
            f"{str(nbr.get('remote-as', '—')):<12}"
            f"{nbr.get('description', '')}"
        )
    return 0


def add_neighbor(
    session: requests.Session,
    host: str,
    local_as: int,
    neighbor: str,
    remote_as: int,
    description: str,
) -> int:
    entry: dict = {"id": neighbor, "remote-as": remote_as}
    if description:
        entry["description"] = description

    payload = {"Cisco-IOS-XE-native:neighbor": [entry]}
    url = _url(host, f"{_BGP_PATH}={local_as}/neighbor={neighbor}")
    try:
        resp = session.put(url, json=payload)
        resp.raise_for_status()
        log.info("Neighbor %s AS %d configured under BGP %d", neighbor, remote_as, local_as)
        return 0
    except requests.HTTPError as exc:
        log.error("add-neighbor failed (%s): %s", exc.response.status_code, exc.response.text[:200])
        return 1
    except requests.RequestException as exc:
        log.error("Connection error: %s", exc)
        return 1


def remove_neighbor(
    session: requests.Session, host: str, local_as: int, neighbor: str
) -> int:
    url = _url(host, f"{_BGP_PATH}={local_as}/neighbor={neighbor}")
    try:
        resp = session.delete(url)
        if resp.status_code == 404:
            log.warning("Neighbor %s not found — nothing removed", neighbor)
            return 0
        resp.raise_for_status()
        log.info("Neighbor %s removed from BGP AS %d", neighbor, local_as)
        return 0
    except requests.HTTPError as exc:
        log.error("remove-neighbor failed (%s): %s", exc.response.status_code, exc.response.text[:200])
        return 1
    except requests.RequestException as exc:
        log.error("Connection error: %s", exc)
        return 1


def advertise_network(
    session: requests.Session, host: str, local_as: int, network: str, mask: str
) -> int:
    af_url = _url(host, f"{_BGP_PATH}={local_as}/address-family/with-vrf/ipv4=unicast")
    try:
        resp = session.get(af_url)
        resp.raise_for_status()
        af = resp.json().get("Cisco-IOS-XE-native:ipv4", {})
    except requests.HTTPError as exc:
        log.error("Could not read IPv4 unicast AF (%s): %s", exc.response.status_code, exc.response.text[:200])
        return 1
    except requests.RequestException as exc:
        log.error("Connection error: %s", exc)
        return 1

    entries = af.get("network", {}).get("with-mask", [])
    if any(e.get("number") == network and e.get("mask") == mask for e in entries):
        log.info("Network %s %s is already advertised", network, mask)
        return 0

    entries.append({"number": network, "mask": mask})
    af.setdefault("network", {})["with-mask"] = entries

    try:
        resp = session.put(af_url, json={"Cisco-IOS-XE-native:ipv4": af})
        resp.raise_for_status()
        log.info("Network %s %s added to BGP %d origination", network, mask, local_as)
        return 0
    except requests.HTTPError as exc:
        log.error("advertise-network failed (%s): %s", exc.response.status_code, exc.response.text[:200])
        return 1
    except requests.RequestException as exc:
        log.error("Connection error: %s", exc)
        return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BGP neighbor and prefix management via RESTCONF")
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--local-as", type=int, required=True, metavar="AS")
    p.add_argument(
        "--action",
        required=True,
        choices=["list-neighbors", "add-neighbor", "remove-neighbor", "advertise-network"],
    )
    p.add_argument("--neighbor", metavar="IP")
    p.add_argument("--remote-as", type=int, metavar="AS")
    p.add_argument("--description", default="")
    p.add_argument("--network", metavar="PREFIX")
    p.add_argument("--mask", metavar="MASK")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--timeout", type=int, default=10)
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.action == "add-neighbor" and not (args.neighbor and args.remote_as):
        sys.exit("add-neighbor requires --neighbor and --remote-as")
    if args.action == "remove-neighbor" and not args.neighbor:
        sys.exit("remove-neighbor requires --neighbor")
    if args.action == "advertise-network" and not (args.network and args.mask):
        sys.exit("advertise-network requires --network and --mask")

    host = f"{args.host}:{args.port}" if args.port != 443 else args.host
    session = requests.Session()
    session.auth = HTTPBasicAuth(args.username, args.password)
    session.headers.update(_HEADERS)
    session.verify = False

    _timeout = args.timeout
    _orig_request = session.request

    def _timed_request(method, url, **kw):
        kw.setdefault("timeout", _timeout)
        return _orig_request(method, url, **kw)

    session.request = _timed_request  # type: ignore[method-assign]

    actions = {
        "list-neighbors": lambda: list_neighbors(session, host, args.local_as),
        "add-neighbor": lambda: add_neighbor(
            session, host, args.local_as, args.neighbor, args.remote_as, args.description
        ),
        "remove-neighbor": lambda: remove_neighbor(session, host, args.local_as, args.neighbor),
        "advertise-network": lambda: advertise_network(
            session, host, args.local_as, args.network, args.mask
        ),
    }
    return actions[args.action]()


if __name__ == "__main__":
    sys.exit(main())