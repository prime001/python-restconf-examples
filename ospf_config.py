```
#!/usr/bin/env python3
"""
005_ospf_config.py - OSPF Configuration via RESTCONF

Purpose:
    Manage OSPF routing configuration on Cisco IOS-XE devices using RESTCONF.
    Supports configuring OSPF processes, areas, network statements, and passive
    interfaces, plus querying live OSPF neighbor state from operational data.

Usage:
    # Show running OSPF configuration for process 1:
    python 005_ospf_config.py -H 192.168.1.1 -u admin -p secret \
        --action show --process-id 1

    # Configure OSPF process with router-id and network statements:
    python 005_ospf_config.py -H 192.168.1.1 -u admin -p secret \
        --action configure --process-id 1 --router-id 1.1.1.1 \
        --networks "10.0.0.0 0.255.255.255 0" "192.168.1.0 0.0.0.255 0"

    # Show OSPF neighbors (operational state):
    python 005_ospf_config.py -H 192.168.1.1 -u admin -p secret \
        --action neighbors --process-id 1

    # Mark an interface as passive (suppress hellos):
    python 005_ospf_config.py -H 192.168.1.1 -u admin -p secret \
        --action passive --process-id 1 --interface GigabitEthernet2

Prerequisites:
    - Cisco IOS-XE 16.6+ with RESTCONF enabled
    - Device must have: ip http secure-server / restconf
    - pip install requests
    - Credentials with privilege level 15
"""

import argparse
import json
import logging
import sys
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

RESTCONF_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}
OSPF_CFG_BASE = (
    "Cisco-IOS-XE-native:native/router/"
    "Cisco-IOS-XE-ospf:router-ospf/ospf/process-id={pid}"
)
OSPF_OPER_BASE = (
    "Cisco-IOS-XE-ospf-oper:ospf-oper-data/ospf-state/"
    "ospf-instance={pid}/ospf-area/ospf-interface/ospf-neighbor"
)


class RestconfClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        verify: bool = False,
    ):
        self.base_url = f"https://{host}:{port}/restconf/data"
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update(RESTCONF_HEADERS)
        self.session.verify = verify

    def get(self, path: str) -> dict:
        url = f"{self.base_url}/{path}"
        log.debug("GET %s", url)
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def patch(self, path: str, payload: dict) -> requests.Response:
        url = f"{self.base_url}/{path}"
        log.debug("PATCH %s payload=%s", url, json.dumps(payload))
        resp = self.session.patch(url, json=payload)
        resp.raise_for_status()
        return resp


def action_show(client: RestconfClient, process_id: int) -> None:
    path = OSPF_CFG_BASE.format(pid=process_id)
    try:
        data = client.get(path)
        print(json.dumps(data, indent=2))
    except requests.HTTPError as exc:
        if exc.response.status_code == 404:
            log.error("OSPF process %d not found", process_id)
        else:
            log.error("GET failed (%s): %s", exc.response.status_code, exc.response.text)
        sys.exit(1)


def action_configure(
    client: RestconfClient,
    process_id: int,
    router_id: Optional[str],
    networks: list,
) -> None:
    ospf_entry: dict = {"id": process_id}

    if router_id:
        ospf_entry["router-id"] = router_id

    if networks:
        parsed = []
        for net in networks:
            parts = net.split()
            if len(parts) != 3:
                log.error(
                    "Bad network format %r — expected '<address> <wildcard> <area>'", net
                )
                sys.exit(1)
            address, wildcard, area = parts
            parsed.append({"ip": address, "mask": wildcard, "area": int(area)})
        ospf_entry["network"] = {"ip": parsed}

    payload = {"Cisco-IOS-XE-ospf:process-id": [ospf_entry]}
    path = OSPF_CFG_BASE.format(pid=process_id)

    try:
        client.patch(path, payload)
        log.info("OSPF process %d applied", process_id)
        if router_id:
            log.info("  router-id: %s", router_id)
        for net in networks:
            log.info("  network: %s", net)
    except requests.HTTPError as exc:
        log.error("PATCH failed (%s): %s", exc.response.status_code, exc.response.text)
        sys.exit(1)


def action_neighbors(client: RestconfClient, process_id: int) -> None:
    path = OSPF_OPER_BASE.format(pid=process_id)
    try:
        data = client.get(path)
    except requests.HTTPError as exc:
        if exc.response.status_code == 404:
            print(f"No OSPF neighbors found for process {process_id}")
            return
        log.error("GET failed (%s): %s", exc.response.status_code, exc.response.text)
        sys.exit(1)

    neighbors = data.get("Cisco-IOS-XE-ospf-oper:ospf-neighbor", [])
    if not neighbors:
        print(f"Process {process_id}: no neighbors")
        return

    header = f"{'Neighbor ID':<18} {'State':<16} {'Priority':<10} {'Dead Timer'}"
    print(header)
    print("-" * len(header))
    for nbr in neighbors:
        print(
            f"{nbr.get('nbr-id', 'N/A'):<18}"
            f" {nbr.get('nbr-state', 'N/A'):<16}"
            f" {nbr.get('nbr-priority', 'N/A'):<10}"
            f" {nbr.get('dead-timer', 'N/A')}"
        )


def action_passive(
    client: RestconfClient, process_id: int, interface: str
) -> None:
    ospf_entry = {
        "id": process_id,
        "passive-interface": {"interface": [{"name": interface}]},
    }
    payload = {"Cisco-IOS-XE-ospf:process-id": [ospf_entry]}
    path = OSPF_CFG_BASE.format(pid=process_id)

    try:
        client.patch(path, payload)
        log.info(
            "OSPF process %d: %s set passive (hellos suppressed)",
            process_id,
            interface,
        )
    except requests.HTTPError as exc:
        log.error("PATCH failed (%s): %s", exc.response.status_code, exc.response.text)
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OSPF configuration and state via RESTCONF (Cisco IOS-XE)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--user", required=True, help="RESTCONF username")
    parser.add_argument("-p", "--password", required=True, help="RESTCONF password")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port (default 443)")
    parser.add_argument(
        "--action",
        required=True,
        choices=["show", "configure", "neighbors", "passive"],
        help="Operation: show config | configure process | show neighbors | set passive iface",
    )
    parser.add_argument(
        "--process-id", type=int, default=1, metavar="PID",
        help="OSPF process ID (default 1)"
    )
    parser.add_argument("--router-id", metavar="A.B.C.D", help="OSPF router ID")
    parser.add_argument(
        "--networks", nargs="+", metavar="NET",
        help='Network statements: "<address> <wildcard> <area>" (quote each)'
    )
    parser.add_argument("--interface", metavar="IFNAME", help="Interface for passive action")
    parser.add_argument("--no-verify", action="store_true", help="Skip TLS cert verification")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    client = RestconfClient(
        host=args.host,
        username=args.user,
        password=args.password,
        port=args.port,
        verify=not args.no_verify,
    )

    if args.action == "show":
        action_show(client, args.process_id)
    elif args.action == "configure":
        action_configure(client, args.process_id, args.router_id, args.networks or [])
    elif args.action == "neighbors":
        action_neighbors(client, args.process_id)
    elif args.action == "passive":
        if not args.interface:
            log.error("--interface is required for 'passive' action")
            sys.exit(1)
        action_passive(client, args.process_id, args.interface)
```