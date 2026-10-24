```python
"""
SNMP Trap Receiver Configuration via RESTCONF
==============================================
Configures SNMP trap destinations and notification settings on IOS-XE
devices using the RESTCONF API and Cisco-IOS-XE-snmp YANG model.

Usage:
    python 029_snmp_config.py --host 192.168.1.1 --user admin --password secret \\
        --trap-host 10.0.0.100 --community monitoring --version 2c

    python 029_snmp_config.py --host 192.168.1.1 --user admin --password secret \\
        --trap-host 10.0.0.100 --community monitoring --version 2c --udp-port 1162 \\
        --list

Prerequisites:
    - IOS-XE 16.6+ with RESTCONF enabled (ip http secure-server, restconf)
    - requests library: pip install requests
    - Valid credentials with privilege 15
"""

import argparse
import json
import logging
import sys
import urllib3

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}

SNMP_HOST_URL = (
    "https://{host}:{port}/restconf/data/Cisco-IOS-XE-native:native"
    "/snmp-server/host={trap_host}"
)
SNMP_HOSTS_URL = (
    "https://{host}:{port}/restconf/data/Cisco-IOS-XE-native:native/snmp-server/host"
)
SNMP_ENABLE_URL = (
    "https://{host}:{port}/restconf/data/Cisco-IOS-XE-native:native/snmp-server/enable"
)


def get_session(username: str, password: str) -> requests.Session:
    session = requests.Session()
    session.auth = (username, password)
    session.headers.update(BASE_HEADERS)
    session.verify = False
    return session


def list_trap_hosts(session: requests.Session, host: str, port: int) -> None:
    url = SNMP_HOSTS_URL.format(host=host, port=port)
    try:
        resp = session.get(url, timeout=10)
        if resp.status_code == 404:
            logging.info("No SNMP trap hosts configured.")
            return
        resp.raise_for_status()
        data = resp.json()
        hosts = data.get("Cisco-IOS-XE-native:host", [])
        if not hosts:
            logging.info("No SNMP trap hosts configured.")
            return
        print(f"\n{'Trap Host':<20} {'Community':<20} {'Version':<10} {'UDP Port'}")
        print("-" * 65)
        for entry in hosts:
            ip = entry.get("ip-address", "unknown")
            community = entry.get("community-or-user", "—")
            version = entry.get("version", "—")
            udp = entry.get("udp-port", 162)
            print(f"{ip:<20} {community:<20} {version:<10} {udp}")
    except requests.RequestException as exc:
        logging.error("Failed to retrieve trap hosts: %s", exc)
        sys.exit(1)


def add_trap_host(
    session: requests.Session,
    host: str,
    port: int,
    trap_host: str,
    community: str,
    version: str,
    udp_port: int,
) -> None:
    url = SNMP_HOST_URL.format(host=host, port=port, trap_host=trap_host)
    payload = {
        "Cisco-IOS-XE-native:host": [
            {
                "ip-address": trap_host,
                "community-or-user": community,
                "version": version,
                "udp-port": udp_port,
            }
        ]
    }
    try:
        resp = session.put(url, data=json.dumps(payload), timeout=10)
        if resp.status_code in (200, 201, 204):
            logging.info(
                "Trap host %s configured (community=%s, v%s, udp/%d).",
                trap_host, community, version, udp_port,
            )
        else:
            logging.error(
                "Unexpected response %d: %s", resp.status_code, resp.text[:200]
            )
            sys.exit(1)
    except requests.RequestException as exc:
        logging.error("Failed to configure trap host: %s", exc)
        sys.exit(1)


def remove_trap_host(
    session: requests.Session, host: str, port: int, trap_host: str
) -> None:
    url = SNMP_HOST_URL.format(host=host, port=port, trap_host=trap_host)
    try:
        resp = session.delete(url, timeout=10)
        if resp.status_code in (200, 204):
            logging.info("Trap host %s removed.", trap_host)
        elif resp.status_code == 404:
            logging.warning("Trap host %s not found; nothing to remove.", trap_host)
        else:
            logging.error(
                "Unexpected response %d: %s", resp.status_code, resp.text[:200]
            )
            sys.exit(1)
    except requests.RequestException as exc:
        logging.error("Failed to remove trap host: %s", exc)
        sys.exit(1)


def enable_traps(session: requests.Session, host: str, port: int) -> None:
    url = SNMP_ENABLE_URL.format(host=host, port=port)
    payload = {
        "Cisco-IOS-XE-native:enable": {
            "traps": {
                "snmp": {"authentication": [None], "coldstart": [None], "linkdown": [None], "linkup": [None]}
            }
        }
    }
    try:
        resp = session.patch(url, data=json.dumps(payload), timeout=10)
        if resp.status_code in (200, 201, 204):
            logging.info("SNMP traps enabled for auth/coldstart/linkdown/linkup.")
        else:
            logging.warning(
                "Trap enable returned %d: %s", resp.status_code, resp.text[:200]
            )
    except requests.RequestException as exc:
        logging.error("Failed to enable traps: %s", exc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configure SNMP trap destinations on IOS-XE via RESTCONF."
    )
    parser.add_argument("--host", required=True, help="Device management IP or hostname")
    parser.add_argument("--user", required=True, help="RESTCONF username")
    parser.add_argument("--password", required=True, help="RESTCONF password")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument("--trap-host", help="IP address of the SNMP trap receiver")
    parser.add_argument("--community", default="public", help="SNMP community string")
    parser.add_argument(
        "--version", choices=["1", "2c"], default="2c", help="SNMP version (default: 2c)"
    )
    parser.add_argument("--udp-port", type=int, default=162, help="Trap UDP port (default: 162)")
    parser.add_argument("--list", action="store_true", help="List current trap destinations")
    parser.add_argument("--remove", action="store_true", help="Remove the specified trap host")
    parser.add_argument("--enable-traps", action="store_true", help="Enable standard SNMP trap types")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    session = get_session(args.user, args.password)

    if args.list:
        list_trap_hosts(session, args.host, args.port)
        sys.exit(0)

    if not args.trap_host:
        logging.error("--trap-host is required unless using --list.")
        sys.exit(1)

    if args.remove:
        remove_trap_host(session, args.host, args.port, args.trap_host)
    else:
        add_trap_host(
            session, args.host, args.port, args.trap_host,
            args.community, args.version, args.udp_port,
        )
        if args.enable_traps:
            enable_traps(session, args.host, args.port)
```