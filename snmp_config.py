```python
"""
009_snmp_config.py - SNMP Configuration via RESTCONF

Configure SNMP communities, trap receivers, and system information
on Cisco IOS-XE devices using the RESTCONF API (YANG native model).

Usage:
    # Show current SNMP config
    python 009_snmp_config.py --device 192.168.1.1 --user admin --password secret --show

    # Configure read-only and read-write communities
    python 009_snmp_config.py --device 192.168.1.1 --user admin --password secret \\
        --community public ro --community private rw

    # Configure trap receiver with system info
    python 009_snmp_config.py --device 192.168.1.1 --user admin --password secret \\
        --trap-host 10.0.0.100 --trap-community monitoring --trap-version 2c \\
        --location "DC1-Row3-Rack12" --contact "noc@example.com" --enable-traps

Prerequisites:
    - Cisco IOS-XE 16.9+ with RESTCONF enabled:
        ip http secure-server
        restconf
    - requests library: pip install requests
    - RESTCONF user with privilege level 15

YANG model: Cisco-IOS-XE-native (bundled in IOS-XE 16.9+)
"""

import argparse
import json
import logging
import sys

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

RESTCONF_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}
SNMP_BASE = "/restconf/data/Cisco-IOS-XE-native:native/snmp-server"


def build_session(user: str, password: str, verify: bool = False) -> requests.Session:
    session = requests.Session()
    session.auth = HTTPBasicAuth(user, password)
    session.headers.update(RESTCONF_HEADERS)
    session.verify = verify
    return session


def get_snmp_config(session: requests.Session, base_url: str) -> dict:
    resp = session.get(base_url + SNMP_BASE, timeout=10)
    resp.raise_for_status()
    return resp.json()


def set_community(
    session: requests.Session, base_url: str, community: str, permission: str
) -> None:
    """Configure an SNMP community string with ro or rw permission."""
    url = base_url + SNMP_BASE + "/community"
    payload = {
        "Cisco-IOS-XE-native:community": [
            {
                "name": community,
                "permission": permission,
            }
        ]
    }
    resp = session.patch(url, data=json.dumps(payload), timeout=10)
    resp.raise_for_status()
    log.info("Community '%s' set to %s", community, permission.upper())


def set_trap_host(
    session: requests.Session,
    base_url: str,
    host: str,
    community: str,
    version: str = "2c",
) -> None:
    """Configure an SNMP trap receiver."""
    url = base_url + SNMP_BASE + "/host"
    payload = {
        "Cisco-IOS-XE-native:host": [
            {
                "ip-address": host,
                "community-or-user": community,
                "version": version,
            }
        ]
    }
    resp = session.patch(url, data=json.dumps(payload), timeout=10)
    resp.raise_for_status()
    log.info("Trap receiver %s configured (community=%s, SNMPv%s)", host, community, version)


def set_system_info(
    session: requests.Session,
    base_url: str,
    location: str = None,
    contact: str = None,
) -> None:
    """Set sysLocation and/or sysContact strings."""
    body = {}
    if location:
        body["location"] = location
    if contact:
        body["contact"] = contact
    if not body:
        return
    payload = {"Cisco-IOS-XE-native:snmp-server": body}
    resp = session.patch(base_url + SNMP_BASE, data=json.dumps(payload), timeout=10)
    resp.raise_for_status()
    if location:
        log.info("sysLocation -> '%s'", location)
    if contact:
        log.info("sysContact  -> '%s'", contact)


def enable_standard_traps(session: requests.Session, base_url: str) -> None:
    """Enable link-state and authentication failure SNMP traps."""
    payload = {
        "Cisco-IOS-XE-native:snmp-server": {
            "enable": {
                "enable-choice": {
                    "traps": {
                        "snmp": {
                            "authentication": [None],
                            "linkdown": [None],
                            "linkup": [None],
                        }
                    }
                }
            }
        }
    }
    resp = session.patch(base_url + SNMP_BASE, data=json.dumps(payload), timeout=10)
    resp.raise_for_status()
    log.info("SNMP traps enabled: linkup, linkdown, authentication")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configure SNMP on Cisco IOS-XE via RESTCONF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--device", required=True, help="Device hostname or IP")
    parser.add_argument("--user", required=True, help="RESTCONF username")
    parser.add_argument("--password", required=True, help="RESTCONF password")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument(
        "--no-verify", action="store_true", help="Disable TLS certificate verification"
    )
    parser.add_argument(
        "--community",
        nargs=2,
        metavar=("STRING", "PERMISSION"),
        action="append",
        default=[],
        help="Community string and permission (ro|rw); may be repeated",
    )
    parser.add_argument("--trap-host", metavar="IP", help="SNMP trap receiver address")
    parser.add_argument(
        "--trap-community", metavar="STRING", help="Community for trap receiver"
    )
    parser.add_argument(
        "--trap-version",
        default="2c",
        choices=["1", "2c"],
        help="SNMP version for traps (default: 2c)",
    )
    parser.add_argument("--location", help="sysLocation MIB string")
    parser.add_argument("--contact", help="sysContact MIB string")
    parser.add_argument(
        "--enable-traps",
        action="store_true",
        help="Enable linkup/linkdown/authentication traps",
    )
    parser.add_argument(
        "--show", action="store_true", help="Print current SNMP config as JSON and exit"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    base_url = f"https://{args.device}:{args.port}"
    session = build_session(args.user, args.password, verify=not args.no_verify)

    if args.show:
        try:
            config = get_snmp_config(session, base_url)
            print(json.dumps(config, indent=2))
        except requests.HTTPError as exc:
            log.error("Failed to read SNMP config: %s", exc.response.text)
            return 1
        return 0

    actions_requested = any(
        [args.community, args.trap_host, args.location, args.contact, args.enable_traps]
    )
    if not actions_requested:
        log.error("No configuration actions specified — use --help for options.")
        return 1

    errors = 0

    for community, permission in args.community:
        if permission not in ("ro", "rw"):
            log.error("'%s': invalid permission '%s' (must be ro or rw)", community, permission)
            errors += 1
            continue
        try:
            set_community(session, base_url, community, permission)
        except requests.HTTPError as exc:
            log.error("Community '%s' failed: %s", community, exc.response.text)
            errors += 1

    if args.trap_host:
        if not args.trap_community:
            log.error("--trap-community is required with --trap-host")
            errors += 1
        else:
            try:
                set_trap_host(
                    session, base_url, args.trap_host, args.trap_community, args.trap_version
                )
            except requests.HTTPError as exc:
                log.error("Trap host config failed: %s", exc.response.text)
                errors += 1

    if args.location or args.contact:
        try:
            set_system_info(session, base_url, args.location, args.contact)
        except requests.HTTPError as exc:
            log.error("System info config failed: %s", exc.response.text)
            errors += 1

    if args.enable_traps:
        try:
            enable_standard_traps(session, base_url)
        except requests.HTTPError as exc:
            log.error("Enable traps failed: %s", exc.response.text)
            errors += 1

    if errors:
        log.warning("%d operation(s) failed", errors)
        return 1

    log.info("SNMP configuration complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```