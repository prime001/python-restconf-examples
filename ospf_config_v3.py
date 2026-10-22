```python
"""
025_ospf_config.py - OSPF Authentication Hardening via RESTCONF

Purpose:
    Configures MD5 or plaintext authentication on OSPF-enabled interfaces
    and verifies neighbor adjacencies are established post-configuration.
    Targets Cisco IOS-XE devices via RESTCONF (RFC 8040).

    Complements 005/015_ospf_config.py (process/area provisioning) by
    focusing on in-service security hardening without tearing down adjacencies.

Usage:
    # Enable MD5 auth on an interface
    python 025_ospf_config.py --host 192.168.1.1 --user admin --password secret \
        --interface GigabitEthernet1 --auth-mode md5 --key-id 1 --key cisco123

    # Remove authentication from an interface
    python 025_ospf_config.py --host 192.168.1.1 --user admin --password secret \
        --interface GigabitEthernet1 --auth-mode none

    # Show current neighbor table only
    python 025_ospf_config.py --host 192.168.1.1 --user admin --password secret \
        --check-neighbors

Prerequisites:
    - IOS-XE 16.6+ with RESTCONF enabled (`restconf` in global config)
    - YANG models: Cisco-IOS-XE-native, Cisco-IOS-XE-ospf-oper
    - pip install requests
    - Account with privilege 15 or NETCONF read-write access
"""

import argparse
import logging
import re
import sys

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}

log = logging.getLogger(__name__)


def session(username: str, password: str) -> requests.Session:
    s = requests.Session()
    s.auth = HTTPBasicAuth(username, password)
    s.headers.update(HEADERS)
    s.verify = False
    return s


def base_url(host: str, port: int) -> str:
    return f"https://{host}:{port}/restconf/data"


def split_interface(name: str) -> tuple:
    """Split 'GigabitEthernet0/1' into ('GigabitEthernet', '0/1')."""
    m = re.match(r"([A-Za-z]+)([\d/.:]+)", name)
    if not m:
        raise ValueError(f"Unrecognised interface name: {name!r}")
    return m.group(1), m.group(2)


def iface_base_path(url: str, iface_type: str, iface_num: str) -> str:
    return (
        f"{url}/Cisco-IOS-XE-native:native/interface"
        f"/{iface_type}={iface_num}/ip/ospf"
    )


def configure_md5(sess: requests.Session, url: str, interface: str,
                  key_id: int, key_string: str) -> None:
    itype, inum = split_interface(interface)
    ospf_path = iface_base_path(url, itype, inum)

    key_payload = {
        "Cisco-IOS-XE-ospf:message-digest-key": [
            {"id": key_id, "md5": {"encrypted": False, "md5-key": key_string}}
        ]
    }
    r = sess.put(f"{ospf_path}/message-digest-key={key_id}", json=key_payload, timeout=10)
    r.raise_for_status()
    log.info("MD5 key %d written to %s", key_id, interface)

    auth_payload = {"Cisco-IOS-XE-ospf:authentication": {"message-digest": {}}}
    r = sess.put(f"{ospf_path}/authentication", json=auth_payload, timeout=10)
    r.raise_for_status()
    log.info("MD5 authentication enabled on %s", interface)


def configure_plaintext(sess: requests.Session, url: str, interface: str,
                        key_string: str) -> None:
    itype, inum = split_interface(interface)
    ospf_path = iface_base_path(url, itype, inum)

    payload = {
        "Cisco-IOS-XE-ospf:authentication-key": {
            "encrypted": False, "auth-key": key_string
        }
    }
    r = sess.put(f"{ospf_path}/authentication-key", json=payload, timeout=10)
    r.raise_for_status()
    log.info("Plaintext authentication key set on %s", interface)


def remove_auth(sess: requests.Session, url: str, interface: str) -> None:
    itype, inum = split_interface(interface)
    ospf_path = iface_base_path(url, itype, inum)

    for suffix in ("authentication", "authentication-key"):
        r = sess.delete(f"{ospf_path}/{suffix}", timeout=10)
        if r.status_code not in (200, 204, 404):
            log.warning("Unexpected %d removing %s from %s", r.status_code, suffix, interface)
    log.info("Authentication cleared on %s", interface)


def get_neighbors(sess: requests.Session, url: str) -> list:
    oper_url = f"{url}/Cisco-IOS-XE-ospf-oper:ospf-oper-data/ospf-state"
    r = sess.get(oper_url, timeout=10)
    if r.status_code == 204:
        return []
    r.raise_for_status()
    neighbors = []
    for instance in r.json().get("Cisco-IOS-XE-ospf-oper:ospf-state", []):
        for area in instance.get("ospf-area", []):
            for iface in area.get("ospf-interface", []):
                for nbr in iface.get("ospf-neighbor", []):
                    neighbors.append({
                        "id": nbr.get("nbr-id", "—"),
                        "interface": iface.get("name", "—"),
                        "area": area.get("area-id", "—"),
                        "state": nbr.get("state", "—"),
                    })
    return neighbors


def print_neighbors(neighbors: list) -> None:
    if not neighbors:
        print("No OSPF neighbors found.")
        return
    print(f"\n{'Neighbor ID':<18} {'Interface':<24} {'Area':<8} State")
    print("─" * 64)
    for n in neighbors:
        print(f"{n['id']:<18} {n['interface']:<24} {n['area']:<8} {n['state']}")
    print()


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OSPF interface authentication via RESTCONF")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--interface", help="e.g. GigabitEthernet1 or Loopback0")
    p.add_argument("--auth-mode", choices=["md5", "plaintext", "none"])
    p.add_argument("--key-id", type=int, default=1, help="MD5 key ID (default: 1)")
    p.add_argument("--key", help="Authentication key string")
    p.add_argument("--check-neighbors", action="store_true")
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


def main() -> int:
    args = build_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
    )

    sess = session(args.user, args.password)
    url = base_url(args.host, args.port)

    try:
        if not args.check_neighbors and not args.auth_mode:
            log.error("Specify --check-neighbors, --auth-mode, or both.")
            return 1

        if args.auth_mode:
            if not args.interface:
                log.error("--interface is required with --auth-mode")
                return 1
            if args.auth_mode in ("md5", "plaintext") and not args.key:
                log.error("--key is required for md5/plaintext auth")
                return 1

            if args.auth_mode == "md5":
                configure_md5(sess, url, args.interface, args.key_id, args.key)
            elif args.auth_mode == "plaintext":
                configure_plaintext(sess, url, args.interface, args.key)
            else:
                remove_auth(sess, url, args.interface)

        if args.check_neighbors or args.auth_mode:
            log.info("Fetching neighbor table from %s", args.host)
            print_neighbors(get_neighbors(sess, url))

    except ValueError as exc:
        log.error("%s", exc)
        return 1
    except requests.exceptions.ConnectionError as exc:
        log.error("Connection failed: %s", exc)
        return 2
    except requests.exceptions.HTTPError as exc:
        body = exc.response.text[:400] if exc.response else ""
        log.error("HTTP %s: %s", exc.response.status_code, body)
        return 2
    except KeyboardInterrupt:
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
```