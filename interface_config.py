```python
"""
008_interface_config.py — Configure interface parameters via RESTCONF on IOS-XE devices.

Purpose:
    Set or update IPv4 addressing, description, MTU, and administrative state on
    physical or logical interfaces using the RESTCONF API (RFC 8040) and the
    ietf-interfaces YANG model.  Reads the existing config first so only the
    requested attributes are overwritten.

Usage:
    # Set IP address and description on a WAN port
    python 008_interface_config.py --device 192.168.1.1 --user admin --password secret \
        --interface GigabitEthernet1 --ip 203.0.113.1 --prefix 30 \
        --description "WAN uplink - ISP-A"

    # Administratively shut down an interface
    python 008_interface_config.py --device 192.168.1.1 --user admin --password secret \
        --interface GigabitEthernet3 --shutdown

    # Preview the RESTCONF payload without applying
    python 008_interface_config.py --device 192.168.1.1 --user admin --password secret \
        --interface Loopback0 --ip 10.255.0.1 --prefix 32 --dry-run

Prerequisites:
    - IOS-XE 16.6+ with RESTCONF enabled:
          ip http secure-server
          restconf
    - Account with privilege 15 (or a role granting write access to ietf-interfaces)
    - pip install requests
    - Python 3.7+
"""

import argparse
import json
import logging
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RESTCONF_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# RESTCONF helpers
# ---------------------------------------------------------------------------

def _iface_url(base: str, name: str) -> str:
    encoded = requests.utils.quote(name, safe="")
    return f"{base}/ietf-interfaces:interfaces/interface={encoded}"


def get_interface(session: requests.Session, base: str, name: str) -> dict | None:
    resp = session.get(_iface_url(base, name))
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json().get("ietf-interfaces:interface", {})


def put_interface(session: requests.Session, base: str, name: str, payload: dict) -> int:
    resp = session.put(_iface_url(base, name), json=payload)
    resp.raise_for_status()
    return resp.status_code


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------

def build_payload(args: argparse.Namespace, existing: dict | None) -> dict:
    iface: dict = dict(existing) if existing else {
        "name": args.interface,
        "type": "iana-if-type:ethernetCsmacd",
    }

    if args.description is not None:
        iface["description"] = args.description

    if args.shutdown:
        iface["enabled"] = False
    elif args.no_shutdown:
        iface["enabled"] = True

    if args.ip and args.prefix is not None:
        ipv4 = iface.setdefault("ietf-ip:ipv4", {})
        addresses = ipv4.get("address", [])
        new_addr = {"ip": args.ip, "prefix-length": args.prefix}
        if addresses:
            addresses[0] = new_addr
        else:
            addresses.append(new_addr)
        ipv4["address"] = addresses

    if args.mtu:
        iface.setdefault("ietf-ip:ipv4", {})["mtu"] = args.mtu

    return {"ietf-interfaces:interface": iface}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Configure interface parameters via RESTCONF (IOS-XE)"
    )
    p.add_argument("--device", required=True, help="Device hostname or IP address")
    p.add_argument("--user", required=True, help="RESTCONF username")
    p.add_argument("--password", required=True, help="RESTCONF password")
    p.add_argument("--interface", required=True,
                   help="Interface name, e.g. GigabitEthernet1 or Loopback0")
    p.add_argument("--ip", help="IPv4 address to assign")
    p.add_argument("--prefix", type=int, metavar="LEN",
                   help="IPv4 prefix length (0-32); required with --ip")
    p.add_argument("--description", metavar="TEXT", help="Interface description")
    p.add_argument("--mtu", type=int, help="IP MTU in bytes (applied to ietf-ip:ipv4 mtu)")
    p.add_argument("--shutdown", action="store_true",
                   help="Administratively disable the interface")
    p.add_argument("--no-shutdown", dest="no_shutdown", action="store_true",
                   help="Administratively enable the interface")
    p.add_argument("--port", type=int, default=443, help="RESTCONF TCP port (default: 443)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print the YANG payload without applying it")
    p.add_argument("--debug", action="store_true", help="Enable DEBUG logging")
    return p.parse_args()


def validate(args: argparse.Namespace) -> None:
    if args.shutdown and args.no_shutdown:
        log.error("--shutdown and --no-shutdown are mutually exclusive")
        sys.exit(1)
    if bool(args.ip) != (args.prefix is not None):
        log.error("--ip and --prefix must be used together")
        sys.exit(1)
    if args.prefix is not None and not (0 <= args.prefix <= 32):
        log.error("--prefix must be between 0 and 32")
        sys.exit(1)


def main() -> None:
    args = parse_args()
    validate(args)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    session = requests.Session()
    session.auth = (args.user, args.password)
    session.headers.update(RESTCONF_HEADERS)
    session.verify = False

    base = f"https://{args.device}:{args.port}/restconf/data"

    log.info("Reading current config for %s on %s", args.interface, args.device)
    try:
        existing = get_interface(session, base, args.interface)
    except requests.exceptions.RequestException as exc:
        log.error("GET failed: %s", exc)
        sys.exit(1)

    if existing is None:
        log.info("Interface not found — a new entry will be created")
    else:
        log.debug("Existing: %s", json.dumps(existing, indent=2))

    payload = build_payload(args, existing)

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        log.info("Dry run — no changes written to device")
        return

    log.info("Applying configuration ...")
    try:
        status = put_interface(session, base, args.interface, payload)
    except requests.exceptions.HTTPError as exc:
        log.error("RESTCONF %s: %s", exc.response.status_code, exc.response.text)
        sys.exit(1)
    except requests.exceptions.RequestException as exc:
        log.error("Request error: %s", exc)
        sys.exit(1)

    log.info("Done — HTTP %s  interface=%s device=%s", status, args.interface, args.device)


if __name__ == "__main__":
    main()
```