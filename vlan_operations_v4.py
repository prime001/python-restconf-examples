The request is for standalone script output, not tied to this repo. Writing the VLAN trunk allowed-list manager now — a distinct angle from basic VLAN CRUD that the existing three `vlan_operations` scripts already cover.

"""
033_vlan_operations.py - VLAN Trunk Allowed-List Manager via RESTCONF

Purpose:
    Manages the VLAN allowed list on trunk interfaces using Cisco IOS-XE
    RESTCONF. Reads current trunk configurations, displays allowed VLANs per
    interface, and supports adding or removing VLANs from trunk allowed lists
    using compact range notation (e.g., 10,20-25,100).

    This complements basic VLAN database management (create/delete VLANs) by
    addressing trunk pruning — controlling which VLANs actually traverse each
    uplink, a critical step in reducing broadcast domains and hardening L2.

Usage:
    # Show trunk allowed-VLAN lists for all interfaces
    python 033_vlan_operations.py --host 192.168.1.1 --user admin --password secret

    # Add VLANs to a specific trunk
    python 033_vlan_operations.py --host 192.168.1.1 --user admin --password secret \
        --action add --interface GigabitEthernet1/0/1 --vlans 100,200-210

    # Remove VLANs from a trunk
    python 033_vlan_operations.py --host 192.168.1.1 --user admin --password secret \
        --action remove --interface GigabitEthernet1/0/1 --vlans 200-205

Prerequisites:
    - Cisco IOS-XE 16.6+ with RESTCONF enabled:
        ip http secure-server
        restconf
    - requests library: pip install requests
    - Account with privilege 15 or netconf-yang access
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
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}

INTF_TYPES = ("GigabitEthernet", "TenGigabitEthernet", "HundredGigE",
              "TwentyFiveGigE", "FortyGigabitEthernet", "FastEthernet")


def base_url(host: str, port: int) -> str:
    return f"https://{host}:{port}/restconf/data"


def session(username: str, password: str) -> requests.Session:
    s = requests.Session()
    s.auth = HTTPBasicAuth(username, password)
    s.headers.update(HEADERS)
    s.verify = False
    return s


def split_interface(name: str) -> tuple[str, str]:
    for prefix in INTF_TYPES:
        if name.startswith(prefix):
            num = name[len(prefix):].replace("/", "%2F")
            return prefix, num
    raise ValueError(f"Unrecognized interface type: {name!r}")


def vlan_str_to_set(vlan_str: str) -> set:
    result = set()
    for part in (vlan_str or "").split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            result.update(range(int(lo), int(hi) + 1))
        elif part.isdigit():
            result.add(int(part))
    return result


def set_to_vlan_str(vlans: set) -> str:
    if not vlans:
        return ""
    items = sorted(vlans)
    ranges, start, end = [], items[0], items[0]
    for v in items[1:]:
        if v == end + 1:
            end = v
        else:
            ranges.append(f"{start}-{end}" if start != end else str(start))
            start = end = v
    ranges.append(f"{start}-{end}" if start != end else str(start))
    return ",".join(ranges)


def list_trunks(sess: requests.Session, host: str, port: int) -> None:
    url = f"{base_url(host, port)}/Cisco-IOS-XE-native:native/interface"
    resp = sess.get(url, timeout=10)
    resp.raise_for_status()
    intf_data = resp.json().get("Cisco-IOS-XE-native:interface", {})

    rows = []
    for itype in INTF_TYPES:
        short = itype.replace("GigabitEthernet", "Gi").replace(
            "TenGigabitEthernet", "Te").replace("FastEthernet", "Fa").replace(
            "HundredGigE", "Hu").replace("TwentyFiveGigE", "Twe").replace(
            "FortyGigabitEthernet", "Fo")
        for intf in intf_data.get(itype, []):
            trunk = (
                intf.get("switchport", {})
                    .get("Cisco-IOS-XE-switch:trunk", {})
                    .get("allowed", {})
                    .get("vlan", {})
            )
            if trunk:
                allowed = trunk.get("vlans") or trunk.get("add") or "(all)"
                rows.append((f"{short}{intf['name']}", allowed))

    if not rows:
        log.info("No trunk interfaces with explicit VLAN allowed lists found.")
        return

    col = max(len(r[0]) for r in rows) + 2
    print(f"{'Interface':<{col}} Allowed VLANs")
    print("-" * (col + 40))
    for iface, allowed in rows:
        print(f"{iface:<{col}} {allowed}")


def get_trunk_vlan_str(sess: requests.Session, host: str, port: int,
                       interface: str) -> str:
    itype, inum = split_interface(interface)
    path = (f"Cisco-IOS-XE-native:native/interface/{itype}={inum}"
            f"/switchport/Cisco-IOS-XE-switch:trunk/allowed/vlan")
    resp = sess.get(f"{base_url(host, port)}/{path}", timeout=10)
    if resp.status_code == 404:
        return ""
    resp.raise_for_status()
    data = resp.json().get("Cisco-IOS-XE-switch:vlan", {})
    return data.get("vlans") or data.get("add") or ""


def put_trunk_vlan_str(sess: requests.Session, host: str, port: int,
                       interface: str, vlan_string: str) -> None:
    itype, inum = split_interface(interface)
    path = (f"Cisco-IOS-XE-native:native/interface/{itype}={inum}"
            f"/switchport/Cisco-IOS-XE-switch:trunk/allowed/vlan")
    payload = {"Cisco-IOS-XE-switch:vlan": {"vlans": vlan_string}}
    resp = sess.put(f"{base_url(host, port)}/{path}",
                    data=json.dumps(payload), timeout=10)
    resp.raise_for_status()


def modify_trunk(sess: requests.Session, host: str, port: int,
                 interface: str, vlans: str, action: str) -> None:
    current_str = get_trunk_vlan_str(sess, host, port, interface)
    current = vlan_str_to_set(current_str)
    delta = vlan_str_to_set(vlans)

    if action == "add":
        updated = current | delta
    else:
        updated = current - delta
        if not updated:
            log.error("Removing %s would leave an empty trunk — aborting.", vlans)
            sys.exit(1)

    new_str = set_to_vlan_str(updated)
    log.info("%-10s current : %s", interface, current_str or "(none)")
    log.info("%-10s %s : %s", interface, action, vlans)
    log.info("%-10s result  : %s", interface, new_str)
    put_trunk_vlan_str(sess, host, port, interface, new_str)
    log.info("Updated %s → %s", interface, new_str)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manage VLAN trunk allowed lists on IOS-XE via RESTCONF"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--port", type=int, default=443,
                        help="RESTCONF HTTPS port (default: 443)")
    parser.add_argument("--user", required=True, help="Username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--action", choices=["list", "add", "remove"],
                        default="list",
                        help="Operation: list all trunks, or add/remove VLANs")
    parser.add_argument("--interface",
                        help="Target interface (e.g. GigabitEthernet1/0/1)")
    parser.add_argument("--vlans",
                        help="VLAN list to add or remove (e.g. 100,200-210)")
    args = parser.parse_args()

    if args.action in ("add", "remove"):
        if not args.interface or not args.vlans:
            parser.error(f"--action {args.action} requires --interface and --vlans")

    sess = session(args.user, args.password)
    try:
        if args.action == "list":
            list_trunks(sess, args.host, args.port)
        else:
            modify_trunk(sess, args.host, args.port,
                         args.interface, args.vlans, args.action)
    except requests.exceptions.ConnectionError as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP %s: %s", exc.response.status_code,
                  exc.response.text[:300])
        sys.exit(1)
    except ValueError as exc:
        log.error("%s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()