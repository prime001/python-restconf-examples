acl_restconf_manager.py — Manage IP access-lists on IOS-XE via RESTCONF (RFC 8040).

Provides CRUD operations for extended ACLs and their ACEs (access-control entries)
on a single device. Complements bulk_restconf_query.py, which handles read-only
multi-device queries; this script is for targeted ACL configuration changes.

Usage:
    List all ACLs:
        python acl_restconf_manager.py --host 192.168.1.1 -u admin -p secret list

    Show a specific ACL:
        python acl_restconf_manager.py --host 192.168.1.1 -u admin -p secret show --acl BLOCK_INBOUND

    Add an ACE (creates the ACL if absent):
        python acl_restconf_manager.py ... add-ace --acl BLOCK_INBOUND --seq 10 \
            --action permit --protocol tcp --src any --dst 10.0.0.0 --dst-mask 0.0.255.255

    Remove a single ACE by sequence number:
        python acl_restconf_manager.py ... remove-ace --acl BLOCK_INBOUND --seq 10

    Delete an entire ACL:
        python acl_restconf_manager.py ... delete --acl BLOCK_INBOUND

Prerequisites:
    pip install requests
    IOS-XE 16.6+:
        conf t
         ip http secure-server
         restconf
"""

import argparse
import json
import logging
import sys

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

_ACL_PATH = "Cisco-IOS-XE-native:native/ip/access-list"
_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}


def _session(user: str, password: str) -> requests.Session:
    s = requests.Session()
    s.auth = HTTPBasicAuth(user, password)
    s.headers.update(_HEADERS)
    s.verify = False
    return s


def _url(host: str, path: str) -> str:
    return f"https://{host}/restconf/data/{path}"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_list(session: requests.Session, host: str) -> int:
    resp = session.get(_url(host, _ACL_PATH), timeout=10)
    if resp.status_code == 404:
        print("No ACLs configured.")
        return 0
    resp.raise_for_status()
    body = resp.json().get("Cisco-IOS-XE-native:access-list", {})
    found = False
    for kind in ("standard", "extended"):
        for acl in body.get(kind, []):
            entries = acl.get("access-list-seq-rule", [])
            print(f"[{kind}]  {acl['name']}  ({len(entries)} entries)")
            found = True
    if not found:
        print("No ACLs configured.")
    return 0


def cmd_show(session: requests.Session, host: str, acl_name: str) -> int:
    resp = session.get(_url(host, f"{_ACL_PATH}/extended={acl_name}"), timeout=10)
    if resp.status_code == 404:
        log.error("ACL '%s' not found.", acl_name)
        return 1
    resp.raise_for_status()
    acl = resp.json().get("Cisco-IOS-XE-native:extended", {})
    if isinstance(acl, list):
        acl = acl[0]
    entries = sorted(
        acl.get("access-list-seq-rule", []),
        key=lambda e: int(e.get("sequence", 0)),
    )
    print(f"Extended ACL: {acl_name}  ({len(entries)} entries)")
    for entry in entries:
        seq = entry.get("sequence", "?")
        ace = entry.get("ace-rule", {})
        action = ace.get("action", "?")
        proto = ace.get("protocol", "ip")
        src = "any" if "any" in ace else ace.get("ipv4-address", ace.get("host", "?"))
        dst_ip = ace.get("dst-ipv4-address", "any")
        print(f"  {seq:>6}  {action:<7}  {proto:<6}  src={src:<18}  dst={dst_ip}")
    return 0


def cmd_add_ace(
    session: requests.Session,
    host: str,
    acl_name: str,
    seq: int,
    action: str,
    protocol: str,
    src: str,
    dst: str,
    dst_mask: str,
) -> int:
    ace_rule: dict = {"action": action, "protocol": protocol}
    if src == "any":
        ace_rule["any"] = [None]
    else:
        parts = src.split("/")
        ace_rule["ipv4-address"] = parts[0]
        ace_rule["mask"] = parts[1] if len(parts) > 1 else "0.0.0.0"
    if dst != "any":
        ace_rule["dst-ipv4-address"] = dst
        ace_rule["dst-mask"] = dst_mask

    payload = {
        "Cisco-IOS-XE-native:access-list-seq-rule": [
            {"sequence": str(seq), "ace-rule": ace_rule}
        ]
    }
    url = _url(host, f"{_ACL_PATH}/extended={acl_name}/access-list-seq-rule")
    resp = session.post(url, data=json.dumps(payload), timeout=10)
    if resp.status_code in (200, 201, 204):
        log.info("ACE seq %d added to '%s'.", seq, acl_name)
        return 0
    log.error("Failed to add ACE: HTTP %d  %s", resp.status_code, resp.text[:300])
    return 1


def cmd_remove_ace(
    session: requests.Session, host: str, acl_name: str, seq: int
) -> int:
    url = _url(host, f"{_ACL_PATH}/extended={acl_name}/access-list-seq-rule={seq}")
    resp = session.delete(url, timeout=10)
    if resp.status_code in (200, 204):
        log.info("ACE seq %d removed from '%s'.", seq, acl_name)
        return 0
    if resp.status_code == 404:
        log.error("ACE seq %d not found in '%s'.", seq, acl_name)
        return 1
    log.error("Delete failed: HTTP %d  %s", resp.status_code, resp.text[:300])
    return 1


def cmd_delete_acl(session: requests.Session, host: str, acl_name: str) -> int:
    resp = session.delete(_url(host, f"{_ACL_PATH}/extended={acl_name}"), timeout=10)
    if resp.status_code in (200, 204):
        log.info("ACL '%s' deleted.", acl_name)
        return 0
    if resp.status_code == 404:
        log.error("ACL '%s' not found.", acl_name)
        return 1
    log.error("Delete failed: HTTP %d  %s", resp.status_code, resp.text[:300])
    return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Manage IOS-XE extended ACLs via RESTCONF.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("-v", "--verbose", action="store_true")

    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List all ACLs")

    sp = sub.add_parser("show", help="Show ACL entries")
    sp.add_argument("--acl", required=True, help="ACL name")

    ap = sub.add_parser("add-ace", help="Add an ACE (creates ACL if absent)")
    ap.add_argument("--acl", required=True)
    ap.add_argument("--seq", required=True, type=int, help="Sequence number")
    ap.add_argument("--action", required=True, choices=["permit", "deny"])
    ap.add_argument("--protocol", default="ip", help="ip|tcp|udp|icmp (default: ip)")
    ap.add_argument("--src", default="any", help="Source: any | A.B.C.D[/prefix]")
    ap.add_argument("--dst", default="any", help="Destination IP (default: any)")
    ap.add_argument("--dst-mask", default="0.0.0.0", help="Wildcard mask for --dst")

    rp = sub.add_parser("remove-ace", help="Remove ACE by sequence number")
    rp.add_argument("--acl", required=True)
    rp.add_argument("--seq", required=True, type=int)

    dp = sub.add_parser("delete", help="Delete an entire ACL")
    dp.add_argument("--acl", required=True)

    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    session = _session(args.username, args.password)
    try:
        if args.command == "list":
            rc = cmd_list(session, args.host)
        elif args.command == "show":
            rc = cmd_show(session, args.host, args.acl)
        elif args.command == "add-ace":
            rc = cmd_add_ace(
                session, args.host, args.acl, args.seq,
                args.action, args.protocol, args.src,
                args.dst, args.dst_mask,
            )
        elif args.command == "remove-ace":
            rc = cmd_remove_ace(session, args.host, args.acl, args.seq)
        elif args.command == "delete":
            rc = cmd_delete_acl(session, args.host, args.acl)
        else:
            rc = 1
    except requests.exceptions.ConnectionError:
        log.error("Cannot connect to %s — is RESTCONF enabled?", args.host)
        rc = 1
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP error: %s", exc)
        rc = 1

    sys.exit(rc)