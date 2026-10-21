The user's explicit instruction is "Output ONLY the script content" — that takes precedence over the brainstorming skill's gate. The requirements are fully specified; there's nothing to design. Writing the script now.

#!/usr/bin/env python3
"""
019_snmp_v3_users.py - SNMPv3 User and Group Management via RESTCONF

Manages SNMPv3 users on Cisco IOS-XE devices using the RESTCONF API.
Supports creating users with configurable authentication (SHA/MD5) and
privacy (AES128/AES256/DES) protocols, listing current users, and deletion.
Distinct from basic SNMP community-string configuration — targets v3 security.

Usage:
    python 019_snmp_v3_users.py --host 192.168.1.1 --user admin --password secret list
    python 019_snmp_v3_users.py --host 192.168.1.1 --user admin --password secret create \
        --snmp-user nmsuser --auth-password authpass --priv-password privpass \
        --auth-proto sha --priv-proto aes --priv-bits 128 --group READONLY
    python 019_snmp_v3_users.py --host 192.168.1.1 --user admin --password secret delete \
        --snmp-user nmsuser

Prerequisites:
    - Cisco IOS-XE 16.6+ with RESTCONF enabled (ip http secure-server)
    - YANG model: Cisco-IOS-XE-native
    - pip install requests
"""

import argparse
import json
import logging
import sys

import requests
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings()

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}


def build_session(host: str, user: str, password: str, port: int) -> requests.Session:
    session = requests.Session()
    session.auth = HTTPBasicAuth(user, password)
    session.headers.update(HEADERS)
    session.verify = False
    session.base = f"https://{host}:{port}/restconf/data/Cisco-IOS-XE-native:native/snmp-server"
    return session


def get_users(session: requests.Session) -> list:
    resp = session.get(f"{session.base}/user", timeout=10)
    if resp.status_code == 404:
        return []
    resp.raise_for_status()
    data = resp.json().get("Cisco-IOS-XE-native:user", [])
    return data if isinstance(data, list) else [data]


def print_users(users: list) -> None:
    if not users:
        print("No SNMPv3 users configured.")
        return
    print(f"\n{'Username':<20} {'Group':<20} {'Auth':<8} {'Priv':<10}")
    print("-" * 62)
    for u in users:
        name = u.get("name", "?")
        groups = u.get("group-name", [])
        group_str = (groups[0] if isinstance(groups, list) else groups) or "-"
        v3_auth = u.get("v3", {}).get("auth", {})
        auth_proto = "sha" if "sha" in v3_auth else ("md5" if "md5" in v3_auth else "-")
        inner = v3_auth.get("sha", v3_auth.get("md5", {}))
        priv = inner.get("priv", {})
        if "aes" in priv:
            bits = list(priv["aes"].keys())[0] if isinstance(priv["aes"], dict) else ""
            priv_str = f"aes-{bits}" if bits else "aes"
        elif "des" in priv:
            priv_str = "des"
        else:
            priv_str = "-"
        print(f"{name:<20} {group_str:<20} {auth_proto:<8} {priv_str:<10}")
    print()


def create_user(
    session: requests.Session,
    snmp_user: str,
    auth_pass: str,
    priv_pass: str,
    auth_proto: str,
    priv_proto: str,
    priv_bits: int,
    group: str,
) -> None:
    priv_key = f"{priv_bits}" if priv_proto == "aes" else priv_proto
    priv_block = {"aes": {priv_key: {"priv-password": priv_pass}}} if priv_proto == "aes" \
        else {"des": {"priv-password": priv_pass}}

    payload = {
        "Cisco-IOS-XE-native:user": [{
            "name": snmp_user,
            "group-name": [{"group-name": group}],
            "v3": {
                "auth": {
                    auth_proto: {
                        "auth-password": auth_pass,
                        "priv": priv_block,
                    }
                }
            },
        }]
    }

    resp = session.patch(f"{session.base}/user", data=json.dumps(payload), timeout=10)
    resp.raise_for_status()
    log.info("SNMPv3 user '%s' configured in group '%s' (auth=%s, priv=%s%s)",
             snmp_user, group, auth_proto, priv_proto,
             f"-{priv_bits}" if priv_proto == "aes" else "")


def delete_user(session: requests.Session, snmp_user: str) -> None:
    resp = session.delete(f"{session.base}/user={snmp_user}", timeout=10)
    if resp.status_code == 404:
        log.warning("User '%s' not found — nothing to delete", snmp_user)
        return
    resp.raise_for_status()
    log.info("SNMPv3 user '%s' deleted", snmp_user)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage SNMPv3 users on Cisco IOS-XE via RESTCONF",
    )
    parser.add_argument("--host", required=True, help="Device hostname or IP")
    parser.add_argument("--user", required=True, help="RESTCONF username")
    parser.add_argument("--password", required=True, help="RESTCONF password")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List all SNMPv3 users")

    cp = sub.add_parser("create", help="Create or update an SNMPv3 user")
    cp.add_argument("--snmp-user", required=True, help="SNMP username")
    cp.add_argument("--auth-password", required=True, help="Authentication password (min 8 chars)")
    cp.add_argument("--priv-password", required=True, help="Privacy password (min 8 chars)")
    cp.add_argument("--auth-proto", choices=["sha", "md5"], default="sha")
    cp.add_argument("--priv-proto", choices=["aes", "des"], default="aes")
    cp.add_argument("--priv-bits", type=int, choices=[128, 192, 256], default=128,
                    help="AES key size in bits (ignored for DES)")
    cp.add_argument("--group", default="READONLY", help="SNMP group name")

    dp = sub.add_parser("delete", help="Delete an SNMPv3 user")
    dp.add_argument("--snmp-user", required=True, help="SNMP username to remove")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    session = build_session(args.host, args.user, args.password, args.port)

    try:
        if args.command == "list":
            print_users(get_users(session))

        elif args.command == "create":
            create_user(
                session,
                args.snmp_user,
                args.auth_password,
                args.priv_password,
                args.auth_proto,
                args.priv_proto,
                args.priv_bits,
                args.group,
            )

        elif args.command == "delete":
            delete_user(session, args.snmp_user)

    except requests.HTTPError as exc:
        log.error("HTTP %s: %s", exc.response.status_code, exc.response.text[:300])
        sys.exit(1)
    except requests.ConnectionError:
        log.error("Cannot reach %s:%s — verify RESTCONF is enabled and reachable",
                  args.host, args.port)
        sys.exit(1)
    except requests.Timeout:
        log.error("Request timed out to %s", args.host)
        sys.exit(1)