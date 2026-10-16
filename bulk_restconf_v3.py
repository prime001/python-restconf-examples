```python
"""
011_ntp_config.py - NTP Server Management via RESTCONF

Manages NTP server configuration on Cisco IOS-XE devices using RESTCONF.
Supports listing, adding, and removing NTP servers and setting the NTP
source interface.

Usage:
    python 011_ntp_config.py --host 192.168.1.1 --user admin --password cisco --action list
    python 011_ntp_config.py --host 192.168.1.1 --user admin --password cisco \
        --action add --server 10.0.0.1 --prefer
    python 011_ntp_config.py --host 192.168.1.1 --user admin --password cisco \
        --action remove --server 10.0.0.1
    python 011_ntp_config.py --host 192.168.1.1 --user admin --password cisco \
        --action source --interface Loopback0

Prerequisites:
    - Cisco IOS-XE 16.6+ with RESTCONF enabled:
        ip http secure-server
        restconf
    - pip install requests
    - RESTCONF reachable on port 443 (or specify --port)
"""

import argparse
import logging
import sys

import requests
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}
NTP_PATH = "restconf/data/Cisco-IOS-XE-native:native/ntp"


def base_url(host, port):
    return f"https://{host}:{port}/{NTP_PATH}"


def get_ntp(session, host, port):
    resp = session.get(base_url(host, port), headers=HEADERS, verify=False)
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    return resp.json().get("Cisco-IOS-XE-native:ntp", {})


def list_ntp(session, host, port):
    cfg = get_ntp(session, host, port)
    servers = cfg.get("server", {}).get("server-list", [])
    src_list = cfg.get("source-interface", [])
    source = src_list[0].get("interface", "") if src_list else ""

    if not servers and not source:
        print("No NTP configuration found.")
        return

    if source:
        print(f"Source interface : {source}")
    if servers:
        print(f"\n{'Server':<20} {'Prefer':<8} {'Version'}")
        print("-" * 38)
        for entry in servers:
            ip_block = entry.get("ip", {})
            prefer = "yes" if "prefer" in ip_block else "no"
            version = ip_block.get("version", "-")
            print(f"{entry['ip-address']:<20} {prefer:<8} {version}")
    else:
        print("No NTP servers configured.")


def add_server(session, host, port, server_ip, prefer):
    cfg = get_ntp(session, host, port)
    servers = cfg.get("server", {}).get("server-list", [])

    if any(s["ip-address"] == server_ip for s in servers):
        log.warning("Server %s already present — skipping.", server_ip)
        return

    ip_block = {}
    if prefer:
        ip_block["prefer"] = [None]

    servers.append({"ip-address": server_ip, "ip": ip_block})
    payload = {
        "Cisco-IOS-XE-native:ntp": {
            "server": {"server-list": servers}
        }
    }
    resp = session.patch(base_url(host, port), headers=HEADERS, json=payload, verify=False)
    resp.raise_for_status()
    log.info("Added NTP server %s (prefer=%s).", server_ip, prefer)


def remove_server(session, host, port, server_ip):
    url = f"{base_url(host, port)}/server/server-list={server_ip}"
    resp = session.delete(url, headers=HEADERS, verify=False)
    if resp.status_code == 404:
        log.warning("Server %s not found — nothing removed.", server_ip)
        return
    resp.raise_for_status()
    log.info("Removed NTP server %s.", server_ip)


def set_source(session, host, port, interface):
    payload = {
        "Cisco-IOS-XE-native:ntp": {
            "source-interface": [{"interface": interface}]
        }
    }
    resp = session.patch(base_url(host, port), headers=HEADERS, json=payload, verify=False)
    resp.raise_for_status()
    log.info("NTP source interface set to %s.", interface)


def parse_args():
    p = argparse.ArgumentParser(
        description="Manage NTP configuration on Cisco IOS-XE via RESTCONF."
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--user", required=True, help="RESTCONF username")
    p.add_argument("--password", required=True, help="RESTCONF password")
    p.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    p.add_argument(
        "--action",
        required=True,
        choices=["list", "add", "remove", "source"],
        help="Action: list servers | add server | remove server | set source interface",
    )
    p.add_argument("--server", help="NTP server IP address (required for add/remove)")
    p.add_argument("--prefer", action="store_true", help="Mark as preferred server (add only)")
    p.add_argument("--interface", help="Source interface name, e.g. Loopback0 (required for source)")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


def main():
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.action in ("add", "remove") and not args.server:
        print(f"error: --server is required for action '{args.action}'", file=sys.stderr)
        sys.exit(1)
    if args.action == "source" and not args.interface:
        print("error: --interface is required for action 'source'", file=sys.stderr)
        sys.exit(1)

    session = requests.Session()
    session.auth = HTTPBasicAuth(args.user, args.password)

    try:
        if args.action == "list":
            list_ntp(session, args.host, args.port)
        elif args.action == "add":
            add_server(session, args.host, args.port, args.server, args.prefer)
        elif args.action == "remove":
            remove_server(session, args.host, args.port, args.server)
        elif args.action == "source":
            set_source(session, args.host, args.port, args.interface)
    except requests.HTTPError as exc:
        log.error("HTTP %s: %s", exc.response.status_code, exc.response.text[:200])
        sys.exit(1)
    except requests.ConnectionError as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
```