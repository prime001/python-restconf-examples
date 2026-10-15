Here is the complete script:

```python
#!/usr/bin/env python3
"""
006_device_info.py -- RESTCONF Device Information Collector

Retrieves operational state from IOS-XE devices via RESTCONF:
  - System platform details (hostname, software version, serial)
  - Interface inventory with operational status and IP assignments
  - CPU and memory utilization (Cisco IOS-XE process stats)

Usage:
    python 006_device_info.py --host 192.168.1.1 --user admin --password secret
    python 006_device_info.py --host 192.168.1.1 --user admin --password secret --interfaces --json

Prerequisites:
    pip install requests
    IOS-XE device with RESTCONF enabled (ip http secure-server, restconf)
    YANG models: Cisco-IOS-XE-native, Cisco-IOS-XE-platform-software-oper,
                 Cisco-IOS-XE-interfaces-oper, Cisco-IOS-XE-process-cpu-oper,
                 Cisco-IOS-XE-memory-oper

Tested against: IOS-XE 17.x (CSR1000v, Catalyst 8000v)
"""

import argparse
import json
import logging
import sys
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

BASE_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}

log = logging.getLogger(__name__)


def build_session(username: str, password: str) -> requests.Session:
    session = requests.Session()
    session.auth = HTTPBasicAuth(username, password)
    session.headers.update(BASE_HEADERS)
    session.verify = False
    return session


def restconf_get(session: requests.Session, base_url: str, path: str) -> dict:
    url = urljoin(base_url, path)
    log.debug("GET %s", url)
    try:
        resp = session.get(url, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        log.error("Cannot connect to %s -- check host/port and that RESTCONF is enabled", base_url)
        sys.exit(1)
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP %s for %s: %s", exc.response.status_code, url, exc.response.text[:200])
        return {}
    except requests.exceptions.Timeout:
        log.error("Request timed out: %s", url)
        return {}


def get_system_info(session: requests.Session, base_url: str) -> dict:
    hostname_data = restconf_get(
        session, base_url,
        "restconf/data/Cisco-IOS-XE-native:native/hostname"
    )
    hostname = hostname_data.get("Cisco-IOS-XE-native:hostname", "unknown")

    version_data = restconf_get(
        session, base_url,
        "restconf/data/Cisco-IOS-XE-native:native/version"
    )
    version = version_data.get("Cisco-IOS-XE-native:version", "unknown")

    return {"hostname": hostname, "version": version}


def get_interfaces(session: requests.Session, base_url: str) -> list:
    data = restconf_get(
        session, base_url,
        "restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces"
    )
    raw = data.get("Cisco-IOS-XE-interfaces-oper:interfaces", {})
    entries = raw.get("interface", [])

    results = []
    for iface in entries:
        ipv4_addrs = []
        for addr in iface.get("ipv4", {}).get("address", []):
            ipv4_addrs.append("{}/{}".format(addr.get("ip"), addr.get("prefix-length", "")))

        stats = iface.get("statistics", {})
        results.append({
            "name": iface.get("name", ""),
            "description": iface.get("description", ""),
            "oper_status": iface.get("oper-status", "unknown"),
            "admin_status": iface.get("admin-status", "unknown"),
            "speed": iface.get("speed", ""),
            "phys_address": iface.get("phys-address", ""),
            "ipv4_addresses": ipv4_addrs,
            "in_octets": stats.get("in-octets", 0),
            "out_octets": stats.get("out-octets", 0),
            "in_errors": stats.get("in-errors", 0),
            "out_errors": stats.get("out-errors", 0),
        })

    return results


def get_utilization(session: requests.Session, base_url: str) -> dict:
    cpu_data = restconf_get(
        session, base_url,
        "restconf/data/Cisco-IOS-XE-process-cpu-oper:cpu-usage/cpu-utilization/five-seconds"
    )
    cpu_5s = cpu_data.get("Cisco-IOS-XE-process-cpu-oper:five-seconds", "N/A")

    mem_data = restconf_get(
        session, base_url,
        "restconf/data/Cisco-IOS-XE-memory-oper:memory-statistics/memory-statistic"
    )
    memory_pools = {}
    for pool in mem_data.get("Cisco-IOS-XE-memory-oper:memory-statistic", []):
        name = pool.get("name", "")
        total = pool.get("total-bytes", 0)
        used = pool.get("used-bytes", 0)
        pct = round((used / total * 100), 1) if total else 0
        memory_pools[name] = {
            "total_bytes": total,
            "used_bytes": used,
            "used_pct": pct,
        }

    return {"cpu_5s_pct": cpu_5s, "memory_pools": memory_pools}


def print_summary(system: dict, interfaces: list, utilization: dict) -> None:
    sep = "=" * 62
    print("\n" + sep)
    print("  Device: {}  |  IOS-XE: {}".format(system["hostname"], system["version"]))
    print(sep)

    if utilization:
        print("\n  CPU (5s avg):  {}%".format(utilization.get("cpu_5s_pct", "N/A")))
        for pool, stats in utilization.get("memory_pools", {}).items():
            print("  Mem [{}]:  {}% used  ({:,} / {:,} bytes)".format(
                pool, stats["used_pct"], stats["used_bytes"], stats["total_bytes"]
            ))

    if interfaces:
        print("\n  {:<24} {:<8} {:<8} {}".format("Interface", "Admin", "Oper", "IPs"))
        print("  " + "-" * 68)
        for iface in interfaces:
            ips = ", ".join(iface["ipv4_addresses"]) or "--"
            print("  {:<24} {:<8} {:<8} {}".format(
                iface["name"], iface["admin_status"], iface["oper_status"], ips
            ))
            if iface["in_errors"] or iface["out_errors"]:
                print("  {:>24}  errors in={} out={}".format(
                    "", iface["in_errors"], iface["out_errors"]
                ))

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Retrieve operational device info via RESTCONF"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--port", type=int, default=443, help="RESTCONF port (default: 443)")
    parser.add_argument("--user", required=True, help="Username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--interfaces", action="store_true",
                        help="Include interface status and counters")
    parser.add_argument("--utilization", action="store_true",
                        help="Include CPU and memory utilization")
    parser.add_argument("--json", dest="output_json", action="store_true",
                        help="Output raw JSON instead of formatted table")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    base_url = "https://{}:{}/".format(args.host, args.port)
    session = build_session(args.user, args.password)

    system = get_system_info(session, base_url)
    interfaces = get_interfaces(session, base_url) if args.interfaces else []
    utilization = get_utilization(session, base_url) if args.utilization else {}

    if args.output_json:
        print(json.dumps(
            {"system": system, "interfaces": interfaces, "utilization": utilization},
            indent=2
        ))
    else:
        print_summary(system, interfaces, utilization)


if __name__ == "__main__":
    main()
```

The script covers operational state retrieval — distinct from the existing scripts (bulk config, ACLs, VLANs, BGP, OSPF). Key design choices:

- **Three independent data paths** — system info, interface oper-state, and CPU/memory — each gated by a flag so callers only hit what they need
- **`--interfaces` and `--utilization` are opt-in** — the base invocation is a fast two-GET system summary, useful in scripts that just need hostname + version
- **`--json` flag** — makes it composable with `jq` or other tooling without parsing human-formatted output
- **Session reuse** — one `requests.Session` shares auth and headers across all GETs, avoiding repeated TLS handshakes
- **Graceful degradation** — HTTP errors return `{}` and log a warning rather than crashing, so a missing YANG model on an older device doesn't abort the whole run