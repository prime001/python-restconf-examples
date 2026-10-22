```python
"""
023_vlan_operations.py - VLAN Compliance Auditor via RESTCONF

Purpose:
    Audits VLAN configurations across one or more Cisco IOS-XE devices using
    RESTCONF. Compares the live VLAN database against a JSON policy file that
    defines the expected VLAN state (IDs, names). Reports drift—missing VLANs,
    undeclared VLANs, name mismatches—and optionally remediates missing entries.

Usage:
    # Audit a single device
    python 023_vlan_operations.py --device 192.168.1.1 --policy vlans.json

    # Audit multiple devices
    python 023_vlan_operations.py --devices 192.168.1.1,192.168.1.2 --policy vlans.json

    # Audit and push missing VLANs
    python 023_vlan_operations.py --device 192.168.1.1 --policy vlans.json --remediate

    # JSON output for pipeline consumption
    python 023_vlan_operations.py --device 192.168.1.1 --policy vlans.json --output json

Policy file format (vlans.json):
    {
      "vlans": [
        {"id": 10, "name": "MGMT"},
        {"id": 20, "name": "SERVERS"},
        {"id": 99, "name": "NATIVE"}
      ]
    }

Prerequisites:
    - Cisco IOS-XE 16.6+ with RESTCONF enabled (ip restconf)
    - NETCONF/YANG support (netconf-yang)
    - Privilege-15 account with restconf access
    - pip install requests
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

RESTCONF_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}
VLAN_LIST_URL = (
    "https://{host}:{port}/restconf/data/Cisco-IOS-XE-native:native"
    "/vlan/Cisco-IOS-XE-vlan:vlan-list"
)


@dataclass
class VlanEntry:
    id: int
    name: str = ""


@dataclass
class AuditResult:
    device: str
    compliant: list = field(default_factory=list)
    missing: list = field(default_factory=list)
    extra: list = field(default_factory=list)
    name_mismatch: list = field(default_factory=list)
    error: Optional[str] = None

    @property
    def is_compliant(self) -> bool:
        return not (self.missing or self.extra or self.name_mismatch)

    def as_text(self) -> str:
        if self.error:
            return f"{self.device}: ERROR — {self.error}"
        status = "COMPLIANT" if self.is_compliant else "DRIFT"
        lines = [f"{self.device}: {status}"]
        if self.missing:
            lines.append(f"  missing VLANs   : {[v.id for v in self.missing]}")
        if self.extra:
            lines.append(f"  undeclared VLANs: {[v.id for v in self.extra]}")
        if self.name_mismatch:
            for m in self.name_mismatch:
                lines.append(
                    f"  name mismatch   : VLAN {m['id']} "
                    f"expected={m['expected']!r} actual={m['actual']!r}"
                )
        return "\n".join(lines)


def fetch_vlans(host: str, port: int, auth: HTTPBasicAuth) -> list:
    url = VLAN_LIST_URL.format(host=host, port=port)
    resp = requests.get(url, headers=RESTCONF_HEADERS, auth=auth, verify=False, timeout=15)
    resp.raise_for_status()
    raw = resp.json().get("Cisco-IOS-XE-vlan:vlan-list", [])
    return [VlanEntry(id=int(v["id"]), name=v.get("name", "")) for v in raw]


def push_vlan(host: str, port: int, auth: HTTPBasicAuth, vlan: VlanEntry) -> None:
    url = VLAN_LIST_URL.format(host=host, port=port) + f"={vlan.id}"
    body = {"Cisco-IOS-XE-vlan:vlan-list": [{"id": str(vlan.id), "name": vlan.name}]}
    resp = requests.put(
        url, headers=RESTCONF_HEADERS, auth=auth, json=body, verify=False, timeout=15
    )
    resp.raise_for_status()


def audit_device(host: str, port: int, auth: HTTPBasicAuth, policy: list) -> AuditResult:
    result = AuditResult(device=host)
    try:
        actual = fetch_vlans(host, port, auth)
    except requests.exceptions.ConnectionError as exc:
        result.error = f"connection refused: {exc}"
        return result
    except requests.exceptions.HTTPError as exc:
        result.error = f"HTTP {exc.response.status_code}"
        return result
    except Exception as exc:
        result.error = str(exc)
        return result

    actual_map = {v.id: v for v in actual}
    policy_map = {v.id: v for v in policy}

    for expected in policy:
        if expected.id not in actual_map:
            result.missing.append(expected)
        else:
            live = actual_map[expected.id]
            if expected.name and live.name != expected.name:
                result.name_mismatch.append(
                    {"id": expected.id, "expected": expected.name, "actual": live.name}
                )
            else:
                result.compliant.append(live)

    for vlan in actual:
        if vlan.id not in policy_map:
            result.extra.append(vlan)

    return result


def remediate_missing(host: str, port: int, auth: HTTPBasicAuth, result: AuditResult) -> None:
    for vlan in result.missing:
        log.info("%s: creating VLAN %d (%s)", host, vlan.id, vlan.name)
        try:
            push_vlan(host, port, auth, vlan)
        except requests.exceptions.HTTPError as exc:
            log.error("%s: failed to create VLAN %d — HTTP %s", host, vlan.id, exc.response.status_code)


def load_policy(path: str) -> list:
    with open(path) as fh:
        data = json.load(fh)
    return [VlanEntry(**v) for v in data["vlans"]]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Audit VLAN compliance across IOS-XE devices via RESTCONF"
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--device", metavar="HOST")
    target.add_argument("--devices", metavar="HOST,HOST", help="Comma-separated list")
    p.add_argument("--policy", required=True, metavar="FILE", help="JSON policy file")
    p.add_argument("-u", "--username", default="admin")
    p.add_argument("-p", "--password", default="admin")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--remediate", action="store_true", help="Push missing VLANs")
    p.add_argument("--output", choices=["text", "json"], default="text")
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.debug:
        log.setLevel(logging.DEBUG)

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    hosts = [h.strip() for h in (args.devices or args.device).split(",")]

    try:
        policy = load_policy(args.policy)
    except (FileNotFoundError, KeyError, json.JSONDecodeError) as exc:
        log.error("Policy load failed: %s", exc)
        return 1

    log.info("Auditing %d device(s) against %d-VLAN policy", len(hosts), len(policy))
    auth = HTTPBasicAuth(args.username, args.password)
    results = []

    for host in hosts:
        result = audit_device(host, args.port, auth, policy)
        if args.remediate and not result.error and result.missing:
            remediate_missing(host, args.port, auth, result)
            result = audit_device(host, args.port, auth, policy)
        results.append(result)

    if args.output == "json":
        out = [
            {
                "device": r.device,
                "compliant": r.is_compliant,
                "error": r.error,
                "missing": [{"id": v.id, "name": v.name} for v in r.missing],
                "extra": [{"id": v.id, "name": v.name} for v in r.extra],
                "name_mismatch": r.name_mismatch,
            }
            for r in results
        ]
        print(json.dumps(out, indent=2))
    else:
        for r in results:
            print(r.as_text())

    return 1 if any(r.error or not r.is_compliant for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
```