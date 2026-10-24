```python
"""
030_yang_explorer.py - Multi-Device YANG Capability Comparison via RESTCONF

Purpose:
    Compares YANG module support across multiple network devices using RESTCONF.
    Identifies capability gaps, revision mismatches, and device-exclusive modules
    in heterogeneous environments — essential before deploying model-dependent automation.

Usage:
    python 030_yang_explorer.py --devices 192.168.1.1,192.168.1.2 \
        --username admin --password secret

    python 030_yang_explorer.py --devices 192.168.1.1,192.168.1.2,192.168.1.3 \
        --username admin --password secret \
        --filter ietf --port 443 --output report.json --debug

Prerequisites:
    pip install requests
    RESTCONF enabled on target devices (Cisco IOS-XE: ip http secure-server)
    Devices must support ietf-yang-library (RFC 8525) or modules-state (RFC 7895)
    Credentials require at minimum RESTCONF read privilege
"""

import argparse
import json
import logging
import sys
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger(__name__)

RESTCONF_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}

# Ordered by RFC preference — try RFC 8525 first, fall back to RFC 7895
YANG_LIBRARY_PATHS = [
    "/restconf/data/ietf-yang-library:yang-library",
    "/restconf/data/ietf-yang-library:modules-state",
]


def build_session(username: str, password: str, timeout: int) -> requests.Session:
    session = requests.Session()
    session.auth = (username, password)
    session.headers.update(RESTCONF_HEADERS)
    session.verify = False
    session.timeout = timeout
    return session


def fetch_yang_library(session: requests.Session, base_url: str) -> Optional[dict]:
    for path in YANG_LIBRARY_PATHS:
        url = base_url + path
        try:
            resp = session.get(url)
            if resp.status_code == 200:
                log.debug("YANG library fetched via %s", path)
                return resp.json()
            log.debug("Path %s returned HTTP %d", path, resp.status_code)
        except requests.exceptions.ConnectionError as exc:
            log.debug("Connection failed for %s: %s", url, exc)
        except requests.exceptions.Timeout:
            log.debug("Timeout reaching %s", url)
        except requests.exceptions.RequestException as exc:
            log.debug("Request error for %s: %s", url, exc)
    return None


def extract_modules(data: dict, name_filter: str) -> dict:
    """Parse both RFC 8525 and RFC 7895 YANG library formats."""
    modules = {}

    # RFC 8525: ietf-yang-library/yang-library/module-set[]/module[]
    yang_lib = data.get("ietf-yang-library:yang-library", {})
    for module_set in yang_lib.get("module-set", []):
        for mod in module_set.get("module", []):
            name = mod.get("name", "")
            if name_filter and name_filter not in name:
                continue
            modules[name] = {
                "revision": mod.get("revision", ""),
                "namespace": mod.get("namespace", ""),
                "features": mod.get("feature", []),
                "deviations": [d.get("name", "") for d in mod.get("deviation", [])],
            }

    # RFC 7895: ietf-yang-library/modules-state/module[]
    modules_state = data.get("ietf-yang-library:modules-state", {})
    for mod in modules_state.get("module", []):
        name = mod.get("name", "")
        if name_filter and name_filter not in name:
            continue
        if name not in modules:
            modules[name] = {
                "revision": mod.get("revision", ""),
                "namespace": mod.get("namespace", ""),
                "features": mod.get("feature", []),
                "deviations": [d.get("deviation", "") for d in mod.get("deviation", [])],
            }

    return modules


def compare_capabilities(device_modules: dict) -> dict:
    all_names = set()
    for mods in device_modules.values():
        all_names.update(mods.keys())

    devices = list(device_modules.keys())
    common = all_names.copy()
    for mods in device_modules.values():
        common &= set(mods.keys())

    report = {
        "devices": devices,
        "total_unique_modules": len(all_names),
        "common_module_count": len(common),
        "common_modules": sorted(common),
        "per_device": {},
        "partial_support": {},
        "revision_mismatches": [],
    }

    for device, mods in device_modules.items():
        report["per_device"][device] = {
            "module_count": len(mods),
            "unique_to_device": sorted(set(mods) - common),
        }

    # Modules present on some but not all devices
    for name in all_names - common:
        supporting = [d for d, mods in device_modules.items() if name in mods]
        report["partial_support"][name] = supporting

    # Revision mismatches among commonly supported modules
    for name in common:
        revisions = {d: device_modules[d][name]["revision"] for d in devices}
        if len(set(revisions.values())) > 1:
            report["revision_mismatches"].append({"module": name, "revisions": revisions})

    return report


def print_report(report: dict) -> None:
    devices = report["devices"]
    sep = "=" * 64
    print(f"\n{sep}")
    print(f"  YANG Capability Comparison ({len(devices)} device(s))")
    print(sep)
    print(f"  Devices            : {', '.join(devices)}")
    print(f"  Unique modules     : {report['total_unique_modules']}")
    print(f"  Shared by all      : {report['common_module_count']}")
    print(f"  Partial support    : {len(report['partial_support'])}")
    print(f"  Revision mismatches: {len(report['revision_mismatches'])}")

    for device, stats in report["per_device"].items():
        excl = stats["unique_to_device"]
        print(f"\n  [{device}]")
        print(f"    Total modules : {stats['module_count']}")
        if excl:
            preview = ", ".join(excl[:4])
            suffix = f" ... +{len(excl) - 4} more" if len(excl) > 4 else ""
            print(f"    Device-only   : {preview}{suffix}")

    if report["revision_mismatches"]:
        print(f"\n  Revision mismatches (first 8 shown):")
        for item in report["revision_mismatches"][:8]:
            print(f"    {item['module']}")
            for dev, rev in item["revisions"].items():
                print(f"      {dev}: {rev or '(none)'}")
        remainder = len(report["revision_mismatches"]) - 8
        if remainder > 0:
            print(f"    ... and {remainder} more (see JSON output)")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare YANG module capabilities across devices via RESTCONF"
    )
    parser.add_argument(
        "--devices", required=True,
        help="Comma-separated device IPs or hostnames"
    )
    parser.add_argument("--username", required=True, help="RESTCONF username")
    parser.add_argument("--password", required=True, help="RESTCONF password")
    parser.add_argument(
        "--port", type=int, default=443,
        help="RESTCONF HTTPS port (default: 443)"
    )
    parser.add_argument(
        "--filter", dest="name_filter", default="",
        metavar="PREFIX",
        help="Filter modules by name substring (e.g. 'ietf', 'Cisco-IOS-XE')"
    )
    parser.add_argument(
        "--timeout", type=int, default=15,
        help="Per-request timeout in seconds (default: 15)"
    )
    parser.add_argument("--output", metavar="FILE", help="Write JSON report to file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    device_list = [d.strip() for d in args.devices.split(",") if d.strip()]
    if not device_list:
        log.error("No valid devices provided via --devices")
        sys.exit(1)

    session = build_session(args.username, args.password, args.timeout)
    device_modules: dict = {}

    for device in device_list:
        base_url = f"https://{device}:{args.port}"
        log.info("Querying YANG library: %s", device)
        data = fetch_yang_library(session, base_url)
        if data is None:
            log.warning("No YANG library response from %s — skipping", device)
            continue
        mods = extract_modules(data, args.name_filter)
        log.info("%s: %d module(s) found", device, len(mods))
        device_modules[device] = mods

    if not device_modules:
        log.error("No devices responded successfully; check connectivity and credentials")
        sys.exit(1)

    report = compare_capabilities(device_modules)
    print_report(report)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)
        log.info("JSON report written to %s", args.output)


if __name__ == "__main__":
    main()
```