010_yang_explorer.py - RESTCONF YANG Module Explorer

Purpose:
    Discover and inspect YANG data models supported by a RESTCONF-capable
    network device. Uses the IETF YANG Library (RFC 7895 / RFC 8525) to
    enumerate modules, revisions, namespaces, and conformance types.
    Useful for auditing device capabilities before writing automation.

Usage:
    python 010_yang_explorer.py --host 192.168.1.1 -u admin -p cisco
    python 010_yang_explorer.py --host 192.168.1.1 -u admin -p cisco --filter ietf
    python 010_yang_explorer.py --host 192.168.1.1 -u admin -p cisco --module ietf-interfaces
    python 010_yang_explorer.py --host 192.168.1.1 -u admin -p cisco --module ietf-interfaces --schema

Prerequisites:
    - pip install requests
    - Device must support RESTCONF (RFC 8040)
    - Device must implement IETF YANG Library (RFC 7895 or RFC 8525)
    - Tested against IOS-XE 16.9+, IOS-XR 6.5+, NX-OS 9.2+
"""

import argparse
import json
import logging
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

YANG_LIBRARY_PATHS = [
    "/restconf/data/ietf-yang-library:yang-library",   # RFC 8525
    "/restconf/data/ietf-yang-library:modules-state",  # RFC 7895
]


def build_session(username, password):
    session = requests.Session()
    session.auth = (username, password)
    session.headers.update({
        "Accept": "application/yang-data+json",
        "Content-Type": "application/yang-data+json",
    })
    session.verify = False
    return session


def fetch_yang_library(base_url, session):
    for path in YANG_LIBRARY_PATHS:
        url = base_url + path
        try:
            resp = session.get(url, timeout=15)
            if resp.status_code == 200:
                log.debug("YANG library found at %s", path)
                return resp.json()
            log.debug("Path %s returned HTTP %d", path, resp.status_code)
        except requests.RequestException as exc:
            log.debug("Request failed for %s: %s", path, exc)

    log.error("Device does not expose a YANG library at known RESTCONF paths.")
    sys.exit(1)


def parse_modules(library_data):
    yang_lib = library_data.get("ietf-yang-library:yang-library", {})
    if yang_lib:
        modules = []
        for module_set in yang_lib.get("module-set", []):
            for mod in module_set.get("module", []):
                modules.append({
                    "name": mod.get("name", ""),
                    "revision": mod.get("revision", ""),
                    "namespace": mod.get("namespace", ""),
                    "conformance": "implement",
                    "features": mod.get("feature", []),
                })
            for mod in module_set.get("import-only-module", []):
                modules.append({
                    "name": mod.get("name", ""),
                    "revision": mod.get("revision", ""),
                    "namespace": mod.get("namespace", ""),
                    "conformance": "import",
                    "features": [],
                })
        return modules

    modules_state = library_data.get("ietf-yang-library:modules-state", {})
    if modules_state:
        return [
            {
                "name": m.get("name", ""),
                "revision": m.get("revision", ""),
                "namespace": m.get("namespace", ""),
                "conformance": m.get("conformance-type", ""),
                "features": m.get("feature", []),
            }
            for m in modules_state.get("module", [])
        ]

    log.error("Unrecognized YANG library response structure.")
    return []


def fetch_schema(base_url, session, module, revision):
    url = base_url + f"/restconf/tailf/modules/{module}/{revision}"
    try:
        resp = session.get(url, timeout=30, headers={"Accept": "application/yang"})
        if resp.status_code == 200:
            return resp.text
        log.warning(
            "Schema fetch returned HTTP %d — device may not expose raw YANG schemas",
            resp.status_code,
        )
        return ""
    except requests.RequestException as exc:
        log.error("Schema fetch failed: %s", exc)
        return ""


def print_module_table(modules, name_filter):
    filtered = [
        m for m in modules
        if not name_filter or name_filter.lower() in m["name"].lower()
    ]
    filtered.sort(key=lambda m: m["name"])

    print(f"\n{'NAME':<45} {'REVISION':<12} {'CONFORMANCE':<12} FEATURES")
    print("-" * 100)
    for m in filtered:
        features = ", ".join(m["features"]) if m["features"] else "-"
        print(f"{m['name']:<45} {m['revision'] or 'N/A':<12} {m['conformance']:<12} {features}")
    print(f"\nTotal: {len(filtered)} module(s)")


def main():
    parser = argparse.ArgumentParser(
        description="Explore YANG modules available on a RESTCONF device.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--port", type=int, default=443, help="RESTCONF port (default: 443)")
    parser.add_argument("-u", "--user", required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("--filter", metavar="PATTERN", help="Filter module list by name substring")
    parser.add_argument("--module", metavar="NAME", help="Show detail for a specific module")
    parser.add_argument(
        "--schema",
        action="store_true",
        help="Fetch raw YANG schema for --module (requires Tail-f/Cisco schema endpoint)",
    )
    parser.add_argument("--json", dest="output_json", action="store_true", help="Dump raw YANG library JSON")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.schema and not args.module:
        parser.error("--schema requires --module")

    base_url = f"https://{args.host}:{args.port}"
    session = build_session(args.user, args.password)

    log.info("Connecting to %s", base_url)
    library_data = fetch_yang_library(base_url, session)

    if args.output_json:
        print(json.dumps(library_data, indent=2))
        return

    modules = parse_modules(library_data)
    if not modules:
        log.error("No modules found in YANG library response.")
        sys.exit(1)

    log.info("Device reports %d YANG module(s)", len(modules))

    if args.module:
        match = [m for m in modules if m["name"] == args.module]
        if not match:
            log.error("Module '%s' not found on this device.", args.module)
            sys.exit(1)
        m = match[0]
        print(f"\nModule:      {m['name']}")
        print(f"Revision:    {m['revision'] or 'N/A'}")
        print(f"Namespace:   {m['namespace']}")
        print(f"Conformance: {m['conformance']}")
        print(f"Features:    {', '.join(m['features']) or 'none'}")
        if args.schema:
            print("\n--- YANG Schema ---")
            schema = fetch_schema(base_url, session, m["name"], m["revision"])
            print(schema if schema else "(schema not available via this endpoint)")
    else:
        print_module_table(modules, args.filter)


if __name__ == "__main__":
    main()