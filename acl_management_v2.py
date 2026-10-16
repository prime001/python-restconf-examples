```python
"""
ACL Compliance Auditor — RESTCONF-based policy validation for IOS-XE

Purpose:
    Reads all IP access-lists from a Cisco IOS-XE device via RESTCONF and
    validates them against a JSON policy baseline. Reports missing required
    ACLs, unapproved (orphaned) ACLs, and forbidden ACE rule matches.
    Exits non-zero when any violation is found, making it CI-pipeline-friendly.

Usage:
    python 012_acl_audit.py --host 192.168.1.1 --user admin --policy policy.json
    python 012_acl_audit.py --host 192.168.1.1 --user admin --policy policy.json \
        --report audit_report.json --debug

Prerequisites:
    - IOS-XE 16.6+ with RESTCONF enabled:
        ip http secure-server
        restconf
    - pip install requests
    - Policy baseline JSON (example):
        {
          "required_acls": ["ACL_MGMT_IN", "ACL_INTERNET_OUT"],
          "approved_acl_names": ["ACL_MGMT_IN", "ACL_INTERNET_OUT", "ACL_VOIP"],
          "forbidden_sequences": [
            {"acl": "ACL_MGMT_IN", "action": "permit", "destination": "any"}
          ]
        }
      Omit any key to skip that check. approved_acl_names defaults to
      permitting all present ACLs (no orphan check performed).
"""

import argparse
import getpass
import json
import logging
import sys
from datetime import datetime, timezone

import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}
_ACL_PATH = "/restconf/data/Cisco-IOS-XE-native:native/ip/access-list"


def _session(username: str, password: str) -> requests.Session:
    s = requests.Session()
    s.auth = HTTPBasicAuth(username, password)
    s.headers.update(_HEADERS)
    s.verify = False
    return s


def fetch_acls(session: requests.Session, base_url: str) -> dict:
    url = f"{base_url}{_ACL_PATH}"
    log.debug("GET %s", url)
    try:
        r = session.get(url, timeout=15)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        log.error("Cannot reach device at %s", base_url)
        sys.exit(1)
    except requests.exceptions.HTTPError as exc:
        log.error("RESTCONF HTTP %s: %s", exc.response.status_code, exc.response.text[:200])
        sys.exit(1)


def _acl_root(raw: dict) -> dict:
    return raw.get("Cisco-IOS-XE-native:access-list", {})


def acl_names(raw: dict) -> list[str]:
    root = _acl_root(raw)
    names = []
    for kind in ("extended", "standard"):
        for acl in root.get(kind, []):
            if name := acl.get("name"):
                names.append(name)
    return names


def acl_entries(raw: dict) -> list[dict]:
    rows = []
    for acl in _acl_root(raw).get("extended", []):
        acl_name = acl.get("name", "")
        for ace in acl.get("access-list-seq-rule", []):
            rule = ace.get("ace-rule", {})
            rows.append({
                "acl": acl_name,
                "sequence": ace.get("sequence"),
                "action": rule.get("action", ""),
                "protocol": rule.get("protocol", ""),
                "destination": rule.get("dst-any-dst", ""),
            })
    return rows


def check_missing(present: list[str], required: list[str]) -> list[str]:
    return [a for a in required if a not in present]


def check_orphaned(present: list[str], approved: list[str] | None) -> list[str]:
    if approved is None:
        return []
    return [a for a in present if a not in approved]


def check_forbidden(entries: list[dict], forbidden: list[dict]) -> list[dict]:
    hits = []
    for rule in forbidden:
        for entry in entries:
            if all(entry.get(k) == v for k, v in rule.items() if k in entry):
                hits.append({"rule": rule, "matched_entry": entry})
    return hits


def audit(raw: dict, policy: dict) -> dict:
    names = acl_names(raw)
    entries = acl_entries(raw)

    missing = check_missing(names, policy.get("required_acls", []))
    orphaned = check_orphaned(names, policy.get("approved_acl_names"))
    forbidden_hits = check_forbidden(entries, policy.get("forbidden_sequences", []))
    compliant = not (missing or orphaned or forbidden_hits)

    return {
        "compliant": compliant,
        "acls_present": names,
        "missing_required": missing,
        "orphaned": orphaned,
        "forbidden_violations": forbidden_hits,
        "summary": {
            "acl_count": len(names),
            "missing_count": len(missing),
            "orphaned_count": len(orphaned),
            "violation_count": len(forbidden_hits),
        },
    }


def print_findings(result: dict, host: str) -> None:
    status = "PASS" if result["compliant"] else "FAIL"
    log.info("%-6s  device=%s  acls=%d", status, host, result["summary"]["acl_count"])
    for name in result["missing_required"]:
        log.warning("MISSING required ACL: %s", name)
    for name in result["orphaned"]:
        log.warning("ORPHANED (unapproved) ACL: %s", name)
    for hit in result["forbidden_violations"]:
        log.warning("FORBIDDEN rule matched — rule=%s  entry=%s", hit["rule"], hit["matched_entry"])


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Audit IOS-XE ACLs against a compliance policy baseline via RESTCONF"
    )
    p.add_argument("--host", required=True, help="Device hostname or IP")
    p.add_argument("--port", type=int, default=443, help="RESTCONF port (default: 443)")
    p.add_argument("--user", required=True, help="RESTCONF username")
    p.add_argument("--password", help="RESTCONF password (prompted if omitted)")
    p.add_argument("--policy", required=True, help="Path to policy baseline JSON file")
    p.add_argument("--report", help="Write JSON audit report to this file")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.user}@{args.host}: ")

    try:
        with open(args.policy) as fh:
            policy = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        log.error("Cannot load policy file: %s", exc)
        sys.exit(1)

    base_url = f"https://{args.host}:{args.port}"
    session = _session(args.user, password)

    log.info("Fetching ACL config from %s", args.host)
    raw = fetch_acls(session, base_url)

    result = audit(raw, policy)
    result["device"] = args.host
    result["timestamp"] = datetime.now(timezone.utc).isoformat()

    print_findings(result, args.host)

    if args.report:
        with open(args.report, "w") as fh:
            json.dump(result, fh, indent=2)
        log.info("Report written to %s", args.report)

    sys.exit(0 if result["compliant"] else 1)
```