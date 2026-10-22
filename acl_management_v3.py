Writing the ACL compliance auditor script now.

```python
"""
ACL Compliance Auditor — RESTCONF-based ACL Policy Validation

Purpose:
    Audits device ACLs against a JSON baseline policy to detect drift,
    unauthorized entries, or missing rules. Generates a structured report
    and optionally remediates by pushing the baseline back to the device.

    Distinct from basic ACL CRUD scripts: this is a snapshot-diff-remediate
    workflow useful for change control, scheduled compliance runs, and CI gates.

Usage:
    # Export current device state as a baseline:
    python 022_acl_compliance_audit.py --host 192.168.1.1 --user admin \
        --password secret --export-baseline acl_policy.json

    # Audit device against a saved baseline:
    python 022_acl_compliance_audit.py --host 192.168.1.1 --user admin \
        --password secret --baseline acl_policy.json

    # Audit and auto-remediate drift:
    python 022_acl_compliance_audit.py --host 192.168.1.1 --user admin \
        --password secret --baseline acl_policy.json --remediate

    # Exit code 1 on drift (useful in CI pipelines):
    python 022_acl_compliance_audit.py ... --baseline acl_policy.json --fail-on-drift

Prerequisites:
    - Cisco IOS-XE device with RESTCONF enabled:
        ip http secure-server
        restconf
    - pip install requests
    - Device reachable on port 443 (default) or --port override
    - YANG model: Cisco-IOS-XE-native
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

RESTCONF_BASE = "https://{host}:{port}/restconf/data"
ACL_PATH = "Cisco-IOS-XE-native:native/ip/access-list"
HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}


@dataclass
class AuditResult:
    acl_name: str
    missing_entries: list = field(default_factory=list)
    extra_entries: list = field(default_factory=list)
    compliant: bool = True

    def summarize(self) -> str:
        if self.compliant:
            return f"  [{self.acl_name}] COMPLIANT"
        lines = [f"  [{self.acl_name}] NON-COMPLIANT"]
        for e in self.missing_entries:
            lines.append(f"    MISSING : {e}")
        for e in self.extra_entries:
            lines.append(f"    EXTRA   : {e}")
        return "\n".join(lines)


def build_session(user: str, password: str) -> requests.Session:
    session = requests.Session()
    session.auth = (user, password)
    session.headers.update(HEADERS)
    session.verify = False
    return session


def fetch_acls(session: requests.Session, host: str, port: int) -> dict:
    url = f"{RESTCONF_BASE.format(host=host, port=port)}/{ACL_PATH}"
    try:
        resp = session.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        log.error("Cannot connect to %s:%d — is RESTCONF enabled?", host, port)
        sys.exit(1)
    except requests.exceptions.HTTPError as exc:
        log.error("HTTP %s fetching ACLs: %s", exc.response.status_code, exc)
        sys.exit(1)


def normalize_entries(raw: dict) -> dict:
    """Flatten device ACL response into {name: [sorted rule strings]}."""
    result = {}
    acl_root = raw.get("Cisco-IOS-XE-native:access-list", raw.get("access-list", {}))
    for acl_type in ("extended", "standard"):
        for acl in acl_root.get(acl_type, []):
            name = acl.get("name", "")
            entries = []
            for seq in acl.get("access-list-seq-rule", []):
                seq_no = seq.get("sequence", "")
                rule = seq.get("ace-rule", {})
                action = rule.get("action", "")
                proto = rule.get("protocol", "ip")
                src = rule.get("ipv4-address", "any")
                entries.append(f"{seq_no} {action} {proto} {src}".strip())
            result[name] = sorted(entries)
    return result


def audit(device_acls: dict, baseline: dict) -> list:
    results = []
    for name in sorted(set(baseline) | set(device_acls)):
        expected = set(baseline.get(name, []))
        actual = set(device_acls.get(name, []))
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        results.append(AuditResult(
            acl_name=name,
            missing_entries=missing,
            extra_entries=extra,
            compliant=not missing and not extra,
        ))
    return results


def push_baseline(session: requests.Session, host: str, port: int, acl_root: dict):
    url = f"{RESTCONF_BASE.format(host=host, port=port)}/{ACL_PATH}"
    payload = {"Cisco-IOS-XE-native:access-list": acl_root}
    try:
        resp = session.put(url, json=payload, timeout=15)
        resp.raise_for_status()
        log.info("Baseline pushed successfully.")
    except requests.exceptions.HTTPError as exc:
        log.error("Remediation failed (%s): %s", exc.response.status_code, resp.text[:300])
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit device ACLs against a compliance baseline via RESTCONF"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--port", type=int, default=443, help="RESTCONF port (default: 443)")
    parser.add_argument("--user", required=True, help="Username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--baseline", help="Path to baseline JSON policy file")
    parser.add_argument(
        "--export-baseline", metavar="FILE",
        help="Snapshot current device ACLs as baseline JSON and exit",
    )
    parser.add_argument(
        "--remediate", action="store_true",
        help="Push baseline to device for any non-compliant ACLs (requires --baseline)",
    )
    parser.add_argument(
        "--fail-on-drift", action="store_true",
        help="Exit with code 1 if drift detected (CI pipeline integration)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    session = build_session(args.user, args.password)

    log.info("Connecting to %s:%d", args.host, args.port)
    raw = fetch_acls(session, args.host, args.port)

    if args.export_baseline:
        with open(args.export_baseline, "w") as fh:
            json.dump(normalize_entries(raw), fh, indent=2)
        log.info("Baseline exported to %s", args.export_baseline)
        return

    if not args.baseline:
        log.error("Provide --baseline <file> to audit, or --export-baseline <file> to snapshot.")
        sys.exit(1)

    with open(args.baseline) as fh:
        baseline = json.load(fh)

    results = audit(normalize_entries(raw), baseline)
    non_compliant = [r for r in results if not r.compliant]

    print(f"\n=== ACL Compliance Report: {args.host} ===")
    for r in results:
        print(r.summarize())
    print(f"\nSummary: {len(results) - len(non_compliant)}/{len(results)} ACLs compliant\n")

    if non_compliant and args.remediate:
        log.info("Remediating %d non-compliant ACL(s)...", len(non_compliant))
        acl_root = raw.get("Cisco-IOS-XE-native:access-list", raw.get("access-list", {}))
        push_baseline(session, args.host, args.port, acl_root)

    if non_compliant and args.fail_on_drift:
        sys.exit(1)


if __name__ == "__main__":
    main()
```