```python
"""
032_acl_management.py - RESTCONF ACL Compliance Auditor

Purpose:
    Audits access control lists on IOS-XE devices against a policy baseline,
    reporting violations and optionally remediating missing entries via RESTCONF.

Usage:
    python 032_acl_management.py --host 192.168.1.1 --user admin --password secret
    python 032_acl_management.py --host 192.168.1.1 --user admin --password secret \
        --policy acl_policy.json --remediate
    python 032_acl_management.py --host 192.168.1.1 --user admin --password secret \
        --acl MGMT_ACCESS --report-only

Prerequisites:
    - IOS-XE 16.6+ with RESTCONF enabled (ip http secure-server, restconf)
    - requests library: pip install requests
    - Device credentials with privilege 15
    - Policy baseline JSON file (see --policy flag; uses built-in default if omitted)

Policy JSON format:
    {
      "acls": [
        {
          "name": "MGMT_ACCESS",
          "required_entries": [
            {"sequence": 10, "action": "permit", "protocol": "tcp",
             "source": "10.0.0.0/8", "destination": "any", "dst-port": "22"}
          ],
          "deny_any_last": true
        }
      ]
    }
"""

import argparse
import json
import logging
import sys
import urllib3

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://{host}:443/restconf/data"
HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}

DEFAULT_POLICY = {
    "acls": [
        {
            "name": "MGMT_ACCESS",
            "required_entries": [
                {
                    "sequence": 10,
                    "action": "permit",
                    "protocol": "tcp",
                    "source": "10.0.0.0 0.255.255.255",
                    "destination": "any",
                    "dst-port": "22",
                },
            ],
            "deny_any_last": True,
        }
    ]
}

log = logging.getLogger(__name__)


def get_session(user: str, password: str) -> requests.Session:
    session = requests.Session()
    session.auth = (user, password)
    session.headers.update(HEADERS)
    session.verify = False
    return session


def fetch_acl(session: requests.Session, host: str, acl_name: str) -> dict | None:
    url = f"{BASE_URL.format(host=host)}/Cisco-IOS-XE-native:native/ip/access-list/extended={acl_name}"
    try:
        resp = session.get(url, timeout=15)
        if resp.status_code == 404:
            log.warning("ACL '%s' not found on device.", acl_name)
            return None
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        log.error("Failed to fetch ACL '%s': %s", acl_name, exc)
        return None


def push_ace(session: requests.Session, host: str, acl_name: str, entry: dict) -> bool:
    url = f"{BASE_URL.format(host=host)}/Cisco-IOS-XE-native:native/ip/access-list/extended={acl_name}"
    seq = entry["sequence"]
    payload = {
        "Cisco-IOS-XE-acl:access-list-seq-rule": [
            {
                "sequence": str(seq),
                "ace-rule": {
                    "action": entry["action"],
                    "protocol": entry["protocol"],
                    "ipv4-address": entry["source"],
                    "dest-ipv4-address": entry["destination"],
                },
            }
        ]
    }
    try:
        resp = session.patch(url, json=payload, timeout=15)
        resp.raise_for_status()
        log.info("Pushed sequence %s to ACL '%s'.", seq, acl_name)
        return True
    except requests.RequestException as exc:
        log.error("Failed to push ACE seq %s to '%s': %s", seq, acl_name, exc)
        return False


def audit_acl(device_acl: dict | None, policy_acl: dict) -> list[dict]:
    violations = []
    acl_name = policy_acl["name"]

    if device_acl is None:
        violations.append({"type": "missing_acl", "acl": acl_name, "detail": "ACL absent on device"})
        return violations

    raw_rules = device_acl.get("Cisco-IOS-XE-acl:extended", {})
    raw_rules = raw_rules if isinstance(raw_rules, dict) else {}
    seq_rules = raw_rules.get("access-list-seq-rule", [])
    device_seqs = {int(r["sequence"]): r for r in seq_rules}

    for required in policy_acl.get("required_entries", []):
        seq = required["sequence"]
        if seq not in device_seqs:
            violations.append({
                "type": "missing_entry",
                "acl": acl_name,
                "sequence": seq,
                "detail": f"Required sequence {seq} absent",
                "entry": required,
            })
        else:
            ace = device_seqs[seq].get("ace-rule", {})
            if ace.get("action") != required.get("action"):
                violations.append({
                    "type": "action_mismatch",
                    "acl": acl_name,
                    "sequence": seq,
                    "detail": f"Expected action '{required['action']}', got '{ace.get('action')}'",
                    "entry": required,
                })

    if policy_acl.get("deny_any_last") and seq_rules:
        last = seq_rules[-1].get("ace-rule", {})
        if last.get("action") != "deny":
            violations.append({
                "type": "missing_deny_any",
                "acl": acl_name,
                "detail": "Last ACE is not an explicit deny",
            })

    return violations


def main():
    parser = argparse.ArgumentParser(
        description="Audit IOS-XE ACLs against a compliance policy via RESTCONF."
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--user", required=True, help="RESTCONF username")
    parser.add_argument("--password", required=True, help="RESTCONF password")
    parser.add_argument("--policy", help="Path to policy JSON file (uses built-in default if omitted)")
    parser.add_argument("--acl", help="Audit a single named ACL (overrides policy list)")
    parser.add_argument("--remediate", action="store_true", help="Push missing entries to device")
    parser.add_argument("--report-only", action="store_true", help="Print violations without exit code change")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.policy:
        try:
            with open(args.policy) as fh:
                policy = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Cannot load policy file: %s", exc)
            sys.exit(1)
    else:
        policy = DEFAULT_POLICY
        log.info("No policy file specified — using built-in default.")

    if args.acl:
        policy["acls"] = [p for p in policy["acls"] if p["name"] == args.acl]
        if not policy["acls"]:
            policy["acls"] = [{"name": args.acl, "required_entries": [], "deny_any_last": True}]

    session = get_session(args.user, args.password)
    all_violations = []

    for acl_policy in policy["acls"]:
        acl_name = acl_policy["name"]
        log.info("Auditing ACL: %s", acl_name)
        device_acl = fetch_acl(session, args.host, acl_name)
        violations = audit_acl(device_acl, acl_policy)
        all_violations.extend(violations)

        if violations:
            for v in violations:
                log.warning("VIOLATION [%s] %s – %s", v["type"], v["acl"], v["detail"])
            if args.remediate:
                for v in violations:
                    if v["type"] in ("missing_entry", "action_mismatch") and "entry" in v:
                        push_ace(session, args.host, acl_name, v["entry"])
        else:
            log.info("ACL '%s' is compliant.", acl_name)

    print(f"\nAudit complete: {len(all_violations)} violation(s) found across {len(policy['acls'])} ACL(s).")

    if all_violations and not args.report_only:
        sys.exit(2)


if __name__ == "__main__":
    main()
```