028_interface_stats_monitor.py - RESTCONF Interface Error Statistics Monitor

Purpose:
    Polls IOS-XE interface statistics via RESTCONF using the ietf-interfaces
    YANG model. Reads per-interface counters for errors, discards, and octets,
    then computes inter-poll deltas to expose active error rates rather than
    cumulative totals. Exits non-zero when any interface exceeds the configured
    threshold — suitable for monitoring pipelines or manual triage.

Usage:
    # One-shot table of all interface error counters:
    python 028_interface_stats_monitor.py --device 192.168.1.1 \
        --username admin --password secret

    # Two polls 30 s apart; alert if errors/s > 5:
    python 028_interface_stats_monitor.py --device 192.168.1.1 \
        --username admin --password secret \
        --interval 30 --threshold 5

    # Single interface, JSON output:
    python 028_interface_stats_monitor.py --device 192.168.1.1 \
        --username admin --password secret \
        --interface GigabitEthernet1 --json

Prerequisites:
    pip install requests
    IOS-XE 16.6+ with RESTCONF enabled:
        ip http secure-server
        ip http authentication local
        restconf
    User requires NETCONF privilege or privilege 15.
"""

import argparse
import json
import logging
import sys
import time

import requests
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

RESTCONF_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}

_STATS_PATH = "restconf/data/ietf-interfaces:interfaces-state/interface"


def build_session(username, password, verify_ssl=False):
    session = requests.Session()
    session.auth = HTTPBasicAuth(username, password)
    session.headers.update(RESTCONF_HEADERS)
    session.verify = verify_ssl
    return session


def fetch_interface_stats(session, base_url, interface=None):
    """Return a dict keyed by interface name with counter sub-dicts."""
    url = f"{base_url}/{_STATS_PATH}"
    if interface:
        url = f"{url}={interface}"

    log.debug("GET %s", url)
    try:
        resp = session.get(url, timeout=15)
    except requests.ConnectionError as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)
    except requests.Timeout:
        log.error("Request timed out to %s", base_url)
        sys.exit(1)

    if resp.status_code == 404:
        log.error("RESTCONF path not found — verify IOS-XE YANG support")
        sys.exit(1)
    if not resp.ok:
        log.error("HTTP %d: %s", resp.status_code, resp.text[:200])
        sys.exit(1)

    data = resp.json()
    entries = data.get("ietf-interfaces:interface", [])
    if isinstance(entries, dict):
        entries = [entries]

    result = {}
    for iface in entries:
        name = iface.get("name", "unknown")
        s = iface.get("statistics", {})
        result[name] = {
            "in_octets": int(s.get("in-octets", 0)),
            "out_octets": int(s.get("out-octets", 0)),
            "in_errors": int(s.get("in-errors", 0)),
            "out_errors": int(s.get("out-errors", 0)),
            "in_discards": int(s.get("in-discards", 0)),
            "out_discards": int(s.get("out-discards", 0)),
        }
    return result


def compute_deltas(before, after, elapsed):
    """Return per-interface per-counter rates (counts/s) between two snapshots."""
    deltas = {}
    for name, counters in after.items():
        prev = before.get(name, {})
        deltas[name] = {
            key: round(max(0, val - prev.get(key, val)) / elapsed, 3)
            for key, val in counters.items()
        }
    return deltas


def check_thresholds(deltas, threshold):
    error_keys = ("in_errors", "out_errors", "in_discards", "out_discards")
    violations = []
    for name, rates in deltas.items():
        for key in error_keys:
            if rates.get(key, 0) > threshold:
                violations.append((name, key, rates[key]))
    return violations


def print_table(stats, label="Counters", rate=False):
    unit = "/s" if rate else ""
    cols = (
        f"{'Interface':<30} {'In Err' + unit:>12} {'Out Err' + unit:>12} "
        f"{'In Disc' + unit:>12} {'Out Disc' + unit:>12} "
        f"{'In Octets' + unit:>16} {'Out Octets' + unit:>16}"
    )
    print(f"\n--- {label} ---")
    print(cols)
    print("-" * len(cols))
    for name, c in sorted(stats.items()):
        print(
            f"{name:<30} {c['in_errors']:>12} {c['out_errors']:>12} "
            f"{c['in_discards']:>12} {c['out_discards']:>12} "
            f"{c['in_octets']:>16} {c['out_octets']:>16}"
        )


def build_parser():
    p = argparse.ArgumentParser(
        description="Monitor interface error counters via RESTCONF on IOS-XE."
    )
    p.add_argument("--device", required=True, help="Device hostname or IP")
    p.add_argument("--username", required=True, help="RESTCONF username")
    p.add_argument("--password", required=True, help="RESTCONF password")
    p.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    p.add_argument("--interface", default=None, help="Restrict to one interface name")
    p.add_argument(
        "--interval",
        type=int,
        default=0,
        help="Seconds between polls for rate calculation. 0 = one-shot (default: 0)",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=0.0,
        help="Errors/discards per second triggering exit code 2 (default: disabled)",
    )
    p.add_argument("--json", dest="output_json", action="store_true", help="JSON output")
    p.add_argument("--verify-ssl", action="store_true", help="Verify TLS certificate")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main():
    args = build_parser().parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    base_url = f"https://{args.device}:{args.port}"
    session = build_session(args.username, args.password, verify_ssl=args.verify_ssl)

    snapshot_1 = fetch_interface_stats(session, base_url, args.interface)

    if args.interval == 0:
        if args.output_json:
            print(json.dumps(snapshot_1, indent=2))
        else:
            print_table(snapshot_1, label=f"Interface Counters — {args.device}")
        return

    log.debug("Sleeping %d s before second poll", args.interval)
    time.sleep(args.interval)

    snapshot_2 = fetch_interface_stats(session, base_url, args.interface)
    deltas = compute_deltas(snapshot_1, snapshot_2, args.interval)

    if args.output_json:
        print(json.dumps(
            {"device": args.device, "interval_seconds": args.interval, "rates": deltas},
            indent=2,
        ))
    else:
        print_table(
            deltas,
            label=f"Error Rates (/s over {args.interval}s) — {args.device}",
            rate=True,
        )

    if args.threshold > 0:
        violations = check_thresholds(deltas, args.threshold)
        if violations:
            print(f"\n[ALERT] Threshold {args.threshold}/s exceeded:")
            for iface, metric, rate in violations:
                print(f"  {iface}  {metric}  {rate}/s")
            sys.exit(2)


if __name__ == "__main__":
    main()