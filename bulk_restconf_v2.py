bulk_restconf_query.py — Bulk RESTCONF interface and config fetcher for IOS-XE / NX-OS devices.

Queries multiple devices in parallel via RESTCONF (RFC 8040), retrieves interface
operational state and optional running-config, and writes per-device JSON to an
output directory.

Usage:
    python bulk_restconf_query.py --inventory devices.csv -u admin -p secret
    python bulk_restconf_query.py --hosts 10.0.0.1,10.0.0.2 -u admin -p secret --config

Inventory CSV (no header row):
    hostname_or_ip,port,verify_ssl
    192.168.1.1,443,false
    router1.lab,443,true

Prerequisites:
    pip install requests
    IOS-XE:  conf t / restconf / ip http secure-server
    NX-OS:   feature restconf
"""

import argparse
import csv
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

RESTCONF_BASE = "/restconf/data"
ACCEPT_JSON = {"Accept": "application/yang-data+json"}

YANG_PATHS = {
    "interfaces": "ietf-interfaces:interfaces",
    "hostname":   "Cisco-IOS-XE-native:native/hostname",
    "config":     "Cisco-IOS-XE-native:native",
    "bgp":        "Cisco-IOS-XE-bgp:bgp-state-data",
    "platform":   "Cisco-IOS-XE-platform-software-oper:cisco-platform-software",
}


@dataclass
class DeviceResult:
    host: str
    port: int
    success: bool = False
    data: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    elapsed_ms: float = 0.0


def restconf_get(
    session: requests.Session,
    host: str,
    port: int,
    yang_path: str,
    timeout: int,
) -> tuple[Optional[dict], Optional[str]]:
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}{RESTCONF_BASE}/{yang_path}"
    try:
        resp = session.get(url, headers=ACCEPT_JSON, timeout=timeout)
        if resp.status_code == 200:
            return resp.json(), None
        if resp.status_code == 204:
            return {}, None
        return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except requests.exceptions.SSLError:
        return None, "SSL error — use --no-verify to skip certificate validation"
    except requests.exceptions.ConnectionError as exc:
        return None, f"Connection failed: {exc}"
    except requests.exceptions.Timeout:
        return None, f"Timed out after {timeout}s"


def query_device(
    host: str,
    port: int,
    username: str,
    password: str,
    paths: list,
    verify_ssl: bool,
    timeout: int,
) -> DeviceResult:
    result = DeviceResult(host=host, port=port)
    t0 = time.monotonic()

    session = requests.Session()
    session.auth = HTTPBasicAuth(username, password)
    session.verify = verify_ssl

    for key in paths:
        yang_path = YANG_PATHS.get(key, key)
        data, err = restconf_get(session, host, port, yang_path, timeout)
        if err:
            result.errors.append({"path": key, "error": err})
            logging.warning("[%s] %s → %s", host, key, err)
        else:
            result.data[key] = data
            logging.debug("[%s] %s → OK", host, key)

    result.elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
    result.success = bool(result.data)
    return result


def load_inventory(path: str) -> list:
    devices = []
    with open(path, newline="") as fh:
        for row in csv.reader(fh):
            row = [c.strip() for c in row]
            if not row or not row[0] or row[0].startswith("#"):
                continue
            devices.append({
                "host":       row[0],
                "port":       int(row[1]) if len(row) > 1 else 443,
                "verify_ssl": row[2].lower() not in ("false", "0", "no") if len(row) > 2 else False,
            })
    return devices


def write_result(result: DeviceResult, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fname = out_dir / f"{result.host.replace('.', '_').replace(':', '_')}.json"
    with open(fname, "w") as fh:
        json.dump({
            "host": result.host, "port": result.port,
            "success": result.success, "elapsed_ms": result.elapsed_ms,
            "errors": result.errors, "data": result.data,
        }, fh, indent=2)
    logging.info("[%s] saved → %s", result.host, fname)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Bulk RESTCONF query across multiple IOS-XE / NX-OS devices.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--inventory", metavar="FILE", help="CSV: host,port,verify_ssl")
    src.add_argument("--hosts", metavar="H1[,H2...]", help="Comma-separated host list")

    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--port", type=int, default=443, help="Default port (default: 443)")
    p.add_argument(
        "--paths", default="interfaces,hostname",
        help=f"Comma-separated YANG paths. Aliases: {', '.join(YANG_PATHS)} (default: interfaces,hostname)",
    )
    p.add_argument("--no-verify", action="store_true", help="Skip TLS certificate validation")
    p.add_argument("--timeout", type=int, default=10, help="Per-request timeout seconds (default: 10)")
    p.add_argument("--workers", type=int, default=10, help="Parallel workers (default: 10)")
    p.add_argument("--output-dir", default="./restconf_results", metavar="DIR")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.inventory:
        try:
            devices = load_inventory(args.inventory)
        except (FileNotFoundError, OSError) as exc:
            logging.error("Cannot read inventory: %s", exc)
            return 1
    else:
        devices = [{"host": h.strip(), "port": args.port, "verify_ssl": not args.no_verify}
                   for h in args.hosts.split(",") if h.strip()]

    if not devices:
        logging.error("No devices found.")
        return 1

    if args.no_verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    paths = [p.strip() for p in args.paths.split(",") if p.strip()]
    out_dir = Path(args.output_dir)
    logging.info("Querying %d device(s) | paths: %s | workers: %d", len(devices), paths, args.workers)

    results = []
    with ThreadPoolExecutor(max_workers=min(args.workers, len(devices))) as pool:
        futures = {
            pool.submit(
                query_device,
                d["host"], d["port"], args.username, args.password,
                paths, d.get("verify_ssl", not args.no_verify), args.timeout,
            ): d["host"]
            for d in devices
        }
        for fut in as_completed(futures):
            result = fut.result()
            results.append(result)
            write_result(result, out_dir)

    ok = [r for r in results if r.success]
    fail = [r for r in results if not r.success]
    print(f"\n{'='*55}")
    print(f"RESULTS  total={len(results)}  ok={len(ok)}  failed={len(fail)}")
    print(f"{'='*55}")
    for r in ok:
        iface_count = len(
            (r.data.get("interfaces") or {})
            .get("ietf-interfaces:interfaces", {})
            .get("interface", [])
        )
        print(f"  OK   {r.host:<28} {iface_count:>3} interfaces  {r.elapsed_ms:.0f}ms")
    for r in fail:
        errs = "; ".join(e["error"] for e in r.errors)
        print(f"  FAIL {r.host:<28} {errs}")

    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())