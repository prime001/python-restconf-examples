026_environment_monitor.py - RESTCONF Environment Health Monitor

Purpose:
    Retrieves environmental telemetry from Cisco IOS-XE devices via RESTCONF:
    temperature sensors, power supply status, and fan tray status. Designed
    for NOC spot-checks and integration with monitoring systems via exit codes
    (0=OK, 1=WARNING, 2=CRITICAL) compatible with Nagios/Icinga plugins.

Usage:
    python 026_environment_monitor.py --host 192.168.1.1 -u admin -p secret
    python 026_environment_monitor.py --host 192.168.1.1 -u admin -p secret --json
    python 026_environment_monitor.py --host 192.168.1.1 -u admin -p secret \
        --warn-temp 70 --crit-temp 85

Prerequisites:
    - Cisco IOS-XE 16.6+ with RESTCONF enabled:
        ip http secure-server
        restconf
    - User account with privilege 15 or a NETCONF/RESTCONF read role
    - pip install requests
"""

import argparse
import json
import logging
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RESTCONF_BASE = "https://{host}:{port}/restconf/data"
ENV_OPER_PATH = "Cisco-IOS-XE-environment-oper:environment-sensors/environment-sensor"
HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}


def build_url(host, port, path):
    return f"{RESTCONF_BASE.format(host=host, port=port)}/{path}"


def restconf_get(session, url):
    try:
        resp = session.get(url, timeout=10, verify=False)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        logging.error("Cannot connect to %s — check RESTCONF is enabled and reachable", url)
        sys.exit(2)
    except requests.exceptions.Timeout:
        logging.error("Request timed out: %s", url)
        sys.exit(2)
    except requests.exceptions.HTTPError as exc:
        logging.error("HTTP %s from %s", exc.response.status_code, url)
        return None
    except ValueError:
        logging.error("Non-JSON response from %s", url)
        return None


def fetch_sensors(session, host, port):
    url = build_url(host, port, ENV_OPER_PATH)
    data = restconf_get(session, url)
    if not data:
        return []
    key = "Cisco-IOS-XE-environment-oper:environment-sensor"
    raw = data.get(key, data)
    return raw if isinstance(raw, list) else [raw]


def classify_sensor(sensor):
    name = sensor.get("name", "").lower()
    if any(k in name for k in ("temp", "inlet", "outlet", "cpu", "asic", "junction")):
        category = "temperature"
    elif any(k in name for k in ("fan", "cooling", "tach")):
        category = "fan"
    elif any(k in name for k in ("power", "pwr", "voltage", "current", "rail", "watt")):
        category = "power"
    else:
        category = "other"

    return {
        "name": sensor.get("name", ""),
        "location": sensor.get("location", ""),
        "category": category,
        "state": sensor.get("state", "unknown"),
        "value": sensor.get("current-reading"),
        "units": sensor.get("sensor-units", ""),
        "threshold_minor": sensor.get("threshold-minor"),
        "threshold_major": sensor.get("threshold-major"),
        "threshold_fatal": sensor.get("threshold-fatal"),
    }


def evaluate_alerts(sensors, warn_temp, crit_temp):
    alerts = []
    for s in sensors:
        state_lower = s["state"].lower()
        if state_lower not in ("normal", "ok", "green", "good", ""):
            severity = "CRITICAL" if any(w in state_lower for w in ("critical", "fatal", "error")) else "WARNING"
            alerts.append({"sensor": s["name"], "severity": severity,
                           "message": f"Sensor state is '{s['state']}'"})

        if s["category"] == "temperature" and isinstance(s["value"], (int, float)):
            if crit_temp is not None and s["value"] >= crit_temp:
                alerts.append({"sensor": s["name"], "severity": "CRITICAL",
                               "message": f"{s['value']}{s['units']} >= critical threshold {crit_temp}"})
            elif warn_temp is not None and s["value"] >= warn_temp:
                alerts.append({"sensor": s["name"], "severity": "WARNING",
                               "message": f"{s['value']}{s['units']} >= warning threshold {warn_temp}"})
    return alerts


def render_table(sensors, alerts):
    categories = [("temperature", "TEMPERATURE"), ("fan", "FAN"), ("power", "POWER"), ("other", "OTHER")]
    col = (34, 14, 12)

    for cat_key, cat_label in categories:
        items = [s for s in sensors if s["category"] == cat_key]
        if not items:
            continue
        print(f"\n  {'─' * 62}")
        print(f"  {cat_label}")
        print(f"  {'─' * 62}")
        print(f"  {'Sensor':<{col[0]}} {'Reading':<{col[1]}} {'State':<{col[2]}} Location")
        print(f"  {'─'*col[0]} {'─'*col[1]} {'─'*col[2]} {'─'*20}")
        for s in items:
            val = f"{s['value']}{s['units']}" if s["value"] is not None else "n/a"
            print(f"  {s['name']:<{col[0]}} {val:<{col[1]}} {s['state']:<{col[2]}} {s['location']}")

    print()
    if alerts:
        print(f"  {'─' * 62}")
        print(f"  ALERTS ({len(alerts)} found)")
        print(f"  {'─' * 62}")
        for a in alerts:
            print(f"  [{a['severity']:^8}] {a['sensor']}: {a['message']}")
    else:
        print("  All sensors within normal parameters.")


def main():
    parser = argparse.ArgumentParser(
        description="RESTCONF environment health monitor for Cisco IOS-XE"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--port", type=int, default=443, help="RESTCONF port (default: 443)")
    parser.add_argument("-u", "--user", required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("--warn-temp", type=float, metavar="C",
                        help="Warning temperature threshold in Celsius")
    parser.add_argument("--crit-temp", type=float, metavar="C",
                        help="Critical temperature threshold in Celsius")
    parser.add_argument("--json", action="store_true", dest="output_json",
                        help="Output structured JSON (useful for monitoring integrations)")
    parser.add_argument("--debug", action="store_true", help="Enable debug-level logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    session = requests.Session()
    session.auth = (args.user, args.password)
    session.headers.update(HEADERS)

    raw_sensors = fetch_sensors(session, args.host, args.port)
    if not raw_sensors:
        logging.error(
            "No sensor data returned. Confirm Cisco-IOS-XE-environment-oper "
            "is supported on this platform and RESTCONF is enabled."
        )
        sys.exit(2)

    sensors = [classify_sensor(s) for s in raw_sensors]
    alerts = evaluate_alerts(sensors, args.warn_temp, args.crit_temp)

    if args.output_json:
        print(json.dumps({"host": args.host, "sensors": sensors, "alerts": alerts}, indent=2))
    else:
        print(f"\nEnvironment Status — {args.host}")
        render_table(sensors, alerts)
        print()

    if any(a["severity"] == "CRITICAL" for a in alerts):
        sys.exit(2)
    if alerts:
        sys.exit(1)


if __name__ == "__main__":
    main()