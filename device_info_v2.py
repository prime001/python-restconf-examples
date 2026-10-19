```python
"""
Interface Statistics Collector via RESTCONF

Retrieves real-time interface statistics from network devices using RESTCONF API.
Displays packet counters, errors, and dropped packets in a formatted table.

Usage:
    python 016_interface_stats.py --device 192.168.1.1 --username admin --password pass
    python 016_interface_stats.py --device 192.168.1.1 --username admin --password pass --interface GigabitEthernet0/0/0

Prerequisites:
    - Target device running IOS-XE or similar with RESTCONF enabled
    - requests library installed
    - Device accessible via RESTCONF API (typically port 443)
"""

import argparse
import json
import logging
import sys

import requests
from requests.auth import HTTPBasicAuth

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class InterfaceStatsCollector:
    """Collects interface statistics from devices via RESTCONF."""

    def __init__(self, host, username, password, verify_ssl=False):
        self.host = host
        self.base_url = f"https://{host}/restconf/data"
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = verify_ssl

    def get_interface_stats(self, interface_name=None):
        """Retrieve interface statistics from device."""
        try:
            url = f"{self.base_url}/ietf-interfaces:interfaces"
            headers = {
                "Accept": "application/yang-data+json",
                "Content-Type": "application/yang-data+json"
            }

            logger.info(f"Querying {self.host} for interface statistics...")
            response = self.session.get(url, headers=headers, timeout=10)
            response.raise_for_status()

            data = response.json()
            interfaces = data.get("ietf-interfaces:interfaces", {}).get("interface", [])

            if interface_name:
                interfaces = [i for i in interfaces if interface_name in i.get("name", "")]

            stats = []
            for interface in interfaces:
                if_name = interface.get("name", "N/A")
                statistics = interface.get("statistics", {})
                
                stats.append({
                    "interface": if_name,
                    "enabled": interface.get("enabled", False),
                    "in_packets": statistics.get("in-packets", 0),
                    "out_packets": statistics.get("out-packets", 0),
                    "in_errors": statistics.get("in-errors", 0),
                    "out_errors": statistics.get("out-errors", 0),
                    "in_discards": statistics.get("in-discards", 0),
                    "out_discards": statistics.get("out-discards", 0),
                })

            logger.info(f"Retrieved statistics for {len(stats)} interfaces")
            return stats

        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection failed: {e}")
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            sys.exit(1)
        except (KeyError, json.JSONDecodeError) as e:
            logger.error(f"Parse error: {e}")
            sys.exit(1)

    def display_table(self, stats):
        """Display statistics in formatted table."""
        if not stats:
            logger.warning("No interface statistics to display")
            return

        print("\n" + "=" * 120)
        print(f"{'Interface':<20} {'Enabled':<10} {'In-Pkts':<15} {'Out-Pkts':<15} "
              f"{'In-Errors':<12} {'Out-Errors':<12} {'In-Drops':<12} {'Out-Drops':<12}")
        print("=" * 120)

        for stat in stats:
            print(f"{stat['interface']:<20} {str(stat['enabled']):<10} "
                  f"{stat['in_packets']:<15} {stat['out_packets']:<15} "
                  f"{stat['in_errors']:<12} {stat['out_errors']:<12} "
                  f"{stat['in_discards']:<12} {stat['out_discards']:<12}")

        print("=" * 120 + "\n")

    def export_json(self, stats, filename):
        """Export statistics to JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump(stats, f, indent=2)
            logger.info(f"Exported to {filename}")
        except IOError as e:
            logger.error(f"Write failed: {e}")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Collect interface statistics from network devices via RESTCONF",
        epilog="Example: %(prog)s --device 192.168.1.1 --username admin --password secret"
    )

    parser.add_argument("--device", required=True, help="Target device IP/hostname")
    parser.add_argument("--username", required=True, help="RESTCONF username")
    parser.add_argument("--password", required=True, help="RESTCONF password")
    parser.add_argument("--interface", help="Filter by interface name")
    parser.add_argument("--json", help="Export to JSON file")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")

    args = parser.parse_args()

    collector = InterfaceStatsCollector(
        host=args.device,
        username=args.username,
        password=args.password,
        verify_ssl=not args.insecure
    )

    stats = collector.get_interface_stats(interface_name=args.interface)
    collector.display_table(stats)

    if args.json:
        collector.export_json(stats, args.json)


if __name__ == "__main__":
    main()
```