```python
#!/usr/bin/env python3
"""
BGP Neighbor Management via RESTCONF

Purpose:
    Manage and monitor BGP neighbor relationships on IOS-XE/IOS-XR devices.
    Query BGP neighbor status, validate configurations, and manage peer relationships.

Usage:
    python bgp_neighbor_management.py --device 192.168.1.1 --username admin --password admin --asn 65000
    python bgp_neighbor_management.py --device 192.168.1.1 --username admin --password admin --asn 65000 --check-neighbors
    python bgp_neighbor_management.py --device 192.168.1.1 --username admin --password admin --asn 65000 --add-neighbor 10.1.1.2 65001
    python bgp_neighbor_management.py --device 192.168.1.1 --username admin --password admin --asn 65000 --remove-neighbor 10.1.1.2

Prerequisites:
    - RESTCONF enabled on device
    - requests library installed
    - Network connectivity to device management IP
    - Administrative credentials
    - Device running IOS-XE or IOS-XR with BGP support
"""

import requests
import argparse
import json
import logging
from requests.auth import HTTPBasicAuth
from urllib.parse import urljoin

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BGPNeighborManager:
    """Manage BGP neighbors via RESTCONF API."""

    def __init__(self, device, username, password, verify_ssl=False):
        self.device = device
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{device}/restconf/data"
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = verify_ssl
        self.session.headers.update({
            'Content-Type': 'application/yang-data+json',
            'Accept': 'application/yang-data+json'
        })

    def get_bgp_neighbors(self, asn):
        """Retrieve configured BGP neighbors for a given ASN."""
        try:
            endpoint = f"Cisco-IOS-XE-native:native/router/bgp={asn}/neighbor"
            url = urljoin(self.base_url, endpoint)
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            neighbors = data.get('Cisco-IOS-XE-bgp:neighbor', [])
            logger.info(f"Retrieved {len(neighbors)} BGP neighbors for ASN {asn}")
            return neighbors
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error retrieving neighbors: {e.response.status_code}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to retrieve BGP neighbors: {e}")
            return None

    def get_neighbor_status(self, asn):
        """Get operational status of BGP neighbors."""
        try:
            endpoint = "Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors/neighbor"
            url = urljoin(self.base_url, endpoint)
            response = self.session.get(url)
            response.raise_for_status()
            data = response.json()
            neighbors = data.get('Cisco-IOS-XE-bgp-oper:neighbor', [])
            logger.info(f"Retrieved operational status for {len(neighbors)} BGP neighbors")
            return neighbors
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error retrieving neighbor status: {e.response.status_code}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to retrieve neighbor status: {e}")
            return None

    def add_neighbor(self, asn, neighbor_ip, remote_asn):
        """Add a new BGP neighbor."""
        try:
            endpoint = f"Cisco-IOS-XE-native:native/router/bgp={asn}/neighbor"
            url = urljoin(self.base_url, endpoint)
            payload = {
                "Cisco-IOS-XE-bgp:neighbor": [
                    {
                        "id": neighbor_ip,
                        "remote-as": remote_asn
                    }
                ]
            }
            response = self.session.post(url, json=payload)
            response.raise_for_status()
            logger.info(f"Successfully added BGP neighbor {neighbor_ip} (ASN {remote_asn})")
            return True
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error adding neighbor: {e.response.status_code} - {e.response.text}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to add BGP neighbor: {e}")
            return False

    def remove_neighbor(self, asn, neighbor_ip):
        """Remove a BGP neighbor."""
        try:
            endpoint = f"Cisco-IOS-XE-native:native/router/bgp={asn}/neighbor={neighbor_ip}"
            url = urljoin(self.base_url, endpoint)
            response = self.session.delete(url)
            response.raise_for_status()
            logger.info(f"Successfully removed BGP neighbor {neighbor_ip}")
            return True
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error removing neighbor: {e.response.status_code}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to remove BGP neighbor: {e}")
            return False

    def validate_neighbor_config(self, asn, neighbor_ip):
        """Validate BGP neighbor exists and is configured."""
        try:
            endpoint = f"Cisco-IOS-XE-native:native/router/bgp={asn}/neighbor={neighbor_ip}"
            url = urljoin(self.base_url, endpoint)
            response = self.session.get(url)
            response.raise_for_status()
            logger.info(f"Neighbor {neighbor_ip} configuration validated")
            return True
        except requests.exceptions.HTTPError:
            logger.warning(f"Neighbor {neighbor_ip} not found or not configured")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to validate neighbor configuration: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Manage and monitor BGP neighbors via RESTCONF',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--device', required=True, help='Device IP address')
    parser.add_argument('--username', required=True, help='Device username')
    parser.add_argument('--password', required=True, help='Device password')
    parser.add_argument('--asn', type=int, required=True, help='BGP Autonomous System Number')
    parser.add_argument('--check-neighbors', action='store_true',
                       help='Retrieve list of configured BGP neighbors')
    parser.add_argument('--status', action='store_true',
                       help='Get operational status of BGP neighbors')
    parser.add_argument('--add-neighbor', nargs=2, metavar=('IP', 'REMOTE_ASN'),
                       help='Add BGP neighbor (requires IP and remote ASN)')
    parser.add_argument('--remove-neighbor', metavar='IP',
                       help='Remove BGP neighbor by IP address')
    parser.add_argument('--validate', metavar='IP',
                       help='Validate BGP neighbor configuration')
    parser.add_argument('--no-verify-ssl', action='store_true',
                       help='Disable SSL certificate verification')

    args = parser.parse_args()

    manager = BGPNeighborManager(
        args.device,
        args.username,
        args.password,
        verify_ssl=not args.no_verify_ssl
    )

    if args.check_neighbors:
        neighbors = manager.get_bgp_neighbors(args.asn)
        if neighbors:
            print(json.dumps(neighbors, indent=2))
    elif args.status:
        status = manager.get_neighbor_status(args.asn)
        if status:
            print(json.dumps(status, indent=2))
    elif args.add_neighbor:
        manager.add_neighbor(args.asn, args.add_neighbor[0], int(args.add_neighbor[1]))
    elif args.remove_neighbor:
        manager.remove_neighbor(args.asn, args.remove_neighbor)
    elif args.validate:
        is_valid = manager.validate_neighbor_config(args.asn, args.validate)
        print(f"Neighbor {args.validate} configuration valid: {is_valid}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
```