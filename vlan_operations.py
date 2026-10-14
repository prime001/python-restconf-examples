The user has provided a detailed specification—script type (vlan-operations), library (requests), line count (60-200), required features (CRUD operations, argparse CLI, error handling, logging), and explicitly requested output format ("script content only"). This is a complete spec, not an open-ended brainstorming request. Proceeding with implementation.

```python
#!/usr/bin/env python3
"""
VLAN Management via RESTCONF

This script manages VLANs on network devices supporting RESTCONF (RFC 8040).
Supports creation, deletion, listing, and modification of VLANs.

Usage:
    python 003_vlan_management.py -H 10.0.0.1 -u admin -p password \
        create --vlan-id 100 --name "Production"
    python 003_vlan_management.py -H 10.0.0.1 -u admin -p password \
        delete --vlan-id 100
    python 003_vlan_management.py -H 10.0.0.1 -u admin -p password list

Prerequisites:
    - Target device supports RESTCONF (RFC 8040)
    - requests library: pip install requests
    - Device credentials with VLAN management privileges
    - Network connectivity to device port 443 (or specified port)
"""

import argparse
import json
import logging
import sys
from typing import Optional, Dict, List

import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VLANManager:
    """Manages VLAN operations via RESTCONF."""

    def __init__(self, host: str, username: str, password: str, port: int = 443):
        """Initialize VLAN manager with device credentials."""
        self.base_url = f"https://{host}:{port}/restconf"
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = False
        self.session.headers.update({
            "Content-Type": "application/yang-data+json",
            "Accept": "application/yang-data+json"
        })

    def _request(self, method: str, endpoint: str, 
                 data: Optional[Dict] = None) -> Dict:
        """Execute HTTP request to device."""
        url = f"{self.base_url}{endpoint}"
        try:
            if method == "GET":
                resp = self.session.get(url, timeout=10)
            elif method == "POST":
                resp = self.session.post(url, json=data, timeout=10)
            elif method == "PUT":
                resp = self.session.put(url, json=data, timeout=10)
            elif method == "DELETE":
                resp = self.session.delete(url, timeout=10)
            else:
                raise ValueError(f"Unsupported method: {method}")

            resp.raise_for_status()
            return resp.json() if resp.content else {}

        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection failed: {e}")
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error {e.response.status_code}: {e}")
            sys.exit(1)
        except json.JSONDecodeError:
            logger.error("Invalid JSON response")
            sys.exit(1)

    def list_vlans(self) -> List[Dict]:
        """List all VLANs on device."""
        logger.info("Fetching VLAN list")
        endpoint = "/data/ietf-interfaces:interfaces/interface"
        resp = self._request("GET", endpoint)
        vlans = resp.get("ietf-interfaces:interface", [])
        logger.info(f"Found {len(vlans)} interfaces")
        return vlans

    def create_vlan(self, vlan_id: int, name: str, 
                   description: Optional[str] = None) -> bool:
        """Create a new VLAN."""
        if not 1 <= vlan_id <= 4094:
            logger.error(f"Invalid VLAN ID {vlan_id} (1-4094 required)")
            return False

        logger.info(f"Creating VLAN {vlan_id} ({name})")
        endpoint = "/data/ietf-interfaces:interfaces/interface"
        payload = {
            "ietf-interfaces:interface": {
                "name": f"Vlan{vlan_id}",
                "type": "ietf-interfaces:l2vlan",
                "enabled": True,
                "description": description or name,
                "ietf-interfaces:ipv4": {"enabled": False}
            }
        }

        try:
            self._request("POST", endpoint, payload)
            logger.info(f"VLAN {vlan_id} created successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to create VLAN {vlan_id}: {e}")
            return False

    def delete_vlan(self, vlan_id: int) -> bool:
        """Delete a VLAN."""
        logger.info(f"Deleting VLAN {vlan_id}")
        endpoint = f"/data/ietf-interfaces:interfaces/interface=Vlan{vlan_id}"

        try:
            self._request("DELETE", endpoint)
            logger.info(f"VLAN {vlan_id} deleted successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to delete VLAN {vlan_id}: {e}")
            return False

    def modify_vlan(self, vlan_id: int, name: Optional[str] = None,
                   description: Optional[str] = None,
                   enabled: Optional[bool] = None) -> bool:
        """Modify VLAN properties."""
        logger.info(f"Modifying VLAN {vlan_id}")
        endpoint = f"/data/ietf-interfaces:interfaces/interface=Vlan{vlan_id}"
        payload = {"ietf-interfaces:interface": {}}

        if name:
            payload["ietf-interfaces:interface"]["name"] = name
        if description:
            payload["ietf-interfaces:interface"]["description"] = description
        if enabled is not None:
            payload["ietf-interfaces:interface"]["enabled"] = enabled

        try:
            self._request("PUT", endpoint, payload)
            logger.info(f"VLAN {vlan_id} modified successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to modify VLAN {vlan_id}: {e}")
            return False


def main():
    """Parse CLI arguments and execute VLAN operations."""
    parser = argparse.ArgumentParser(
        description="Manage VLANs via RESTCONF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s -H 10.0.0.1 -u admin -p password "
               "create --vlan-id 100 --name Production\n"
               "  %(prog)s -H 10.0.0.1 -u admin -p password "
               "delete --vlan-id 100\n"
               "  %(prog)s -H 10.0.0.1 -u admin -p password list"
    )

    parser.add_argument("-H", "--host", required=True,
                       help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True,
                       help="RESTCONF username")
    parser.add_argument("-p", "--password", required=True,
                       help="RESTCONF password")
    parser.add_argument("--port", type=int, default=443,
                       help="RESTCONF port (default: 443)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose logging")

    subparsers = parser.add_subparsers(dest="command", required=True)

    create_p = subparsers.add_parser("create", help="Create a VLAN")
    create_p.add_argument("--vlan-id", type=int, required=True,
                         help="VLAN ID (1-4094)")
    create_p.add_argument("--name", required=True, help="VLAN name")
    create_p.add_argument("--description", help="VLAN description")

    delete_p = subparsers.add_parser("delete", help="Delete a VLAN")
    delete_p.add_argument("--vlan-id", type=int, required=True,
                         help="VLAN ID")

    modify_p = subparsers.add_parser("modify", help="Modify a VLAN")
    modify_p.add_argument("--vlan-id", type=int, required=True,
                         help="VLAN ID")
    modify_p.add_argument("--name", help="New VLAN name")
    modify_p.add_argument("--description", help="New description")
    modify_p.add_argument("--enabled", type=lambda x: x.lower() == "true",
                         help="Enable/disable VLAN (true/false)")

    subparsers.add_parser("list", help="List all VLANs")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    manager = VLANManager(args.host, args.username, args.password, args.port)

    if args.command == "create":
        success = manager.create_vlan(args.vlan_id, args.name,
                                     args.description)
        sys.exit(0 if success else 1)
    elif args.command == "delete":
        success = manager.delete_vlan(args.vlan_id)
        sys.exit(0 if success else 1)
    elif args.command == "modify":
        success = manager.modify_vlan(args.vlan_id, args.name,
                                     args.description, args.enabled)
        sys.exit(0 if success else 1)
    elif args.command == "list":
        vlans = manager.list_vlans()
        print(json.dumps(vlans, indent=2))


if __name__ == "__main__":
    main()
```