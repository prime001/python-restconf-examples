```python
#!/usr/bin/env python3
"""
Port Channel Configuration via RESTCONF

Configure Ethernet port channels on Cisco IOS-XE devices using RESTCONF.
Enables rapid setup of link aggregation for bandwidth aggregation and redundancy.

Usage:
    python 013_port_channel_config.py --device 192.168.1.1 --username admin \
        --password pass123 --port-channel 10 --members Gi0/0/1,Gi0/0/2 --mode active

Prerequisites:
    - Cisco IOS-XE device with RESTCONF enabled
    - HTTPS connectivity on port 443
    - YANG support for cisco-ios-xe-native
    - User credentials with configuration privilege

Requirements:
    - requests library: pip install requests
"""

import argparse
import logging
import sys
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PortChannelManager:
    """Manage port channels on IOS-XE devices via RESTCONF."""

    def __init__(self, device: str, username: str, password: str, ssl_verify: bool = False):
        """Initialize RESTCONF session."""
        self.base_url = f"https://{device}/restconf/data"
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = ssl_verify
        self.session.headers = {
            'Content-Type': 'application/yang-data+json',
            'Accept': 'application/yang-data+json'
        }

    def create_port_channel(self, channel_id: int, members: list, mode: str = 'active') -> bool:
        """
        Create port channel and add member interfaces.

        Args:
            channel_id: Port channel number (1-4096)
            members: List of interface names
            mode: LACP mode (active, passive, or on for static)

        Returns:
            True if successful, False otherwise
        """
        if not 1 <= channel_id <= 4096:
            logger.error(f"Invalid port channel ID: {channel_id}")
            return False

        try:
            # Create port channel interface
            pc_url = f"{self.base_url}/Cisco-IOS-XE-native:native/interface/Port-channel"
            pc_payload = {
                "Cisco-IOS-XE-native:Port-channel": [{
                    "name": str(channel_id),
                    "description": f"Port-Channel {channel_id}",
                    "shutdown": False
                }]
            }

            resp = self.session.post(pc_url, json=pc_payload, timeout=10)
            if resp.status_code not in [200, 201, 204]:
                logger.error(f"Failed to create port channel: {resp.status_code}")
                return False

            logger.info(f"Created port channel {channel_id}")

            # Add member interfaces
            for member in members:
                if not self._add_member(channel_id, member, mode):
                    return False

            return True

        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            return False

    def _add_member(self, channel_id: int, interface: str, mode: str) -> bool:
        """Add single interface to port channel."""
        try:
            url = f"{self.base_url}/Cisco-IOS-XE-native:native/interface/GigabitEthernet={interface}"
            payload = {
                "Cisco-IOS-XE-native:GigabitEthernet": {
                    "name": interface,
                    "channel-group": {
                        "number": channel_id,
                        "mode": mode
                    }
                }
            }

            resp = self.session.patch(url, json=payload, timeout=10)
            if resp.status_code not in [200, 204]:
                logger.error(f"Failed to add {interface}: {resp.status_code}")
                return False

            logger.info(f"Added {interface} to port channel {channel_id} (mode: {mode})")
            return True

        except requests.exceptions.RequestException as e:
            logger.error(f"Request error adding {interface}: {e}")
            return False

    def verify_port_channel(self, channel_id: int) -> Optional[dict]:
        """Retrieve and verify port channel configuration."""
        try:
            url = f"{self.base_url}/Cisco-IOS-XE-native:native/interface/Port-channel={channel_id}"
            resp = self.session.get(url, timeout=10)

            if resp.status_code == 200:
                logger.info(f"Port channel {channel_id} verified successfully")
                return resp.json()

            logger.warning(f"Could not retrieve port channel {channel_id}")
            return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Verification error: {e}")
            return None


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Configure port channels on Cisco IOS-XE devices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('--device', required=True, help='Target device IP or hostname')
    parser.add_argument('--username', required=True, help='RESTCONF username')
    parser.add_argument('--password', required=True, help='RESTCONF password')
    parser.add_argument('--port-channel', type=int, required=True, help='Port channel number')
    parser.add_argument('--members', required=True, help='Comma-separated interface list (e.g., Gi0/0/1,Gi0/0/2)')
    parser.add_argument('--mode', default='active', choices=['active', 'passive', 'on'],
                        help='LACP mode (default: active)')
    parser.add_argument('--verify', action='store_true', help='Verify configuration after creation')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Disable SSL certificate verification')

    args = parser.parse_args()

    try:
        manager = PortChannelManager(
            args.device,
            args.username,
            args.password,
            ssl_verify=not args.no_ssl_verify
        )

        members = [m.strip() for m in args.members.split(',')]
        logger.info(f"Creating port channel {args.port_channel} with {len(members)} members (mode: {args.mode})")

        if not manager.create_port_channel(args.port_channel, members, args.mode):
            logger.error("Failed to create port channel")
            sys.exit(1)

        if args.verify:
            config = manager.verify_port_channel(args.port_channel)
            if config:
                logger.info("Port channel configuration verified")

        logger.info("Port channel configuration completed successfully")

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
```