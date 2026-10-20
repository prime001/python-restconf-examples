```python
#!/usr/bin/env python3
"""
Retrieve and display routing table information from network devices via RESTCONF.

Usage:
    python routing_table_read.py -d 192.168.1.1 -u admin -p password
    python routing_table_read.py -d 192.168.1.1 -u admin -p password --vrf default
    python routing_table_read.py -d 192.168.1.1 -u admin -p password --filter 10.0.0.0/8

Prerequisites:
    - Target device must support RESTCONF (RFC 8040)
    - Device must have IP reachability from this host
    - User must have appropriate RESTCONF permissions
    - requests library installed (pip install requests)

Output:
    Formatted table with routing entries including destination, next-hop, protocol, metric, and VRF.
"""

import argparse
import logging
import sys
from typing import Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RESTCONFRouteReader:
    """RESTCONF client for retrieving routing table information."""
    
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: int = 10
    ):
        """Initialize RESTCONF client."""
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.base_url = f"https://{host}:{port}/restconf"
        
    def _request(self, method: str, path: str, **kwargs) -> dict:
        """Perform RESTCONF request."""
        url = f"{self.base_url}/{path}"
        headers = kwargs.pop("headers", {})
        headers.update({
            "Accept": "application/yang-data+json",
            "Content-Type": "application/yang-data+json"
        })
        
        try:
            response = requests.request(
                method=method,
                url=url,
                auth=HTTPBasicAuth(self.username, self.password),
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout to {self.host}")
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection failed to {self.host}: {e}")
            raise
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {e.response.status_code} - {e}")
            raise
    
    def get_routes(self, vrf: str = "default") -> List[Dict]:
        """Retrieve IPv4 routing table entries."""
        logger.info(f"Fetching routing table for VRF: {vrf}")
        
        try:
            path = "data/ietf-routing:routing/ribs/rib"
            data = self._request("GET", path)
            
            routes = []
            rib_list = data.get("ietf-routing:rib", [])
            
            if not isinstance(rib_list, list):
                rib_list = [rib_list]
            
            for rib in rib_list:
                if rib.get("name") != vrf:
                    continue
                
                routes_data = rib.get("routes", {})
                ipv4_routes = routes_data.get("route", [])
                
                if not isinstance(ipv4_routes, list):
                    ipv4_routes = [ipv4_routes]
                
                for route in ipv4_routes:
                    route_entry = {
                        "destination": route.get("destination-prefix", "Unknown"),
                        "vrf": vrf,
                        "protocol": "Unknown",
                        "metric": "N/A",
                        "next_hop": "Unknown"
                    }
                    
                    source_protocol = route.get("source-protocol", "Unknown")
                    if isinstance(source_protocol, dict):
                        route_entry["protocol"] = source_protocol.get("identifier", "Unknown")
                    else:
                        route_entry["protocol"] = str(source_protocol)
                    
                    route_metric = route.get("route-metric")
                    if route_metric is not None:
                        route_entry["metric"] = int(route_metric)
                    
                    next_hops = route.get("next-hop", {})
                    nh_list = next_hops.get("next-hop-list", {}).get("next-hop", [])
                    
                    if nh_list:
                        if not isinstance(nh_list, list):
                            nh_list = [nh_list]
                        route_entry["next_hop"] = nh_list[0].get("address", "Unknown")
                    
                    routes.append(route_entry)
            
            logger.info(f"Retrieved {len(routes)} routes")
            return routes
            
        except Exception as e:
            logger.error(f"Failed to retrieve routing table: {e}", exc_info=True)
            raise
    
    def filter_routes(
        self,
        routes: List[Dict],
        prefix_filter: Optional[str] = None
    ) -> List[Dict]:
        """Filter routes by destination prefix."""
        if not prefix_filter:
            return routes
        
        filtered = [
            r for r in routes
            if r["destination"].startswith(prefix_filter)
        ]
        logger.info(f"Filtered to {len(filtered)} routes")
        return filtered


def display_routes(routes: List[Dict]) -> None:
    """Display routes in formatted table."""
    if not routes:
        print("No routes found.")
        return
    
    print("\n" + "=" * 90)
    print(f"{'Destination':<25} {'Next-Hop':<20} {'Protocol':<15} {'Metric':<10} {'VRF':<15}")
    print("=" * 90)
    
    for route in routes:
        dest = route["destination"][:24]
        nh = str(route["next_hop"])[:19]
        proto = str(route["protocol"])[:14]
        metric = str(route["metric"])[:9]
        vrf = route["vrf"][:14]
        
        print(f"{dest:<25} {nh:<20} {proto:<15} {metric:<10} {vrf:<15}")
    
    print("=" * 90)
    print(f"Total routes: {len(routes)}\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Read routing table from RESTCONF-enabled devices"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="RESTCONF username")
    parser.add_argument("-p", "--password", required=True, help="RESTCONF password")
    parser.add_argument("--port", type=int, default=443, help="RESTCONF port (default: 443)")
    parser.add_argument("--vrf", default="default", help="VRF name (default: default)")
    parser.add_argument("--filter", help="Filter by destination prefix")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    
    args = parser.parse_args()
    
    try:
        reader = RESTCONFRouteReader(
            host=args.device,
            username=args.username,
            password=args.password,
            port=args.port,
            verify_ssl=not args.no_verify,
            timeout=args.timeout
        )
        
        routes = reader.get_routes(args.vrf)
        routes = reader.filter_routes(routes, args.filter)
        display_routes(routes)
        
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```