"""IP geolocation and ISP lookup functionality."""

import json
import time
from typing import Dict, Optional
import urllib.request


class IPInfoLookup:
    """Class for looking up IP address information."""

    def __init__(self) -> None:
        """Initialize the IP info lookup."""
        self.cache: Dict[str, Dict] = {}
        self.last_request_time = 0
        self.min_request_interval = 1  # Minimum seconds between API requests to avoid rate limiting

    def get_ip_info(self, ip_address: str) -> Dict:
        """Get information about an IP address."""
        if ip_address in self.cache:
            return self.cache[ip_address]

        # Respect rate limits
        current_time = time.time()
        if current_time - self.last_request_time < self.min_request_interval:
            time.sleep(self.min_request_interval - (current_time - self.last_request_time))
        
        try:
            # Use ipinfo.io API (free tier, no API key required for basic lookups)
            url = f"https://ipinfo.io/{ip_address}/json"
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "CozyGuard/0.1.0 (https://github.com/example/cozyguard)"
                }
            )
            
            with urllib.request.urlopen(request, timeout=3) as response:
                data = json.loads(response.read().decode())
                self.cache[ip_address] = data
                self.last_request_time = time.time()
                return data
        except Exception as e:
            # Return minimal info on error
            self.cache[ip_address] = {"ip": ip_address, "org": "Unknown", "error": str(e)}
            return self.cache[ip_address]

    def get_isp(self, ip_address: str) -> str:
        """Get the ISP name for an IP address."""
        info = self.get_ip_info(ip_address)
        return info.get("org", "Unknown").split(" ", 1)[1] if " " in info.get("org", "Unknown") else info.get("org", "Unknown")
