"""UFW log parser module."""

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Dict, List, Optional, Set, Tuple, Union

import dns.resolver
from dns.exception import DNSException

from ..config import config


class UFWEventType(Enum):
    """UFW event types."""

    BLOCK = auto()
    ALLOW = auto()
    AUDIT = auto()
    UNKNOWN = auto()


@dataclass
class UFWEvent:
    """Represents a UFW log event."""

    timestamp: datetime
    event_type: UFWEventType
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: Optional[str]
    interface: Optional[str]
    raw_log: str

    @property
    def source_is_public(self) -> bool:
        """Check if source IP is public."""
        if not self.source_ip:
            return False
        try:
            # Handle IPv6 addresses in the format 0000:0000:0000:0000:0000:0000:0000:0001
            ip_str = self.source_ip
            if ":" in ip_str and not ip_str.startswith("["):
                # Normalize IPv6 address format
                ip_str = ip_str.replace("0000", "")
                while "::" not in ip_str and ":::" not in ip_str:
                    ip_str = ip_str.replace(":", "::", 1)
                
            ip = ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
        except ValueError:
            return False

    @property
    def destination_is_public(self) -> bool:
        """Check if destination IP is public."""
        if not self.destination_ip:
            return False
        try:
            # Handle IPv6 addresses in the format 0000:0000:0000:0000:0000:0000:0000:0001
            ip_str = self.destination_ip
            if ":" in ip_str and not ip_str.startswith("["):
                # Normalize IPv6 address format
                ip_str = ip_str.replace("0000", "")
                while "::" not in ip_str and ":::" not in ip_str:
                    ip_str = ip_str.replace(":", "::", 1)
                
            ip = ip_address(ip_str)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
        except ValueError:
            return False


class UFWLogParser:
    """Parser for UFW log files."""

    # Regular expressions for parsing UFW logs
    # Support both traditional and systemd journal formats
    TIMESTAMP_PATTERN_ISO = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})"
    TIMESTAMP_PATTERN_SYSLOG = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    EVENT_TYPE_PATTERN = r"UFW\s+(BLOCK|ALLOW|AUDIT)"  # Updated to match UFW AUDIT format without brackets
    SRC_PATTERN = r"SRC=(\S+)"
    DST_PATTERN = r"DST=(\S+)"
    SPT_PATTERN = r"SPT=(\d+)"
    DPT_PATTERN = r"DPT=(\d+)"
    PROTO_PATTERN = r"PROTO=(\S+)"
    IN_PATTERN = r"IN=(\S+)"

    def __init__(self, log_file_path: Optional[str] = None) -> None:
        """Initialize the parser with the log file path."""
        # Use provided log file path or get from config
        if log_file_path is None:
            log_file_path = config.get("log_file")
            
        self.log_file_path = log_file_path
        self.events: List[UFWEvent] = []
        self.dns_cache: Dict[str, str] = {}

    def parse(self) -> List[UFWEvent]:
        """Parse the UFW log file and return a list of events."""
        self.events = []
        
        try:
            with open(self.log_file_path, "r", encoding="utf-8") as file:
                for line in file:
                    # Remove newlines and join broken lines
                    line = line.strip()
                    if not line:
                        continue
                        
                    event = self._parse_line(line)
                    if event:
                        self.events.append(event)
        except FileNotFoundError:
            print(f"Error: Log file not found at {self.log_file_path}")
        except PermissionError:
            print(f"Error: Permission denied when accessing {self.log_file_path}")
        
        return self.events

    def _parse_line(self, line: str) -> Optional[UFWEvent]:
        """Parse a single log line and return a UFWEvent if valid."""
        if "UFW" not in line:
            return None

        # Extract timestamp - try both formats
        timestamp_match = re.search(self.TIMESTAMP_PATTERN_ISO, line)
        timestamp = None
        
        if timestamp_match:
            try:
                # Parse ISO format timestamp
                timestamp_str = timestamp_match.group(1)
                timestamp = datetime.fromisoformat(timestamp_str)
            except ValueError:
                pass
        
        if not timestamp:
            # Try syslog format
            timestamp_match = re.search(self.TIMESTAMP_PATTERN_SYSLOG, line)
            if timestamp_match:
                try:
                    # Parse syslog format timestamp (assume current year)
                    timestamp_str = timestamp_match.group(1)
                    current_year = datetime.now().year
                    timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                except ValueError:
                    pass
        
        if not timestamp:
            return None

        # Extract event type
        event_type_match = re.search(self.EVENT_TYPE_PATTERN, line)
        if event_type_match:
            event_type_str = event_type_match.group(1)
            if event_type_str == "BLOCK":
                event_type = UFWEventType.BLOCK
            elif event_type_str == "ALLOW":
                event_type = UFWEventType.ALLOW
            elif event_type_str == "AUDIT":
                event_type = UFWEventType.AUDIT
            else:
                event_type = UFWEventType.UNKNOWN
        else:
            event_type = UFWEventType.UNKNOWN

        # Extract IP addresses and ports
        source_ip = self._extract_pattern(self.SRC_PATTERN, line)
        destination_ip = self._extract_pattern(self.DST_PATTERN, line)
        
        source_port_str = self._extract_pattern(self.SPT_PATTERN, line)
        source_port = int(source_port_str) if source_port_str else None
        
        destination_port_str = self._extract_pattern(self.DPT_PATTERN, line)
        destination_port = int(destination_port_str) if destination_port_str else None
        
        protocol = self._extract_pattern(self.PROTO_PATTERN, line)
        interface = self._extract_pattern(self.IN_PATTERN, line)

        return UFWEvent(
            timestamp=timestamp,
            event_type=event_type,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            interface=interface,
            raw_log=line.strip()
        )

    def _extract_pattern(self, pattern: str, text: str) -> Optional[str]:
        """Extract a pattern from text."""
        match = re.search(pattern, text)
        if not match:
            return None
            
        value = match.group(1)
        
        # Handle IPv6 addresses
        if pattern in [self.SRC_PATTERN, self.DST_PATTERN] and ":" in value:
            # Convert from 0000:0000:0000:0000:0000:0000:0000:0001 format to standard IPv6
            try:
                # Try to parse as is first
                ip_address(value)
                return value
            except ValueError:
                try:
                    # Try to normalize the address
                    parts = value.split(":")
                    normalized = ":".join([part.lstrip("0") or "0" for part in parts])
                    ip_address(normalized)
                    return normalized
                except ValueError:
                    # If all else fails, return as is
                    return value
        
        return value

    def resolve_domain(self, ip_addr: str) -> str:
        """Resolve IP address to domain name."""
        if ip_addr in self.dns_cache:
            return self.dns_cache[ip_addr]
        
        try:
            addr = ip_address(ip_addr)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                self.dns_cache[ip_addr] = ip_addr
                return ip_addr
            
            # Try reverse DNS lookup
            result = dns.resolver.resolve_address(ip_addr)
            domain = str(result[0])
            
            # Remove trailing dot from domain name
            if domain.endswith('.'):
                domain = domain[:-1]
                
            self.dns_cache[ip_addr] = domain
            return domain
        except (DNSException, ValueError):
            self.dns_cache[ip_addr] = ip_addr
            return ip_addr

    def group_by_event_type(self) -> Dict[UFWEventType, List[UFWEvent]]:
        """Group events by their type."""
        result: Dict[UFWEventType, List[UFWEvent]] = {}
        for event in self.events:
            if event.event_type not in result:
                result[event.event_type] = []
            result[event.event_type].append(event)
        return result

    def deduplicate_by_ip(self) -> Dict[str, Tuple[int, UFWEvent]]:
        """Deduplicate events by IP address and count occurrences."""
        ip_counts: Dict[str, Tuple[int, UFWEvent]] = {}
        
        for event in self.events:
            # Process source IP if it's public
            if event.source_ip and event.source_is_public:
                if event.source_ip not in ip_counts:
                    ip_counts[event.source_ip] = (1, event)
                else:
                    count, first_event = ip_counts[event.source_ip]
                    ip_counts[event.source_ip] = (count + 1, first_event)
            
            # Process destination IP if it's public
            if event.destination_ip and event.destination_is_public:
                if event.destination_ip not in ip_counts:
                    ip_counts[event.destination_ip] = (1, event)
                else:
                    count, first_event = ip_counts[event.destination_ip]
                    ip_counts[event.destination_ip] = (count + 1, first_event)
        
        return ip_counts
    def is_public_ip(self, ip_str: str) -> bool:
        """Check if an IP address is public."""
        if not ip_str:
            return False
            
        # Skip multicast addresses
        if ip_str.startswith("224.") or ip_str.startswith("239."):
            return False
            
        try:
            # Handle IPv6 addresses
            if ":" in ip_str:
                # Try to normalize the address if needed
                try:
                    ip = ip_address(ip_str)
                except ValueError:
                    parts = ip_str.split(":")
                    normalized = ":".join([part.lstrip("0") or "0" for part in parts])
                    ip = ip_address(normalized)
                
                return not (ip.is_private or ip.is_loopback or ip.is_link_local or 
                           ip.is_multicast or ip.is_unspecified or ip.is_reserved)
            else:
                # Handle IPv4
                ip = ip_address(ip_str)
                return not (ip.is_private or ip.is_loopback or ip.is_link_local or 
                           ip.is_multicast or ip.is_unspecified or ip.is_reserved)
        except ValueError:
            return False
