"""UFW log analyzer module."""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..config import config
from .parser import UFWEvent, UFWEventType, UFWLogParser
from .geo import IPInfoLookup


@dataclass
class IPSummary:
    """Summary information for an IP address."""

    ip_address: str
    domain_name: str
    isp: str  # Added ISP field
    count: int  # Total count (kept for compatibility)
    is_source: bool
    is_destination: bool
    source_count: int  # Count of events where this IP is the source
    destination_count: int  # Count of events where this IP is the destination
    event_types: List[UFWEventType]
    source_event_types: List[UFWEventType]  # Event types where this IP is the source
    destination_event_types: List[UFWEventType]  # Event types where this IP is the destination
    protocols: List[str]
    ports: List[int]
    
    @property
    def direction_type(self) -> str:
        """Return a categorized direction type for sorting and display."""
        if self.is_source and not self.is_destination:
            return "Incoming"  # External IP trying to connect to us
        elif self.is_destination and not self.is_source:
            return "Outgoing"  # We're connecting to external IP
        else:
            return "Bidirectional"  # Both directions seen


class UFWLogAnalyzer:
    """Analyzer for UFW logs."""

    def __init__(self, log_file_path: Optional[str] = None) -> None:
        """Initialize the analyzer with the log file path."""
        # Use provided log file path or get from config
        if log_file_path is None:
            log_file_path = config.get("log_file")
        
        self.parser = UFWLogParser(log_file_path)
        self.ip_lookup = IPInfoLookup()
        self.events: List[UFWEvent] = []
        self.ip_summaries: List[IPSummary] = []

    def analyze(self) -> List[IPSummary]:
        """Analyze the UFW logs and return IP summaries."""
        self.events = self.parser.parse()
        self._generate_ip_summaries()
        return self.ip_summaries

    def _generate_ip_summaries(self) -> None:
        """Generate summaries for each unique IP address."""
        ip_data: Dict[str, IPSummary] = {}
        
        for event in self.events:
            # Process source IP if it's public
            if event.source_ip and event.source_is_public:
                self._process_ip(
                    ip_data, 
                    event.source_ip, 
                    event, 
                    is_source=True, 
                    is_destination=False
                )
            
            # Process destination IP if it's public
            if event.destination_ip and event.destination_is_public:
                self._process_ip(
                    ip_data, 
                    event.destination_ip, 
                    event, 
                    is_source=False, 
                    is_destination=True
                )
        
        # Convert to list and sort by direction type (incoming first) and then by count
        self.ip_summaries = sorted(
            ip_data.values(), 
            key=lambda x: (
                0 if x.direction_type == "Incoming" else 
                1 if x.direction_type == "Bidirectional" else 2,
                -x.count  # Negative for descending order
            )
        )

    def _process_ip(
        self, 
        ip_data: Dict[str, IPSummary], 
        ip_address: str, 
        event: UFWEvent, 
        is_source: bool, 
        is_destination: bool
    ) -> None:
        """Process an IP address and update its summary."""
        if ip_address not in ip_data:
            domain_name = self.parser.resolve_domain(ip_address)
            
            # Get ISP information if domain is same as IP (unresolved)
            isp = "Unknown"
            if domain_name == ip_address:
                try:
                    isp = self.ip_lookup.get_isp(ip_address)
                except Exception:
                    pass
            
            ip_data[ip_address] = IPSummary(
                ip_address=ip_address,
                domain_name=domain_name,
                isp=isp,
                count=1,
                is_source=is_source,
                is_destination=is_destination,
                source_count=1 if is_source else 0,
                destination_count=1 if is_destination else 0,
                event_types=[event.event_type],
                source_event_types=[event.event_type] if is_source else [],
                destination_event_types=[event.event_type] if is_destination else [],
                protocols=[event.protocol] if event.protocol else [],
                ports=[]
            )
            
            # Add relevant ports
            if is_source and event.source_port:
                ip_data[ip_address].ports.append(event.source_port)
            if is_destination and event.destination_port:
                ip_data[ip_address].ports.append(event.destination_port)
        else:
            # Update existing summary
            summary = ip_data[ip_address]
            summary.count += 1
            summary.is_source = summary.is_source or is_source
            summary.is_destination = summary.is_destination or is_destination
            
            # Update direction-specific counts
            if is_source:
                summary.source_count += 1
                if event.event_type not in summary.source_event_types:
                    summary.source_event_types.append(event.event_type)
            
            if is_destination:
                summary.destination_count += 1
                if event.event_type not in summary.destination_event_types:
                    summary.destination_event_types.append(event.event_type)
            
            if event.event_type not in summary.event_types:
                summary.event_types.append(event.event_type)
            
            if event.protocol and event.protocol not in summary.protocols:
                summary.protocols.append(event.protocol)
            
            if is_source and event.source_port and event.source_port not in summary.ports:
                summary.ports.append(event.source_port)
            
            if is_destination and event.destination_port and event.destination_port not in summary.ports:
                summary.ports.append(event.destination_port)
