"""Tests for TSV output functionality."""

import io
import sys
from unittest.mock import patch

from ufwinspector.core.analyzer import IPSummary
from ufwinspector.core.parser import UFWEventType
from ufwinspector.ui.console import ConsoleUI


def test_display_tsv_output():
    """Test TSV output format."""
    # Create test data
    ip_summaries = [
        IPSummary(
            ip_address="8.8.8.8",
            domain_name="dns.google",
            isp="Google LLC",
            count=5,
            is_source=True,
            is_destination=False,
            source_count=5,
            destination_count=0,
            event_types=[UFWEventType.BLOCK],
            source_event_types=[UFWEventType.BLOCK],
            destination_event_types=[],
            protocols=["TCP"],
            ports=[53]
        ),
        IPSummary(
            ip_address="1.1.1.1",
            domain_name="1.1.1.1",
            isp="Cloudflare",
            count=3,
            is_source=False,
            is_destination=True,
            source_count=0,
            destination_count=3,
            event_types=[UFWEventType.ALLOW],
            source_event_types=[],
            destination_event_types=[UFWEventType.ALLOW],
            protocols=["UDP"],
            ports=[53]
        )
    ]
    
    # Capture stdout
    captured_output = io.StringIO()
    with patch('sys.stdout', captured_output):
        ui = ConsoleUI()
        ui.display_tsv(ip_summaries)
    
    output = captured_output.getvalue()
    lines = output.strip().split('\n')
    
    # Check header
    expected_header = "IP_Address\tDomain_Name\tISP\tDirection\tIn_Count\tOut_Count\tEvent_Types\tProtocols"
    assert lines[0] == expected_header
    
    # Check first data row (incoming)
    expected_row1 = "8.8.8.8\tdns.google\t-\tIncoming\t5\t0\tIN:BLOCK\tTCP"
    assert lines[1] == expected_row1
    
    # Check second data row (outgoing)
    expected_row2 = "1.1.1.1\t1.1.1.1\tCloudflare\tOutgoing\t0\t3\tOUT:ALLOW\tUDP"
    assert lines[2] == expected_row2


def test_display_tsv_empty():
    """Test TSV output with empty data."""
    captured_output = io.StringIO()
    with patch('sys.stdout', captured_output):
        ui = ConsoleUI()
        ui.display_tsv([])
    
    output = captured_output.getvalue().strip()
    assert output == "No public IP addresses found in the logs."