"""Tests for the UFW log parser."""

import os
import tempfile
from datetime import datetime

import pytest

from ufwinspector.core.parser import UFWEventType, UFWLogParser


def test_parse_block_line() -> None:
    """Test parsing a UFW BLOCK log line."""
    parser = UFWLogParser("")  # Empty string for testing individual lines
    line = "Jun 15 12:34:56 hostname kernel: [12345.678901] UFW BLOCK IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=12345 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0"
    event = parser._parse_line(line)
    
    assert event is not None
    assert event.event_type == UFWEventType.BLOCK
    assert event.source_ip == "192.168.1.100"
    assert event.destination_ip == "192.168.1.1"
    assert event.source_port == 12345
    assert event.destination_port == 80
    assert event.protocol == "TCP"
    assert event.interface == "eth0"


def test_parse_allow_line() -> None:
    """Test parsing a UFW ALLOW log line."""
    parser = UFWLogParser("")  # Empty string for testing individual lines
    line = "Jun 15 12:34:56 hostname kernel: [12345.678901] UFW ALLOW IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=12345 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0"
    event = parser._parse_line(line)
    
    assert event is not None
    assert event.event_type == UFWEventType.ALLOW
    assert event.source_ip == "192.168.1.100"
    assert event.destination_ip == "192.168.1.1"
    assert event.source_port == 12345
    assert event.destination_port == 22
    assert event.protocol == "TCP"
    assert event.interface == "eth0"


def test_parse_invalid_line() -> None:
    """Test parsing an invalid log line."""
    parser = UFWLogParser()
    line = "This is not a valid UFW log line"
    event = parser._parse_line(line)
    
    assert event is None


def test_parse_file() -> None:
    """Test parsing a log file."""
    # Create a temporary log file
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
        temp_file.write("Jun 15 12:34:56 hostname kernel: [12345.678901] UFW BLOCK IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=12345 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0\n")
        temp_file.write("Jun 15 12:35:56 hostname kernel: [12345.678902] UFW ALLOW IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12346 DF PROTO=TCP SPT=12345 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0\n")
        temp_file.write("This is not a valid UFW log line\n")
    
    try:
        parser = UFWLogParser(temp_file.name)
        events = parser.parse()
        
        assert len(events) == 2
        assert events[0].event_type == UFWEventType.BLOCK
        assert events[1].event_type == UFWEventType.ALLOW
    finally:
        os.unlink(temp_file.name)


def test_source_is_public() -> None:
    """Test the source_is_public property."""
    parser = UFWLogParser("")  # Empty string for testing individual lines
    
    # Public IP
    line = "Jun 15 12:34:56 hostname kernel: [12345.678901] UFW BLOCK IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=8.8.8.8 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=12345 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0"
    event = parser._parse_line(line)
    assert event is not None
    assert event.source_is_public is True
    
    # Private IP
    line = "Jun 15 12:34:56 hostname kernel: [12345.678901] UFW BLOCK IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=192.168.1.100 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=12345 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0"
    event = parser._parse_line(line)
    assert event is not None
    assert event.source_is_public is False
