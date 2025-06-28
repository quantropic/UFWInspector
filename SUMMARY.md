# CozyGuard Project Summary

## Overview

CozyGuard is a Python-based UFW log analyzer that processes firewall logs to identify potential security threats. The application analyzes `/var/log/ufw.log` entries, groups them by event type, deduplicates by IP address, resolves domain names, and presents the results in a sorted table.

## Project Structure

```
CozyGuard/
├── cozyguard/
│   ├── __init__.py
│   ├── cli.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── parser.py
│   │   └── analyzer.py
│   └── ui/
│       ├── __init__.py
│       └── console.py
├── tests/
│   ├── test_parser.py
│   └── sample_ufw.log
├── debian/
│   ├── changelog
│   ├── control
│   ├── copyright
│   ├── rules
│   ├── cozyguard.install
│   └── cozyguard.desktop
├── pyproject.toml
├── README.md
└── PACKAGING.md
```

## Features

1. **Log Parsing**: Parses UFW log entries to extract event type, IP addresses, ports, and protocols
2. **IP Classification**: Identifies public vs. private IP addresses
3. **Domain Resolution**: Resolves IP addresses to domain names
4. **Event Grouping**: Groups events by type (BLOCK, ALLOW, AUDIT)
5. **Deduplication**: Counts occurrences of each unique IP address
6. **Direction Identification**: Determines if public IPs are source or destination
7. **Sorted Results**: Presents results sorted by occurrence count
8. **Multiple Output Formats**: Rich text tables, plain text, and grouped by event type

## Usage

```bash
# Basic usage
cozyguard analyze

# Specify a different log file
cozyguard analyze --log-file /path/to/ufw.log

# Use plain text output
cozyguard analyze --plain

# Group results by event type
cozyguard analyze --group-by-type
```

## Packaging

The project is set up for Debian/Ubuntu packaging with:
- Complete debian/ directory structure
- Desktop file for application menu integration
- Proper dependency management
- Instructions for building and signing packages

## Development Best Practices

1. **Type Annotations**: All code uses Python type hints for better IDE support and error detection
2. **Modular Design**: Clear separation between parsing, analysis, and presentation
3. **Unit Tests**: Test coverage for core functionality
4. **Error Handling**: Graceful handling of file access issues and parsing errors
5. **Documentation**: Comprehensive docstrings and user documentation

## Next Steps

1. **Add Graphical Interface**: Implement a GUI version using PyQt or Tkinter
2. **Enhance Analysis**: Add more security-focused analysis features
3. **Real-time Monitoring**: Add capability to watch log files in real-time
4. **Threat Intelligence**: Integrate with threat intelligence feeds
5. **Reporting**: Add PDF/HTML report generation
6. **Windows Port**: Adapt the code for Windows Event Log analysis
