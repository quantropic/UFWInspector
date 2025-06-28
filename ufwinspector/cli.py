"""Command-line interface for UFWInspector."""

import os
import sys
from typing import Optional

import typer
from rich.console import Console

from ufwinspector import __version__
from ufwinspector.config import config
from ufwinspector.core.analyzer import UFWLogAnalyzer
from ufwinspector.ui.console import ConsoleUI

app = typer.Typer(help="UFWInspector - UFW log analyzer for security monitoring")
console = Console()

# Create a subcommand group for configuration
config_app = typer.Typer(help="Configuration commands")
app.add_typer(config_app, name="config")


@config_app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Configuration key to get")
) -> None:
    """Get a configuration value."""
    value = config.get(key)
    if value is None:
        console.print(f"[yellow]Configuration key '{key}' not found[/yellow]")
    else:
        console.print(f"{key} = {value}")


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Configuration key to set"),
    value: str = typer.Argument(..., help="Value to set")
) -> None:
    """Set a configuration value."""
    # Handle special cases for type conversion
    if key == "max_entries":
        try:
            value = int(value)
        except ValueError:
            console.print("[red]Error: max_entries must be an integer[/red]")
            return
    elif key == "enable_isp_lookup":
        value = value.lower() in ("true", "yes", "1", "on")
    elif key == "dns_cache_ttl":
        try:
            value = int(value)
        except ValueError:
            console.print("[red]Error: dns_cache_ttl must be an integer[/red]")
            return
    
    config.set(key, value)
    console.print(f"[green]Configuration updated: {key} = {value}[/green]")


@config_app.command("list")
def config_list() -> None:
    """List all configuration values."""
    console.print("[bold]UFWInspector Configuration[/bold]")
    for key, value in config.config.items():
        console.print(f"{key} = {value}")


@config_app.command("reset")
def config_reset() -> None:
    """Reset configuration to defaults."""
    config.reset()
    console.print("[green]Configuration reset to defaults[/green]")
    config_list()


@app.command()
def analyze(
    log_file: Optional[str] = typer.Option(
        None, 
        "--log-file", 
        "-f", 
        help="Path to the UFW log file (overrides config)"
    ),
    plain: bool = typer.Option(
        False, 
        "--plain", 
        "-p", 
        help="Use plain text output instead of rich formatting"
    ),
    group_by_type: bool = typer.Option(
        False, 
        "--group-by-type", 
        "-g", 
        help="Group results by event type"
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        "-d",
        help="Enable debug output"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose debug output"
    )
) -> None:
    """Analyze UFW logs and display results."""
    # Get log file path from config if not provided
    if log_file is None:
        log_file = config.get("log_file")
    
    if not os.path.exists(log_file):
        console.print(f"[red]Error: Log file not found at {log_file}[/red]")
        sys.exit(1)
    
    if not os.access(log_file, os.R_OK):
        console.print(f"[red]Error: Permission denied when accessing {log_file}[/red]")
        sys.exit(1)
    
    console.print(f"[blue]Analyzing UFW logs from {log_file}...[/blue]")
    
    # Create a custom analyzer for verbose debugging
    if verbose:
        from ufwinspector.core.parser import UFWLogParser
        parser = UFWLogParser(log_file)
        
        # Read the first 10 lines for debugging
        with open(log_file, 'r') as f:
            lines = [f.readline().strip() for _ in range(10)]
        
        for i, line in enumerate(lines):
            console.print(f"[yellow]Line {i+1}:[/yellow] {line}")
            event = parser._parse_line(line)
            if event:
                console.print(f"  [green]Parsed successfully:[/green]")
                console.print(f"  - Event type: {event.event_type.name}")
                console.print(f"  - Source IP: {event.source_ip} (Public: {event.source_is_public})")
                console.print(f"  - Destination IP: {event.destination_ip} (Public: {event.destination_is_public})")
                console.print(f"  - Protocol: {event.protocol}")
                console.print(f"  - Ports: {event.source_port} -> {event.destination_port}")
            else:
                console.print(f"  [red]Failed to parse[/red]")
        
        # Continue with normal analysis
    
    analyzer = UFWLogAnalyzer(log_file)
    ip_summaries = analyzer.analyze()
    
    if debug:
        console.print(f"[yellow]Debug: Found {len(analyzer.events)} total events[/yellow]")
        public_ips = set()
        for event in analyzer.events:
            if event.source_ip and event.source_is_public:
                public_ips.add(event.source_ip)
            if event.destination_ip and event.destination_is_public:
                public_ips.add(event.destination_ip)
        console.print(f"[yellow]Debug: Found {len(public_ips)} unique public IPs: {', '.join(list(public_ips)[:10])}{'...' if len(public_ips) > 10 else ''}[/yellow]")
    
    ui = ConsoleUI()
    
    if group_by_type:
        ui.display_event_type_summary(ip_summaries)
    elif plain:
        ui.display_plain_table(ip_summaries)
    else:
        ui.display_summary(ip_summaries)


@app.command()
def version() -> None:
    """Show the version of CozyGuard."""
    console.print(f"[bold]CozyGuard[/bold] version {__version__}")
    console.print(f"Configuration file: {config.config_file}")
    console.print(f"Log file: {config.get('log_file')}")


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"[bold]UFWInspector[/bold] version {__version__}")
    console.print(f"Configuration file: {config.config_file}")
    console.print(f"Default log file: {config.get('log_file')}")


def main() -> None:
    """Entry point for the application."""
    app()


if __name__ == "__main__":
    main()
