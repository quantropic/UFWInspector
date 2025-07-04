"""Console UI for UFWInspector."""

from typing import List

from rich.console import Console
from rich.table import Table
from tabulate import tabulate

from ..core.analyzer import IPSummary
from ..core.parser import UFWEventType


class ConsoleUI:
    """Console UI for displaying analysis results."""

    def __init__(self) -> None:
        """Initialize the console UI."""
        self.console = Console()

    def display_summary(self, ip_summaries: List[IPSummary]) -> None:
        """Display a summary of the analysis results."""
        if not ip_summaries:
            self.console.print("[yellow]No public IP addresses found in the logs.[/yellow]")
            return

        table = Table(title="UFW Log Analysis Summary")
        
        table.add_column("IP Address", style="cyan")
        table.add_column("Domain Name", style="green")
        table.add_column("ISP", style="cyan")  # Added ISP column
        table.add_column("Direction", style="blue")
        table.add_column("In Count", justify="right", style="red")
        table.add_column("Out Count", justify="right", style="magenta")
        table.add_column("Event Types", style="yellow")
        table.add_column("Protocols", style="white")
        
        for summary in ip_summaries:
            # Format direction with emphasis on incoming connections
            if summary.direction_type == "Incoming":
                direction = "[bold red]Incoming[/bold red]"
            elif summary.direction_type == "Outgoing":
                direction = "[green]Outgoing[/green]"
            else:
                direction = "[yellow]Bidirectional[/yellow]"
            
            # Format event types by direction
            source_events = [et.name for et in summary.source_event_types]
            dest_events = [et.name for et in summary.destination_event_types]
            
            if summary.direction_type == "Incoming":
                event_types = f"[bold red]{', '.join(source_events)}[/bold red]"
            elif summary.direction_type == "Outgoing":
                event_types = f"[green]{', '.join(dest_events)}[/green]"
            else:
                event_types = f"In: [red]{', '.join(source_events)}[/red], Out: [green]{', '.join(dest_events)}[/green]"
            
            # Show ISP info only if domain name is the same as IP (unresolved)
            isp_info = summary.isp if summary.domain_name == summary.ip_address else "-"
            
            table.add_row(
                summary.ip_address,
                summary.domain_name,
                isp_info,
                direction,
                str(summary.source_count) if summary.source_count > 0 else "-",
                str(summary.destination_count) if summary.destination_count > 0 else "-",
                event_types,
                ", ".join(summary.protocols) if summary.protocols else "N/A"
            )
        
        self.console.print(table)

    def display_plain_table(self, ip_summaries: List[IPSummary]) -> None:
        """Display results as a plain text table."""
        if not ip_summaries:
            print("No public IP addresses found in the logs.")
            return

        table_data = []
        headers = ["IP Address", "Domain Name", "ISP", "Direction", "In Count", "Out Count", "Event Types", "Protocols"]
        
        for summary in ip_summaries:
            # Format event types by direction
            source_events = [et.name for et in summary.source_event_types]
            dest_events = [et.name for et in summary.destination_event_types]
            
            if summary.direction_type == "Incoming":
                event_types = f"IN: {', '.join(source_events)}"
            elif summary.direction_type == "Outgoing":
                event_types = f"OUT: {', '.join(dest_events)}"
            else:
                event_types = f"IN: {', '.join(source_events)}, OUT: {', '.join(dest_events)}"
            
            # Show ISP info only if domain name is the same as IP (unresolved)
            isp_info = summary.isp if summary.domain_name == summary.ip_address else "-"
            
            table_data.append([
                summary.ip_address,
                summary.domain_name,
                isp_info,
                summary.direction_type,
                summary.source_count if summary.source_count > 0 else "-",
                summary.destination_count if summary.destination_count > 0 else "-",
                event_types,
                ", ".join(summary.protocols) if summary.protocols else "N/A"
            ])
        


    def display_tsv(self, ip_summaries: List[IPSummary]) -> None:
        """Display results as tab-separated values."""
        if not ip_summaries:
            print("No public IP addresses found in the logs.")
            return

        # Print header
        headers = ["IP_Address", "Domain_Name", "ISP", "Direction", "In_Count", "Out_Count", "Event_Types", "Protocols"]
        print("\t".join(headers))
        
        # Print data rows
        for summary in ip_summaries:
            source_events = [et.name for et in summary.source_event_types]
            dest_events = [et.name for et in summary.destination_event_types]
            
            if summary.direction_type == "Incoming":
                event_types = f"IN:{','.join(source_events)}"
            elif summary.direction_type == "Outgoing":
                event_types = f"OUT:{','.join(dest_events)}"
            else:
                event_types = f"IN:{','.join(source_events)},OUT:{','.join(dest_events)}"
            
            isp_info = summary.isp if summary.domain_name == summary.ip_address else "-"
            
            row = [
                summary.ip_address,
                summary.domain_name,
                isp_info,
                summary.direction_type,
                str(summary.source_count) if summary.source_count > 0 else "0",
                str(summary.destination_count) if summary.destination_count > 0 else "0",
                event_types,
                ",".join(summary.protocols) if summary.protocols else "N/A"
            ]
            print("\t".join(row))

    def display_event_type_summary(self, ip_summaries: List[IPSummary]) -> None:
        """Display a summary grouped by event type."""
        if not ip_summaries:
            self.console.print("[yellow]No public IP addresses found in the logs.[/yellow]")
            return
        
        # First, display incoming connections (highest priority)
        incoming_ips = [s for s in ip_summaries if s.direction_type == "Incoming"]
        if incoming_ips:
            self.console.print("\n[bold red]INCOMING CONNECTIONS[/bold red] (External IPs connecting to your system)")
            
            table = Table()
            table.add_column("IP Address", style="cyan")
            table.add_column("Domain Name", style="green")
            table.add_column("ISP", style="cyan")  # Added ISP column
            table.add_column("Count", justify="right", style="magenta")
            table.add_column("Event Types", style="yellow")
            table.add_column("Protocols", style="white")
            
            for summary in sorted(incoming_ips, key=lambda x: x.source_count, reverse=True):
                source_events = [et.name for et in summary.source_event_types]
                
                # Show ISP info only if domain name is the same as IP (unresolved)
                isp_info = summary.isp if summary.domain_name == summary.ip_address else "-"
                
                table.add_row(
                    summary.ip_address,
                    summary.domain_name,
                    isp_info,
                    str(summary.source_count),
                    ", ".join(source_events),
                    ", ".join(summary.protocols) if summary.protocols else "N/A"
                )
            
            self.console.print(table)
        
        # Then display bidirectional connections
        bidir_ips = [s for s in ip_summaries if s.direction_type == "Bidirectional"]
        if bidir_ips:
            self.console.print("\n[bold yellow]BIDIRECTIONAL CONNECTIONS[/bold yellow]")
            
            table = Table()
            table.add_column("IP Address", style="cyan")
            table.add_column("Domain Name", style="green")
            table.add_column("ISP", style="cyan")  # Added ISP column
            table.add_column("In Count", justify="right", style="red")
            table.add_column("Out Count", justify="right", style="magenta")
            table.add_column("Event Types", style="yellow")
            
            for summary in sorted(bidir_ips, key=lambda x: x.count, reverse=True):
                source_events = [et.name for et in summary.source_event_types]
                dest_events = [et.name for et in summary.destination_event_types]
                event_types = f"In: {', '.join(source_events)}, Out: {', '.join(dest_events)}"
                
                # Show ISP info only if domain name is the same as IP (unresolved)
                isp_info = summary.isp if summary.domain_name == summary.ip_address else "-"
                
                table.add_row(
                    summary.ip_address,
                    summary.domain_name,
                    isp_info,
                    str(summary.source_count),
                    str(summary.destination_count),
                    event_types
                )
            
            self.console.print(table)
        
        # Finally display outgoing connections
        outgoing_ips = [s for s in ip_summaries if s.direction_type == "Outgoing"]
        if outgoing_ips:
            self.console.print("\n[bold green]OUTGOING CONNECTIONS[/bold green] (Your system connecting to external IPs)")
            
            table = Table()
            table.add_column("IP Address", style="cyan")
            table.add_column("Domain Name", style="green")
            table.add_column("ISP", style="cyan")  # Added ISP column
            table.add_column("Count", justify="right", style="magenta")
            table.add_column("Event Types", style="yellow")
            table.add_column("Protocols", style="white")
            
            for summary in sorted(outgoing_ips, key=lambda x: x.destination_count, reverse=True):
                dest_events = [et.name for et in summary.destination_event_types]
                
                # Show ISP info only if domain name is the same as IP (unresolved)
                isp_info = summary.isp if summary.domain_name == summary.ip_address else "-"
                
                table.add_row(
                    summary.ip_address,
                    summary.domain_name,
                    isp_info,
                    str(summary.destination_count),
                    ", ".join(dest_events),
                    ", ".join(summary.protocols) if summary.protocols else "N/A"
                )
            
            self.console.print(table)
