from typing import List, Dict, Any
from rich.table import Table

try:
    from scapy.all import traceroute as scapy_traceroute
except ImportError:
    pass

class TraceRoute:
    """Network Path Mapping using Scapy."""

    def __init__(self):
        pass

    def trace(self, target: str, max_hops: int = 30) -> List[Dict[str, Any]]:
        """Run traceroute to a target."""
        results = []
        try:
            # scapy_traceroute returns (ans, unans)
            ans, _ = scapy_traceroute(target, maxttl=max_hops, verbose=0)
            
            for snd, rcv in ans:
                ttl = snd.ttl
                ip = rcv.src
                # Scapy ans tuples give us time directly via sent/rcv times if available, or we approximate
                rtt = (rcv.time - snd.sent_time) * 1000 if hasattr(snd, 'sent_time') else 0
                results.append({
                    'hop': ttl,
                    'ip': ip,
                    'rtt': round(rtt, 2),
                    'hostname': '' # could be resolved later
                })
                
            # Fill missing hops (timeout)
            if results:
                max_found = max(r['hop'] for r in results)
                final_results = []
                found_dict = {r['hop']: r for r in results}
                for i in range(1, max_found + 1):
                    if i in found_dict:
                        final_results.append(found_dict[i])
                    else:
                        final_results.append({
                            'hop': i,
                            'ip': '* * *',
                            'rtt': 0.0,
                            'hostname': ''
                        })
                return final_results
        except Exception:
            pass
        return results

    def format_results(self, hops: List[Dict[str, Any]]) -> str:
        """Format traceroute results into a Rich table string representation."""
        table = Table(title="Traceroute Results")
        table.add_column("Hop", justify="right", style="cyan", no_wrap=True)
        table.add_column("IP Address", style="magenta")
        table.add_column("Hostname", style="green")
        table.add_column("RTT (ms)", justify="right", style="yellow")

        for hop in hops:
            table.add_row(
                str(hop['hop']),
                hop['ip'],
                hop['hostname'] or "-",
                str(hop['rtt']) if hop['ip'] != '* * *' else "*"
            )
            
        # Rich tables are usually printed. To return as string we capture from the shared console
        from utils.console import console
        with console.capture() as capture:
            console.print(table)
        return capture.get()
