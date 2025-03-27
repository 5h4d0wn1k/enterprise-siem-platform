"""
Enterprise SIEM Platform - Port Scanner

This module provides network port scanning capabilities for vulnerability assessment.
"""
import socket
import threading
import time
import logging
import ipaddress
import queue
from typing import List, Dict, Tuple, Optional

from src.utils.event import Event

class PortScanner:
    """Port scanner for vulnerability assessment."""
    
    def __init__(self, config: dict):
        """Initialize the port scanner.
        
        Args:
            config: Dictionary with scanner configuration
        """
        self.config = config
        self.enabled = config.get('enabled', False)
        self.scan_interval = config.get('scan_interval', 3600)  # Default: scan every hour
        self.targets = config.get('targets', [])
        self.port_ranges = config.get('port_ranges', [(1, 1024)])
        self.scan_timeout = config.get('scan_timeout', 1.0)
        self.concurrency = config.get('concurrency', 50)
        self.last_scan_results = {}
        self.logger = logging.getLogger(__name__)
        
    def scan_target(self, target: str, ports: List[int], timeout: float) -> Dict[int, bool]:
        """Scan a single target for open ports.
        
        Args:
            target: IP address to scan
            ports: List of ports to scan
            timeout: Timeout for each connection attempt
            
        Returns:
            Dictionary of port numbers to open status (True if open)
        """
        results = {}
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((target, port))
                    is_open = (result == 0)
                    results[port] = is_open
            except (socket.gaierror, socket.error) as e:
                self.logger.error(f"Error scanning {target}:{port} - {str(e)}")
                results[port] = False
        return results

    def worker(self, work_queue: queue.Queue, results: Dict[str, Dict[int, bool]]):
        """Worker thread for concurrent scanning.
        
        Args:
            work_queue: Queue of (target, port) tuples to scan
            results: Dictionary to store results
        """
        while not work_queue.empty():
            try:
                target, port = work_queue.get_nowait()
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(self.scan_timeout)
                        result = s.connect_ex((target, port))
                        is_open = (result == 0)
                        
                        if target not in results:
                            results[target] = {}
                            
                        results[target][port] = is_open
                except (socket.gaierror, socket.error) as e:
                    self.logger.error(f"Error scanning {target}:{port} - {str(e)}")
                    if target not in results:
                        results[target] = {}
                    results[target][port] = False
            except queue.Empty:
                break
            finally:
                work_queue.task_done()

    def scan_network(self) -> Dict[str, Dict[int, bool]]:
        """Scan all configured targets and port ranges.
        
        Returns:
            Dictionary of targets to port scan results
        """
        results = {}
        work_queue = queue.Queue()
        
        # Build work queue
        for target_spec in self.targets:
            try:
                # Handle IP ranges (CIDR notation)
                if '/' in target_spec:
                    network = ipaddress.ip_network(target_spec, strict=False)
                    targets = [str(ip) for ip in network.hosts()]
                else:
                    targets = [target_spec]
                
                for target in targets:
                    for port_range in self.port_ranges:
                        start_port, end_port = port_range
                        for port in range(start_port, end_port + 1):
                            work_queue.put((target, port))
            except ValueError as e:
                self.logger.error(f"Invalid target specification: {target_spec} - {str(e)}")
        
        # Create worker threads
        threads = []
        for _ in range(min(self.concurrency, work_queue.qsize())):
            thread = threading.Thread(target=self.worker, args=(work_queue, results))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all scans to complete
        for thread in threads:
            thread.join()
            
        return results
    
    def compare_scan_results(self, current_results: Dict[str, Dict[int, bool]]) -> List[Dict]:
        """Compare current scan results with previous scan results.
        
        Args:
            current_results: Current scan results
            
        Returns:
            List of changes detected
        """
        changes = []
        
        for target, ports in current_results.items():
            for port, is_open in ports.items():
                # Check if we have previous results for this target
                prev_status = self.last_scan_results.get(target, {}).get(port)
                
                # If this is a new target or port, or the status has changed
                if prev_status is None or prev_status != is_open:
                    change = {
                        'target': target,
                        'port': port,
                        'status': 'open' if is_open else 'closed',
                        'previous_status': 'unknown' if prev_status is None else ('open' if prev_status else 'closed'),
                    }
                    changes.append(change)
        
        return changes
    
    def generate_events(self, changes: List[Dict]) -> List[Event]:
        """Generate events for port status changes.
        
        Args:
            changes: List of port status changes
            
        Returns:
            List of Event objects
        """
        events = []
        
        for change in changes:
            target = change['target']
            port = change['port']
            status = change['status']
            previous_status = change['previous_status']
            
            # Only generate events for newly opened ports or status changes
            if status == 'open' or (status != previous_status and previous_status != 'unknown'):
                # Determine common service for this port
                service = self.get_common_service(port)
                
                # Create event
                event = Event(
                    source='port_scanner',
                    event_type='port_status_change',
                    message=f"Port {port} ({service}) on {target} is {status} (was: {previous_status})",
                    severity='medium' if status == 'open' else 'low',
                    details={
                        'target': target,
                        'port': port,
                        'status': status,
                        'previous_status': previous_status,
                        'service': service,
                        'timestamp': time.time()
                    }
                )
                events.append(event)
                
        return events
    
    def get_common_service(self, port: int) -> str:
        """Get common service name for a port number.
        
        Args:
            port: Port number
            
        Returns:
            Service name string
        """
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            123: 'NTP',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT'
        }
        
        return common_ports.get(port, 'Unknown')
    
    def run_scanner(self, event_queue: queue.Queue):
        """Run the port scanner at regular intervals.
        
        Args:
            event_queue: Queue to put events into
        """
        self.logger.info("Port Scanner starting")
        
        while True:
            try:
                if not self.enabled:
                    time.sleep(60)  # Check every minute if we've been enabled
                    continue
                
                self.logger.info("Starting network scan")
                scan_start = time.time()
                
                # Run the scan
                current_results = self.scan_network()
                
                # Compare with previous results
                changes = self.compare_scan_results(current_results)
                
                # Generate events for changes
                events = self.generate_events(changes)
                
                # Put events into queue
                for event in events:
                    event_queue.put(event)
                
                # Update last scan results
                self.last_scan_results = current_results
                
                scan_duration = time.time() - scan_start
                self.logger.info(f"Network scan completed in {scan_duration:.2f} seconds. Found {len(events)} changes.")
                
                # Sleep until next scan
                time.sleep(max(1, self.scan_interval - scan_duration))
                
            except Exception as e:
                self.logger.error(f"Error in port scanner: {str(e)}")
                time.sleep(60)  # Wait a minute before retrying 