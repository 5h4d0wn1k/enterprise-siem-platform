"""
Enterprise SIEM Platform - Offensive Security Manager

This module manages and coordinates all offensive security features.
"""
import logging
import threading
import queue
import time
from typing import List, Dict, Optional

from src.offensive.port_scanner import PortScanner
from src.offensive.brute_force_detector import BruteForceDetector
from src.offensive.vulnerability_scanner import VulnerabilityScanner
from src.utils.event import Event

class OffensiveSecurityManager:
    """Manages all offensive security components."""
    
    def __init__(self, config: dict):
        """Initialize the offensive security manager.
        
        Args:
            config: Dictionary with offensive security configuration
        """
        self.config = config
        self.enabled = config.get('enabled', False)
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing Offensive Security Manager")
        
        # Initialize components
        self.port_scanner = None
        self.brute_force_detector = None
        self.vulnerability_scanner = None
        
        # Initialize port scanner if enabled
        port_scanner_config = config.get('port_scanner', {})
        if port_scanner_config.get('enabled', False):
            self.logger.info("Initializing Port Scanner")
            self.port_scanner = PortScanner(port_scanner_config)
        
        # Initialize brute force detector if enabled
        brute_force_config = config.get('brute_force', {})
        if brute_force_config.get('enabled', False):
            self.logger.info("Initializing Brute Force Detector")
            self.brute_force_detector = BruteForceDetector(brute_force_config)
        
        # Initialize vulnerability scanner if enabled
        vuln_scanner_config = config.get('vulnerability_scanner', {})
        if vuln_scanner_config.get('enabled', False):
            self.logger.info("Initializing Vulnerability Scanner")
            self.vulnerability_scanner = VulnerabilityScanner(vuln_scanner_config)
    
    def start(self, event_queue: queue.Queue) -> List[threading.Thread]:
        """Start all offensive security components.
        
        Args:
            event_queue: Queue to put events into
            
        Returns:
            List of started threads
        """
        if not self.enabled:
            self.logger.info("Offensive Security Manager is disabled")
            return []
            
        threads = []
        
        # Start port scanner
        if self.port_scanner:
            self.logger.info("Starting Port Scanner")
            thread = threading.Thread(
                target=self.port_scanner.run_scanner,
                args=(event_queue,),
                daemon=True
            )
            thread.start()
            threads.append(('Port Scanner', thread))
        
        # Start brute force detector
        if self.brute_force_detector:
            self.logger.info("Starting Brute Force Detector")
            thread = threading.Thread(
                target=self.brute_force_detector.run_detector,
                args=(event_queue,),
                daemon=True
            )
            thread.start()
            threads.append(('Brute Force Detector', thread))
        
        # Start vulnerability scanner
        if self.vulnerability_scanner:
            self.logger.info("Starting Vulnerability Scanner")
            thread = threading.Thread(
                target=self.vulnerability_scanner.run_scanner,
                args=(event_queue,),
                daemon=True
            )
            thread.start()
            threads.append(('Vulnerability Scanner', thread))
        
        return threads
    
    def process_event(self, event: Event) -> Optional[List[Event]]:
        """Process an incoming event for offensive security analysis.
        
        This method allows the offensive security components to analyze
        events from other sources and potentially generate additional events.
        
        Args:
            event: Event to process
            
        Returns:
            List of additional events or None
        """
        if not self.enabled:
            return None
            
        additional_events = []
        
        # Process with brute force detector if it's a login event
        if self.brute_force_detector and event.event_type in ['login_attempt', 'authentication']:
            # Determine if this is a login attempt and create a LoginAttempt object
            
            # Extract source IP
            source_ip = event.details.get('source_ip', 'unknown')
            if source_ip == 'unknown' and 'ip' in event.details:
                source_ip = event.details['ip']
                
            # Extract username
            username = event.details.get('username', 'unknown')
            if username == 'unknown' and 'user' in event.details:
                username = event.details['user']
                
            # Determine success
            success = event.details.get('success', False)
            if not isinstance(success, bool) and 'result' in event.details:
                success = event.details['result'] == 'success'
                
            # Determine service
            service = event.details.get('service', 'unknown')
            if service == 'unknown' and 'protocol' in event.details:
                service = event.details['protocol']
                
            # Create login attempt if we have enough information
            if source_ip != 'unknown' and username != 'unknown':
                login_attempt = self.brute_force_detector.LoginAttempt(
                    source_ip=source_ip,
                    username=username,
                    success=success,
                    timestamp=event.timestamp,
                    service=service,
                    destination_ip=event.details.get('destination_ip'),
                    destination_port=event.details.get('destination_port'),
                    details=event.details
                )
                
                # Add to brute force detector
                self.brute_force_detector.add_login_attempt(login_attempt)
                
                # Check for brute force patterns immediately
                brute_force_events = self.brute_force_detector.check_brute_force()
                additional_events.extend(brute_force_events)
        
        return additional_events if additional_events else None
        
    def stop(self):
        """Stop all offensive security components."""
        self.logger.info("Stopping Offensive Security Manager")
        # Nothing to do here since components run in daemon threads 