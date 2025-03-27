"""
Enterprise SIEM Platform - Brute Force Detector

This module provides capabilities to detect and simulate password brute force attacks.
"""
import time
import logging
import queue
import threading
import re
import random
import socket
import paramiko
import hashlib
from typing import List, Dict, Optional, Tuple, Set
from collections import defaultdict, deque

from src.utils.event import Event

class LoginAttempt:
    """Represents a single login attempt."""
    
    def __init__(self, 
                 source_ip: str,
                 username: str,
                 success: bool,
                 timestamp: float,
                 service: str,
                 destination_ip: Optional[str] = None,
                 destination_port: Optional[int] = None,
                 details: Optional[Dict] = None):
        """Initialize a login attempt.
        
        Args:
            source_ip: Source IP address
            username: Username attempted
            success: Whether the attempt was successful
            timestamp: Unix timestamp of the attempt
            service: Service name (e.g., 'ssh', 'ftp')
            destination_ip: Optional destination IP
            destination_port: Optional destination port
            details: Additional details about the attempt
        """
        self.source_ip = source_ip
        self.username = username
        self.success = success
        self.timestamp = timestamp
        self.service = service
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.details = details or {}


class BruteForceDetector:
    """Detects brute force password attacks."""
    
    def __init__(self, config: dict):
        """Initialize the brute force detector.
        
        Args:
            config: Dictionary with detector configuration
        """
        self.config = config
        self.enabled = config.get('enabled', False)
        self.check_interval = config.get('check_interval', 10)  # seconds
        self.time_window = config.get('time_window', 300)  # 5 minutes
        self.threshold = config.get('threshold', 5)  # 5 failed attempts
        self.alert_cooldown = config.get('alert_cooldown', 300)  # 5 minutes
        
        # Simulation settings
        self.simulate = config.get('simulate', {})
        self.simulate_enabled = self.simulate.get('enabled', False)
        self.simulate_interval = self.simulate.get('interval', 3600)  # Default: simulate every hour
        self.simulate_targets = self.simulate.get('targets', [])
        self.simulate_usernames = self.simulate.get('usernames', ['admin', 'root', 'user'])
        self.simulate_services = self.simulate.get('services', ['ssh'])
        
        # Track login attempts per source IP, user, and service
        self.attempts = defaultdict(list)  # (source_ip, username, service) -> list of attempts
        self.last_alert_time = {}  # (source_ip, username, service) -> timestamp
        
        self.logger = logging.getLogger(__name__)
        
    def add_login_attempt(self, attempt: LoginAttempt):
        """Add a login attempt for analysis.
        
        Args:
            attempt: LoginAttempt object
        """
        key = (attempt.source_ip, attempt.username, attempt.service)
        self.attempts[key].append(attempt)
        
        # Clean old attempts outside time window
        cutoff = time.time() - self.time_window
        self.attempts[key] = [a for a in self.attempts[key] if a.timestamp >= cutoff]
        
    def check_brute_force(self) -> List[Event]:
        """Check for brute force patterns and generate events.
        
        Returns:
            List of Events for detected brute force attempts
        """
        events = []
        now = time.time()
        
        for key, attempts in self.attempts.items():
            source_ip, username, service = key
            
            # Skip if we've recently alerted about this
            last_alert = self.last_alert_time.get(key, 0)
            if now - last_alert < self.alert_cooldown:
                continue
                
            # Count failed attempts in time window
            failed_attempts = [a for a in attempts if not a.success]
            
            if len(failed_attempts) >= self.threshold:
                # Check if there was a successful login after the failed attempts
                successful_after_failures = any(
                    a.success and a.timestamp > failed_attempts[0].timestamp 
                    for a in attempts
                )
                
                severity = 'high' if successful_after_failures else 'medium'
                
                # Create event
                event = Event(
                    source='brute_force_detector',
                    event_type='brute_force_detected',
                    message=f"Possible brute force attack detected from {source_ip} against {username} on {service}. " +
                            f"{len(failed_attempts)} failed attempts" +
                            (" with successful login afterward" if successful_after_failures else ""),
                    severity=severity,
                    details={
                        'source_ip': source_ip,
                        'username': username,
                        'service': service,
                        'failed_attempts': len(failed_attempts),
                        'successful_login': successful_after_failures,
                        'first_attempt': failed_attempts[0].timestamp,
                        'last_attempt': failed_attempts[-1].timestamp,
                        'destination_ip': attempts[0].destination_ip,
                        'destination_port': attempts[0].destination_port,
                    }
                )
                events.append(event)
                
                # Update last alert time
                self.last_alert_time[key] = now
                
        return events
    
    def parse_windows_event(self, event: Dict) -> Optional[LoginAttempt]:
        """Parse Windows security event for login attempts.
        
        Args:
            event: Windows event dictionary
            
        Returns:
            LoginAttempt object if event is a login attempt, None otherwise
        """
        try:
            event_id = event.get('EventID')
            
            # Windows logon events
            if event_id in [4624, 4625]:
                details = event.get('EventData', {})
                
                source_ip = details.get('IpAddress', '')
                if source_ip == '-' or source_ip == '::1' or source_ip.startswith('127.'):
                    source_ip = 'localhost'
                
                username = details.get('TargetUserName', '')
                if not username or username == 'SYSTEM' or username == 'LOCAL SERVICE':
                    return None
                
                success = (event_id == 4624)
                timestamp = event.get('TimeCreated', time.time())
                
                login_type = details.get('LogonType')
                
                # Determine service based on logon type
                service_map = {
                    '2': 'interactive',
                    '3': 'network',
                    '4': 'batch',
                    '5': 'service',
                    '7': 'unlock',
                    '8': 'network_cleartext',
                    '9': 'new_credentials',
                    '10': 'remote_interactive',
                    '11': 'cached_interactive'
                }
                
                service = service_map.get(str(login_type), 'unknown')
                
                return LoginAttempt(
                    source_ip=source_ip,
                    username=username,
                    success=success,
                    timestamp=timestamp,
                    service=service,
                    destination_ip='local',
                    details=details
                )
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error parsing Windows event: {str(e)}")
            return None
            
    def parse_syslog_event(self, event: Dict) -> Optional[LoginAttempt]:
        """Parse syslog event for login attempts.
        
        Args:
            event: Syslog event dictionary
            
        Returns:
            LoginAttempt object if event is a login attempt, None otherwise
        """
        try:
            message = event.get('message', '')
            program = event.get('program', '')
            timestamp = event.get('timestamp', time.time())
            
            # SSH login attempts
            if program in ['sshd', 'ssh']:
                # Failed password
                failed_match = re.search(r'Failed password for (invalid user )?(\S+) from (\S+) port \d+', message)
                if failed_match:
                    username = failed_match.group(2)
                    source_ip = failed_match.group(3)
                    return LoginAttempt(
                        source_ip=source_ip,
                        username=username,
                        success=False,
                        timestamp=timestamp,
                        service='ssh'
                    )
                
                # Successful login
                success_match = re.search(r'Accepted password for (\S+) from (\S+) port \d+', message)
                if success_match:
                    username = success_match.group(1)
                    source_ip = success_match.group(2)
                    return LoginAttempt(
                        source_ip=source_ip,
                        username=username,
                        success=True,
                        timestamp=timestamp,
                        service='ssh'
                    )
            
            # FTP login attempts (vsftpd)
            if program == 'vsftpd':
                # Failed login
                failed_match = re.search(r'FAIL LOGIN: Client "(\S+)"', message)
                if failed_match:
                    source_ip = failed_match.group(1)
                    # Username not always available in vsftpd logs
                    return LoginAttempt(
                        source_ip=source_ip,
                        username='unknown',
                        success=False,
                        timestamp=timestamp,
                        service='ftp'
                    )
                
                # Successful login
                success_match = re.search(r'OK LOGIN: Client "(\S+)", user "(\S+)"', message)
                if success_match:
                    source_ip = success_match.group(1)
                    username = success_match.group(2)
                    return LoginAttempt(
                        source_ip=source_ip,
                        username=username,
                        success=True,
                        timestamp=timestamp,
                        service='ftp'
                    )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error parsing syslog event: {str(e)}")
            return None
            
    def simulate_brute_force(self) -> List[LoginAttempt]:
        """Simulate a brute force attack for testing.
        
        Returns:
            List of simulated login attempts
        """
        if not self.simulate_enabled or not self.simulate_targets:
            return []
            
        attempts = []
        now = time.time()
        
        # Choose a random target, service, and username
        target = random.choice(self.simulate_targets)
        service = random.choice(self.simulate_services)
        username = random.choice(self.simulate_usernames)
        
        # Generate a random source IP for the attacker
        octets = [str(random.randint(1, 254)) for _ in range(4)]
        source_ip = '.'.join(octets)
        
        # Determine port based on service
        port = 22 if service == 'ssh' else 21
        
        # Generate 5-15 failed attempts
        num_attempts = random.randint(5, 15)
        
        for i in range(num_attempts):
            # Attempts happen in quick succession
            timestamp = now - (num_attempts - i) * random.uniform(5, 15)
            
            attempt = LoginAttempt(
                source_ip=source_ip,
                username=username,
                success=False,  # Failed attempts
                timestamp=timestamp,
                service=service,
                destination_ip=target,
                destination_port=port,
                details={'simulated': True, 'attempt_number': i + 1}
            )
            attempts.append(attempt)
        
        # Randomly decide if the attack will be successful at the end
        if random.random() < 0.3:  # 30% chance of success
            success_attempt = LoginAttempt(
                source_ip=source_ip,
                username=username,
                success=True,  # Successful attempt
                timestamp=now,
                service=service,
                destination_ip=target,
                destination_port=port,
                details={'simulated': True, 'final_attempt': True}
            )
            attempts.append(success_attempt)
            
        return attempts
    
    def run_active_simulation(self) -> List[LoginAttempt]:
        """Run an active SSH brute force simulation against configured targets.
        
        This method actively attempts SSH connections but doesn't actually
        send any real credentials to prevent security issues.
        
        Returns:
            List of simulated login attempts
        """
        if not self.simulate_enabled or not self.simulate_targets:
            return []
            
        # Only simulate SSH for active connections
        service = 'ssh'
        attempts = []
        now = time.time()
        
        # Choose a random target and username
        target = random.choice(self.simulate_targets)
        username = random.choice(self.simulate_usernames)
        port = 22
        
        # Use a slightly randomized local address
        source_ip = '127.0.0.' + str(random.randint(1, 254))
        
        # Check if the target is available first
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result != 0:
                self.logger.warning(f"Target {target}:{port} is not available for SSH simulation")
                return []
                
        except Exception as e:
            self.logger.error(f"Error checking target availability: {str(e)}")
            return []
        
        # Generate 3-5 failed attempts with actual connections
        num_attempts = random.randint(3, 5)
        
        for i in range(num_attempts):
            try:
                # Create SSH client
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Generate invalid password
                password = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
                
                timestamp = now - (num_attempts - i) * random.uniform(5, 15)
                
                # Attempt connection with invalid credentials
                # This will fail but generate a real login attempt on the target
                try:
                    ssh.connect(
                        target,
                        port=port,
                        username=username,
                        password=password,
                        timeout=3.0
                    )
                    # This should never happen with invalid credentials
                    success = True
                except (paramiko.AuthenticationException, paramiko.SSHException):
                    # Expected authentication failure
                    success = False
                finally:
                    ssh.close()
                
                attempt = LoginAttempt(
                    source_ip=source_ip,
                    username=username,
                    success=success,
                    timestamp=timestamp,
                    service=service,
                    destination_ip=target,
                    destination_port=port,
                    details={'active_simulation': True, 'attempt_number': i + 1}
                )
                attempts.append(attempt)
                
                # Sleep a bit to prevent overwhelming the target
                time.sleep(random.uniform(1.0, 2.0))
                
            except Exception as e:
                self.logger.error(f"Error in active SSH simulation: {str(e)}")
        
        return attempts
    
    def run_detector(self, event_queue: queue.Queue):
        """Run the brute force detector continuously.
        
        Args:
            event_queue: Queue to put events into
        """
        self.logger.info("Brute Force Detector starting")
        last_simulation_time = 0
        
        while True:
            try:
                if not self.enabled:
                    time.sleep(60)  # Check every minute if we've been enabled
                    continue
                
                # Check for brute force patterns
                events = self.check_brute_force()
                
                # Put events into queue
                for event in events:
                    event_queue.put(event)
                
                # Check if it's time to run a simulation
                now = time.time()
                if self.simulate_enabled and now - last_simulation_time >= self.simulate_interval:
                    self.logger.info("Running brute force simulation")
                    
                    # Choose between passive and active simulation
                    if random.random() < 0.8:  # 80% passive, 20% active
                        simulated_attempts = self.simulate_brute_force()
                        simulation_type = "passive"
                    else:
                        simulated_attempts = self.run_active_simulation()
                        simulation_type = "active"
                    
                    for attempt in simulated_attempts:
                        self.add_login_attempt(attempt)
                    
                    self.logger.info(f"Completed {simulation_type} brute force simulation with {len(simulated_attempts)} attempts")
                    last_simulation_time = now
                
                # Sleep until next check
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in brute force detector: {str(e)}")
                time.sleep(60)  # Wait a minute before retrying 