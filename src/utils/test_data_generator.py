"""
Test Data Generator for Enterprise SIEM Platform.

This module provides functions to generate test events for development and testing.
It can be used to simulate different types of security events and test the system
without requiring actual security events to occur.
"""
import random
import datetime
import time
import logging
import ipaddress
import uuid
from src.utils.event import Event

logger = logging.getLogger(__name__)

# Common event types for testing
COMMON_EVENT_TYPES = {
    'authentication': ['login_success', 'login_failure', 'password_change', 'account_lockout'],
    'file_access': ['file_read', 'file_write', 'file_delete', 'file_permission_change'],
    'network': ['connection_established', 'connection_terminated', 'firewall_block', 'dns_query'],
    'system': ['process_start', 'process_terminate', 'service_start', 'service_stop', 'system_boot', 'system_shutdown'],
    'security': ['malware_detected', 'intrusion_attempt', 'suspicious_activity', 'policy_violation']
}

# Sample usernames for authentication events
SAMPLE_USERNAMES = ['admin', 'user', 'guest', 'system', 'root', 'service_account', 'john.doe', 'jane.doe']

# Sample file paths for file access events
SAMPLE_FILE_PATHS = [
    'C:\\Windows\\System32\\config\\SAM',
    'C:\\Users\\Administrator\\Documents\\confidential.docx',
    'C:\\Program Files\\Application\\config.ini',
    '/etc/passwd',
    '/var/log/auth.log',
    '/home/user/documents/report.pdf'
]

# Sample IP addresses for network events
SAMPLE_IP_RANGES = [
    '192.168.1.0/24',   # Local network
    '10.0.0.0/8',       # Private network
    '172.16.0.0/12',    # Private network
    '8.8.8.0/24',       # Google DNS range
    '1.1.1.0/24'        # Cloudflare DNS range
]

# Sample process names for system events
SAMPLE_PROCESSES = [
    'svchost.exe',
    'explorer.exe',
    'chrome.exe',
    'outlook.exe',
    'powershell.exe',
    'cmd.exe',
    'httpd',
    'mysqld',
    'nginx',
    'python.exe'
]


def generate_random_timestamp(days_back=1):
    """
    Generate a random timestamp within the last specified number of days.
    
    Args:
        days_back (int): Number of days in the past to go back
        
    Returns:
        datetime: Random timestamp
    """
    now = datetime.datetime.now()
    seconds_back = days_back * 24 * 60 * 60
    random_seconds = random.randint(0, seconds_back)
    return now - datetime.timedelta(seconds=random_seconds)


def generate_random_ip(ip_range=None):
    """
    Generate a random IP address, optionally within a specific range.
    
    Args:
        ip_range (str): IP range in CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        str: Random IP address
    """
    if ip_range is None:
        ip_range = random.choice(SAMPLE_IP_RANGES)
    
    network = ipaddress.IPv4Network(ip_range)
    # Get the first and last IP in the range
    first_ip = int(network.network_address)
    last_ip = int(network.broadcast_address)
    
    # Generate a random IP in that range
    random_ip = ipaddress.IPv4Address(random.randint(first_ip, last_ip))
    return str(random_ip)


def generate_authentication_event(severity=None, event_type=None):
    """
    Generate a random authentication event.
    
    Args:
        severity (str): Optional severity level
        event_type (str): Optional specific event type
        
    Returns:
        Event: Generated event
    """
    if event_type is None:
        event_type = random.choice(COMMON_EVENT_TYPES['authentication'])
    
    username = random.choice(SAMPLE_USERNAMES)
    source_ip = generate_random_ip()
    
    # Determine message based on event type
    if event_type == 'login_success':
        message = f"Successful login for user '{username}' from {source_ip}"
        default_severity = 'low'
    elif event_type == 'login_failure':
        message = f"Failed login attempt for user '{username}' from {source_ip}"
        default_severity = 'medium'
    elif event_type == 'password_change':
        message = f"Password changed for user '{username}' from {source_ip}"
        default_severity = 'low'
    elif event_type == 'account_lockout':
        message = f"Account '{username}' locked out after multiple failed login attempts from {source_ip}"
        default_severity = 'high'
    else:
        message = f"Authentication event: {event_type} for user '{username}' from {source_ip}"
        default_severity = 'low'
    
    # Use provided severity or default based on event type
    severity = severity or default_severity
    
    # Create raw data
    raw_data = {
        'username': username,
        'source_ip': source_ip,
        'event_type': event_type,
        'auth_method': random.choice(['password', 'key', 'token', 'certificate']),
        'success': event_type == 'login_success',
    }
    
    return Event(
        source='authentication',
        event_type=f"auth_{event_type}",
        message=message,
        raw_data=raw_data,
        severity=severity,
        timestamp=generate_random_timestamp()
    )


def generate_file_access_event(severity=None, event_type=None):
    """
    Generate a random file access event.
    
    Args:
        severity (str): Optional severity level
        event_type (str): Optional specific event type
        
    Returns:
        Event: Generated event
    """
    if event_type is None:
        event_type = random.choice(COMMON_EVENT_TYPES['file_access'])
    
    file_path = random.choice(SAMPLE_FILE_PATHS)
    username = random.choice(SAMPLE_USERNAMES)
    
    # Determine message based on event type
    if event_type == 'file_read':
        message = f"File '{file_path}' read by user '{username}'"
        default_severity = 'low'
    elif event_type == 'file_write':
        message = f"File '{file_path}' modified by user '{username}'"
        default_severity = 'medium'
    elif event_type == 'file_delete':
        message = f"File '{file_path}' deleted by user '{username}'"
        default_severity = 'medium'
    elif event_type == 'file_permission_change':
        message = f"Permissions changed on file '{file_path}' by user '{username}'"
        default_severity = 'medium'
    else:
        message = f"File access event: {event_type} on '{file_path}' by user '{username}'"
        default_severity = 'low'
    
    # Use provided severity or default based on event type
    severity = severity or default_severity
    
    # Increase severity for sensitive files
    if 'System32' in file_path or '/etc/' in file_path or 'confidential' in file_path:
        if severity == 'low':
            severity = 'medium'
        elif severity == 'medium':
            severity = 'high'
    
    # Create raw data
    raw_data = {
        'file_path': file_path,
        'username': username,
        'event_type': event_type,
        'process_name': random.choice(SAMPLE_PROCESSES)
    }
    
    return Event(
        source='file_system',
        event_type=f"file_{event_type}",
        message=message,
        raw_data=raw_data,
        severity=severity,
        timestamp=generate_random_timestamp()
    )


def generate_network_event(severity=None, event_type=None):
    """
    Generate a random network event.
    
    Args:
        severity (str): Optional severity level
        event_type (str): Optional specific event type
        
    Returns:
        Event: Generated event
    """
    if event_type is None:
        event_type = random.choice(COMMON_EVENT_TYPES['network'])
    
    source_ip = generate_random_ip()
    dest_ip = generate_random_ip()
    source_port = random.randint(1024, 65535)
    dest_port = random.choice([21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080])
    protocol = random.choice(['TCP', 'UDP', 'ICMP'])
    
    # Determine message based on event type
    if event_type == 'connection_established':
        message = f"{protocol} connection established from {source_ip}:{source_port} to {dest_ip}:{dest_port}"
        default_severity = 'low'
    elif event_type == 'connection_terminated':
        message = f"{protocol} connection terminated from {source_ip}:{source_port} to {dest_ip}:{dest_port}"
        default_severity = 'low'
    elif event_type == 'firewall_block':
        message = f"Firewall blocked {protocol} connection from {source_ip}:{source_port} to {dest_ip}:{dest_port}"
        default_severity = 'medium'
    elif event_type == 'dns_query':
        domains = ['example.com', 'google.com', 'microsoft.com', 'suspicious-site.com', 'malware-domain.com']
        domain = random.choice(domains)
        message = f"DNS query from {source_ip} for domain {domain}"
        default_severity = 'low'
        if 'suspicious' in domain or 'malware' in domain:
            default_severity = 'high'
    else:
        message = f"Network event: {event_type} from {source_ip} to {dest_ip}"
        default_severity = 'low'
    
    # Use provided severity or default based on event type
    severity = severity or default_severity
    
    # Create raw data
    raw_data = {
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'source_port': source_port,
        'dest_port': dest_port,
        'protocol': protocol,
        'event_type': event_type
    }
    
    return Event(
        source='network',
        event_type=f"net_{event_type}",
        message=message,
        raw_data=raw_data,
        severity=severity,
        timestamp=generate_random_timestamp()
    )


def generate_system_event(severity=None, event_type=None):
    """
    Generate a random system event.
    
    Args:
        severity (str): Optional severity level
        event_type (str): Optional specific event type
        
    Returns:
        Event: Generated event
    """
    if event_type is None:
        event_type = random.choice(COMMON_EVENT_TYPES['system'])
    
    process_name = random.choice(SAMPLE_PROCESSES)
    pid = random.randint(1000, 9999)
    user = random.choice(SAMPLE_USERNAMES)
    
    # Determine message based on event type
    if event_type == 'process_start':
        message = f"Process '{process_name}' (PID: {pid}) started by user '{user}'"
        default_severity = 'low'
    elif event_type == 'process_terminate':
        message = f"Process '{process_name}' (PID: {pid}) terminated"
        default_severity = 'low'
    elif event_type == 'service_start':
        message = f"Service '{process_name}' started by user '{user}'"
        default_severity = 'low'
    elif event_type == 'service_stop':
        message = f"Service '{process_name}' stopped by user '{user}'"
        default_severity = 'low'
    elif event_type == 'system_boot':
        message = f"System boot completed"
        default_severity = 'low'
    elif event_type == 'system_shutdown':
        message = f"System shutdown initiated by user '{user}'"
        default_severity = 'low'
    else:
        message = f"System event: {event_type}"
        default_severity = 'low'
    
    # Use provided severity or default based on event type
    severity = severity or default_severity
    
    # Increase severity for certain processes
    if process_name in ['cmd.exe', 'powershell.exe'] and event_type == 'process_start':
        if user in ['admin', 'root', 'system']:
            severity = 'medium'
    
    # Create raw data
    raw_data = {
        'process_name': process_name,
        'pid': pid,
        'user': user,
        'event_type': event_type,
        'command_line': f"{process_name} --arg1 --arg2"
    }
    
    return Event(
        source='system',
        event_type=f"sys_{event_type}",
        message=message,
        raw_data=raw_data,
        severity=severity,
        timestamp=generate_random_timestamp()
    )


def generate_security_event(severity=None, event_type=None):
    """
    Generate a random security event.
    
    Args:
        severity (str): Optional severity level
        event_type (str): Optional specific event type
        
    Returns:
        Event: Generated event
    """
    if event_type is None:
        event_type = random.choice(COMMON_EVENT_TYPES['security'])
    
    source_ip = generate_random_ip()
    
    # Determine message based on event type
    if event_type == 'malware_detected':
        malware_names = ['Trojan.Win32.Generic', 'Backdoor.Java.Agent', 'Worm.Python.Dummy', 'Ransomware.Crypto.Evil']
        malware_name = random.choice(malware_names)
        file_path = random.choice(SAMPLE_FILE_PATHS)
        message = f"Malware '{malware_name}' detected in file '{file_path}'"
        default_severity = 'critical'
    elif event_type == 'intrusion_attempt':
        technique = random.choice(['SQL injection', 'XSS', 'brute force', 'directory traversal', 'command injection'])
        message = f"Intrusion attempt ({technique}) detected from {source_ip}"
        default_severity = 'high'
    elif event_type == 'suspicious_activity':
        activity = random.choice(['unusual login time', 'repeated failed logins', 'access to sensitive files', 'network scanning'])
        user = random.choice(SAMPLE_USERNAMES)
        message = f"Suspicious activity ({activity}) detected for user '{user}' from {source_ip}"
        default_severity = 'medium'
    elif event_type == 'policy_violation':
        policy = random.choice(['password policy', 'access control policy', 'data handling policy', 'network usage policy'])
        user = random.choice(SAMPLE_USERNAMES)
        message = f"Policy violation ({policy}) by user '{user}'"
        default_severity = 'medium'
    else:
        message = f"Security event: {event_type} from {source_ip}"
        default_severity = 'medium'
    
    # Use provided severity or default based on event type
    severity = severity or default_severity
    
    # Create raw data
    raw_data = {
        'source_ip': source_ip,
        'event_type': event_type,
        'detection_engine': random.choice(['antivirus', 'IDS', 'firewall', 'EDR', 'SIEM'])
    }
    
    return Event(
        source='security',
        event_type=f"sec_{event_type}",
        message=message,
        raw_data=raw_data,
        severity=severity,
        timestamp=generate_random_timestamp()
    )


def generate_random_event(severity=None):
    """
    Generate a completely random event of any type.
    
    Args:
        severity (str): Optional severity level
        
    Returns:
        Event: Generated event
    """
    # Choose a random event category
    category = random.choice(list(COMMON_EVENT_TYPES.keys()))
    
    # Generate an event of that category
    if category == 'authentication':
        return generate_authentication_event(severity)
    elif category == 'file_access':
        return generate_file_access_event(severity)
    elif category == 'network':
        return generate_network_event(severity)
    elif category == 'system':
        return generate_system_event(severity)
    elif category == 'security':
        return generate_security_event(severity)
    else:
        logger.warning(f"Unknown event category: {category}")
        return generate_security_event(severity)


def generate_event_sequence(event_type, count, interval_seconds=1, severity=None):
    """
    Generate a sequence of similar events with timestamps separated by the specified interval.
    Useful for testing threshold-based alerts.
    
    Args:
        event_type (str): Type of event to generate ('login_failure', 'malware_detected', etc.)
        count (int): Number of events to generate
        interval_seconds (int): Time interval between events in seconds
        severity (str): Optional severity level
        
    Returns:
        list: List of generated events
    """
    events = []
    # Determine which category this event type belongs to
    category = None
    for cat, types in COMMON_EVENT_TYPES.items():
        if event_type in types:
            category = cat
            break
    
    if not category:
        logger.warning(f"Unknown event type: {event_type}")
        return events
    
    # Generate events with decreasing timestamps (newest first)
    base_time = datetime.datetime.now()
    for i in range(count):
        # Create timestamp with specified interval
        timestamp = base_time - datetime.timedelta(seconds=i * interval_seconds)
        
        # Generate the appropriate event type
        if category == 'authentication':
            event = generate_authentication_event(severity, event_type)
        elif category == 'file_access':
            event = generate_file_access_event(severity, event_type)
        elif category == 'network':
            event = generate_network_event(severity, event_type)
        elif category == 'system':
            event = generate_system_event(severity, event_type)
        elif category == 'security':
            event = generate_security_event(severity, event_type)
        
        # Override the timestamp
        event.timestamp = timestamp
        events.append(event)
    
    return events


def generate_test_dataset(count=100):
    """
    Generate a diverse test dataset with various event types.
    
    Args:
        count (int): Total number of events to generate
        
    Returns:
        list: List of generated events
    """
    events = []
    
    # Generate a mix of event types
    for _ in range(count):
        # Randomly choose severity with weighted distribution
        severity_weights = {'low': 60, 'medium': 25, 'high': 10, 'critical': 5}
        severity = random.choices(
            list(severity_weights.keys()),
            weights=list(severity_weights.values()),
            k=1
        )[0]
        
        events.append(generate_random_event(severity))
    
    # Sort events by timestamp (newest first)
    events.sort(key=lambda e: e.timestamp, reverse=True)
    
    return events


def generate_alertable_sequence():
    """
    Generate a sequence of events that should trigger alerts based on
    the default threshold analyzer rules.
    
    Returns:
        list: List of generated events
    """
    sequences = []
    
    # Generate failed login attempts (should trigger failed_login_attempts rule)
    sequences.extend(generate_event_sequence('login_failure', 6, 10, 'medium'))
    
    # Generate malware detections (should trigger a high-severity alert)
    sequences.extend(generate_event_sequence('malware_detected', 2, 30, 'critical'))
    
    # Add some random events in between
    random_events = generate_test_dataset(20)
    
    # Combine and sort all events by timestamp (newest first)
    all_events = sequences + random_events
    all_events.sort(key=lambda e: e.timestamp, reverse=True)
    
    return all_events


def inject_events_into_queue(event_queue, events):
    """
    Inject a list of events into an event queue.
    
    Args:
        event_queue: Queue to add events to
        events (list): List of events to inject
    """
    for event in events:
        event_queue.put(event)
        logger.debug(f"Injected event: {event}")


def run_test_data_generator(event_queue, duration_seconds=60, events_per_second=1):
    """
    Continuously generate random test data and inject it into the event queue.
    
    Args:
        event_queue: Queue to add events to
        duration_seconds (int): How long to run (0 for indefinitely)
        events_per_second (float): Rate of event generation
    """
    logger.info(f"Starting test data generator ({events_per_second} events/second)")
    
    start_time = time.time()
    count = 0
    
    try:
        while True:
            # Generate a random event
            event = generate_random_event()
            
            # Inject it into the queue
            event_queue.put(event)
            count += 1
            
            # Every 10 events, log a message
            if count % 10 == 0:
                logger.info(f"Generated {count} test events so far")
            
            # Sleep to maintain the desired rate
            time.sleep(1 / events_per_second)
            
            # Check if we've run for the specified duration
            if duration_seconds > 0 and time.time() - start_time >= duration_seconds:
                break
                
    except KeyboardInterrupt:
        logger.info("Test data generation stopped by user")
    except Exception as e:
        logger.error(f"Error in test data generator: {str(e)}")
    
    logger.info(f"Test data generator finished after generating {count} events")


if __name__ == "__main__":
    # This allows the module to be run directly for testing
    logging.basicConfig(level=logging.INFO)
    
    # Generate and print some sample events
    print("Authentication event example:")
    print(generate_authentication_event().to_json(pretty=True))
    
    print("\nFile access event example:")
    print(generate_file_access_event().to_json(pretty=True))
    
    print("\nNetwork event example:")
    print(generate_network_event().to_json(pretty=True))
    
    print("\nSystem event example:")
    print(generate_system_event().to_json(pretty=True))
    
    print("\nSecurity event example:")
    print(generate_security_event().to_json(pretty=True)) 