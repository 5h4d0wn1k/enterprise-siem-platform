#!/usr/bin/env python3
"""
Custom Collector Example for Enterprise SIEM Platform.

This example demonstrates how to create a custom collector that integrates with 
a third-party API (in this case, a simulated threat intelligence API).
"""
import os
import sys
import logging
import time
import datetime
import json
import random
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Add the parent directory to the path so we can import from src
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.collectors.base_collector import BaseCollector
from src.utils.event import Event

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class ThreatIntelCollector(BaseCollector):
    """
    A collector that gathers threat intelligence from a third-party API.
    
    This example demonstrates how to:
    1. Connect to an external API
    2. Parse the response
    3. Create appropriate security events
    4. Handle errors and retries
    """
    
    def __init__(self, config):
        """
        Initialize the ThreatIntelCollector.
        
        Args:
            config (dict): Configuration dictionary with the following keys:
                - api_key: API key for the threat intelligence service
                - api_url: URL of the API endpoint
                - interval: Time between API calls in seconds
                - max_retries: Maximum number of retries on API failure
                - retry_delay: Delay between retries in seconds
        """
        super().__init__(config)
        self.name = "threat_intel_collector"
        self.logger = logging.getLogger(__name__)
        
        # Extract configuration
        self.api_key = config.get('api_key', 'demo_key')
        self.api_url = config.get('api_url', 'https://api.example.com/threats')
        self.interval = config.get('interval', 300)  # Default: check every 5 minutes
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 10)
        
        # Track the last time we checked for threats
        self.last_check_time = None
        
        self.logger.info(f"Initialized {self.name} with API endpoint: {self.api_url}")
    
    def _make_api_request(self):
        """
        Make a request to the threat intelligence API.
        
        Returns:
            dict: The parsed JSON response or None if the request failed
        """
        query_params = ""
        if self.last_check_time:
            # Only get threats since our last check
            query_params = f"?since={self.last_check_time.isoformat()}"
        
        url = f"{self.api_url}{query_params}"
        
        # Create request with headers
        request = Request(
            url,
            headers={
                'X-API-Key': self.api_key,
                'Accept': 'application/json',
                'User-Agent': f'Enterprise-SIEM-Platform/{self.name}'
            }
        )
        
        retries = 0
        while retries <= self.max_retries:
            try:
                self.logger.debug(f"Making API request to: {url}")
                with urlopen(request, timeout=30) as response:
                    # Update the last check time
                    self.last_check_time = datetime.datetime.now()
                    
                    # Parse the JSON response
                    response_data = json.loads(response.read().decode('utf-8'))
                    self.logger.debug(f"Received response with {len(response_data.get('threats', []))} threats")
                    return response_data
                    
            except HTTPError as e:
                self.logger.error(f"HTTP error: {e.code} - {e.reason}")
                if e.code == 429:  # Too Many Requests
                    # Exponential backoff
                    sleep_time = self.retry_delay * (2 ** retries)
                    self.logger.warning(f"Rate limited. Retrying in {sleep_time}s")
                    time.sleep(sleep_time)
                    retries += 1
                    continue
                elif e.code == 401:  # Unauthorized
                    self.logger.error("API key is invalid or expired")
                    return None
                elif e.code >= 500:  # Server errors
                    if retries < self.max_retries:
                        time.sleep(self.retry_delay)
                        retries += 1
                        continue
                    return None
                else:
                    return None
                    
            except URLError as e:
                self.logger.error(f"URL error: {str(e)}")
                if retries < self.max_retries:
                    time.sleep(self.retry_delay)
                    retries += 1
                    continue
                return None
                
            except Exception as e:
                self.logger.error(f"Error making API request: {str(e)}")
                if retries < self.max_retries:
                    time.sleep(self.retry_delay)
                    retries += 1
                    continue
                return None
        
        self.logger.error(f"Failed to get data after {self.max_retries} retries")
        return None
    
    def collect_events(self, event_queue):
        """
        Collect events from the threat intelligence API.
        
        Args:
            event_queue (Queue): Queue to place collected events
        """
        self.logger.info("Collecting events from threat intelligence API")
        
        try:
            # For demo purposes, we'll simulate the API response instead of making a real request
            if os.environ.get('DEMO_MODE', 'true').lower() == 'true':
                response_data = self._simulate_api_response()
            else:
                response_data = self._make_api_request()
            
            if not response_data:
                self.logger.warning("No data received from API")
                return
            
            # Process the threats
            threats = response_data.get('threats', [])
            self.logger.info(f"Processing {len(threats)} threats")
            
            for threat in threats:
                # Create an event for each threat
                severity = threat.get('severity', 'medium').lower()
                
                event = Event(
                    source="threat_intelligence",
                    event_type=threat.get('type', 'unknown'),
                    message=threat.get('description', 'Unknown threat detected'),
                    severity=severity,
                    raw_data=threat,
                    timestamp=datetime.datetime.now()
                )
                
                # Add to queue
                event_queue.put(event)
                self.logger.debug(f"Added threat event to queue: {event.message}")
            
        except Exception as e:
            self.logger.error(f"Error collecting threat intelligence: {str(e)}")
    
    def _simulate_api_response(self):
        """
        Simulate a response from the threat intelligence API for demonstration purposes.
        
        Returns:
            dict: A simulated API response with random threats
        """
        self.logger.debug("Simulating API response")
        
        # Types of threats we might detect
        threat_types = [
            "malware", "phishing", "ransomware", "data_exfiltration", 
            "brute_force", "ddos", "insider_threat", "zero_day_exploit"
        ]
        
        # Severity levels
        severity_levels = ["low", "medium", "high", "critical"]
        
        # Generate random number of threats (0-5)
        num_threats = random.randint(0, 5)
        
        threats = []
        for i in range(num_threats):
            threat_type = random.choice(threat_types)
            severity = random.choice(severity_levels)
            
            # Generate appropriate description based on threat type
            descriptions = {
                "malware": [
                    "Malware signature detected in network traffic",
                    "Potential malware download detected",
                    "Malicious executable identified on host",
                ],
                "phishing": [
                    "Phishing URL accessed by internal user",
                    "Suspicious email link clicked",
                    "Known phishing domain contacted",
                ],
                "ransomware": [
                    "Potential ransomware activity detected",
                    "File encryption behavior observed",
                    "Known ransomware command and control contacted",
                ],
                "data_exfiltration": [
                    "Unusual data transfer to external IP",
                    "Large file upload to untrusted domain",
                    "Potential data exfiltration via DNS",
                ],
                "brute_force": [
                    "Multiple authentication failures detected",
                    "Password spray attack identified",
                    "SSH brute force attempt",
                ],
                "ddos": [
                    "Potential DDoS traffic detected",
                    "Abnormal network traffic pattern identified",
                    "DDoS attack signature matched",
                ],
                "insider_threat": [
                    "Unusual access pattern by privileged user",
                    "Sensitive file access outside normal hours",
                    "Data access from unusual location",
                ],
                "zero_day_exploit": [
                    "Unknown exploit pattern detected",
                    "Suspicious memory manipulation observed",
                    "Possible zero-day vulnerability exploitation",
                ]
            }
            
            description = random.choice(descriptions[threat_type])
            
            # Generate random IP or domain as the indicator
            indicator_type = random.choice(["ip", "domain"])
            if indicator_type == "ip":
                octets = [str(random.randint(1, 254)) for _ in range(4)]
                indicator = ".".join(octets)
            else:
                domains = ["malicious-site.com", "evil-domain.net", "fake-bank.com", 
                           "malware-host.org", "suspicious-site.io"]
                indicator = random.choice(domains)
            
            # Create the threat object
            threat = {
                "id": f"THREAT-{random.randint(10000, 99999)}",
                "type": threat_type,
                "severity": severity,
                "description": description,
                "indicator": indicator,
                "indicator_type": indicator_type,
                "confidence": random.randint(50, 100),
                "first_seen": (datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 30))).isoformat(),
                "last_seen": datetime.datetime.now().isoformat(),
                "references": []
            }
            
            threats.append(threat)
        
        # Simulate API response
        return {
            "status": "success",
            "timestamp": datetime.datetime.now().isoformat(),
            "threats": threats
        }

def run_collector_demo():
    """
    Run a demonstration of the ThreatIntelCollector.
    """
    # Create a queue to hold events
    import queue
    event_queue = queue.Queue()
    
    # Configure the collector
    config = {
        'api_key': 'demo_key',
        'api_url': 'https://api.example.com/threats',
        'interval': 10,  # Short interval for demo purposes
        'max_retries': 3,
        'retry_delay': 2
    }
    
    # Create the collector
    collector = ThreatIntelCollector(config)
    
    # Run the collector a few times
    print("Running ThreatIntelCollector demo...")
    print("This will simulate 3 API calls to a threat intelligence service")
    print("Press Ctrl+C to stop")
    
    try:
        for i in range(3):
            print(f"\nAPI call {i+1}:")
            
            # Collect events
            collector.collect_events(event_queue)
            
            # Process events from the queue
            print(f"Collected {event_queue.qsize()} events")
            
            while not event_queue.empty():
                event = event_queue.get()
                print(f"  - [{event.severity.upper()}] {event.message}")
                
                # Print more details for the first event if any
                if i == 0 and event_queue.qsize() == 0:
                    print("\nExample event details:")
                    print(f"  Source: {event.source}")
                    print(f"  Type: {event.event_type}")
                    print(f"  Timestamp: {event.timestamp}")
                    print(f"  Raw data: {json.dumps(event.raw_data, indent=2)}")
            
            # Wait before the next collection
            if i < 2:  # Don't sleep after the last iteration
                print(f"\nWaiting {collector.interval} seconds before next collection...")
                time.sleep(collector.interval)
    
    except KeyboardInterrupt:
        print("\nDemo stopped by user")
    
    print("\nThreatIntelCollector demo complete!")

def main():
    """
    Main entry point for the example script.
    """
    run_collector_demo()
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 