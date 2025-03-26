"""
Threshold Analyzer for Enterprise SIEM Platform.
"""
import logging
import time
import re
import datetime
from collections import defaultdict

from src.utils.event import Event

class ThresholdAnalyzer:
    """
    Analyzes events based on thresholds to detect potential security incidents.
    """
    
    def __init__(self, config):
        """
        Initialize the Threshold Analyzer.
        
        Args:
            config (dict): Configuration for the analyzer
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.rules = config.get('rules', [])
        self.event_buffers = {}  # Keep track of events for each rule
    
    def init_rule_buffer(self, rule_name):
        """
        Initialize a buffer for a rule.
        
        Args:
            rule_name (str): Name of the rule
            
        Returns:
            dict: Rule buffer
        """
        buffer = {
            'events': [],
            'last_alert': None
        }
        self.event_buffers[rule_name] = buffer
        return buffer
    
    def cleanup_old_events(self):
        """
        Remove events that are outside the timeframe for each rule.
        """
        current_time = datetime.datetime.now()
        
        for rule in self.rules:
            rule_name = rule.get('name')
            if rule_name not in self.event_buffers:
                continue
                
            timeframe = rule.get('timeframe', 300)  # Default 5 minutes
            buffer = self.event_buffers[rule_name]
            
            # Filter events to keep only those within the timeframe
            buffer['events'] = [
                event for event in buffer['events']
                if (current_time - event.timestamp).total_seconds() <= timeframe
            ]
    
    def match_event(self, event, rule):
        """
        Check if an event matches a rule.
        
        Args:
            event (Event): The event to check
            rule (dict): The rule to match against
            
        Returns:
            bool: True if the event matches the rule, False otherwise
        """
        # Check source
        if 'source' in rule and event.source != rule['source']:
            return False
        
        # Check event type
        if 'event_type' in rule and event.event_type != rule['event_type']:
            return False
        
        # Check pattern in message
        if 'pattern' in rule:
            pattern = rule['pattern']
            message = event.message
            
            # Convert Windows Event ID to string for comparison
            if 'raw_data' in event.raw_data and 'event_id' in event.raw_data:
                event_id = str(event.raw_data['event_id'])
                if pattern == event_id:
                    return True
            
            # Check pattern in message
            if re.search(pattern, message, re.IGNORECASE):
                return True
            
            # No match
            return False
        
        # No pattern specified, but other criteria matched
        return True
    
    def analyze_event(self, event):
        """
        Analyze a single event against all rules.
        
        Args:
            event (Event): The event to analyze
            
        Returns:
            list: List of alert Events if thresholds are exceeded
        """
        alerts = []
        
        for rule in self.rules:
            rule_name = rule.get('name')
            
            # Skip disabled rules
            if not rule.get('enabled', True):
                continue
            
            # Get or create the buffer for this rule
            if rule_name not in self.event_buffers:
                buffer = self.init_rule_buffer(rule_name)
            else:
                buffer = self.event_buffers[rule_name]
            
            # Check if the event matches the rule
            if self.match_event(event, rule):
                # Add the event to the buffer
                buffer['events'].append(event)
                
                # Get rule parameters
                threshold = rule.get('threshold', 5)
                timeframe = rule.get('timeframe', 300)  # seconds
                severity = rule.get('severity', 'medium')
                
                # Count events in the buffer
                event_count = len(buffer['events'])
                
                # Check if we've exceeded the threshold
                if event_count >= threshold:
                    # Check if we've already alerted recently
                    last_alert = buffer.get('last_alert')
                    current_time = datetime.datetime.now()
                    
                    if last_alert is None or (current_time - last_alert).total_seconds() > timeframe:
                        # Create an alert
                        description = rule.get('description', f"Rule {rule_name} triggered")
                        alert_message = f"{description}: {event_count} events in the last {timeframe} seconds"
                        
                        alert = Event(
                            source='threshold_analyzer',
                            event_type='threshold_alert',
                            message=alert_message,
                            raw_data={
                                'rule_name': rule_name,
                                'description': description,
                                'threshold': threshold,
                                'timeframe': timeframe,
                                'event_count': event_count,
                                'matched_events': [e.to_dict() for e in buffer['events'][-5:]]  # Last 5 events
                            },
                            severity=severity
                        )
                        
                        # Add the alert
                        alerts.append(alert)
                        
                        # Update the last alert time
                        buffer['last_alert'] = current_time
                        
                        self.logger.warning(f"Alert triggered: {alert_message}")
        
        return alerts
    
    def run_analyzer(self, event_queue, alert_queue):
        """
        Run the analyzer continuously, processing events from the queue.
        
        Args:
            event_queue: Queue to get events from
            alert_queue: Queue to put alerts in
        """
        self.logger.info("Starting Threshold Analyzer")
        
        while True:
            try:
                # Cleanup old events
                self.cleanup_old_events()
                
                # Get an event from the queue (if available)
                if not event_queue.empty():
                    event = event_queue.get()
                    
                    # Analyze the event
                    alerts = self.analyze_event(event)
                    
                    # Add alerts to the queue
                    for alert in alerts:
                        alert_queue.put(alert)
                
                # Sleep briefly
                time.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Error in Threshold Analyzer: {str(e)}")
                time.sleep(1)  # Sleep briefly before retrying 