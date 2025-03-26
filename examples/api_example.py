#!/usr/bin/env python3
"""
API Example for Enterprise SIEM Platform.

This script demonstrates how to use the SIEM platform's components programmatically.
It shows how to create custom events, analyze them, and handle alerts.
"""
import os
import sys
import logging
import datetime
import queue
import time

# Add the parent directory to the path so we can import from src
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.event import Event
from src.analyzers.threshold_analyzer import ThresholdAnalyzer
from src.alerting.console_alerter import ConsoleAlerter

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def create_custom_event(source, event_type, message, severity='low'):
    """
    Create a custom event.
    
    Args:
        source (str): Source of the event
        event_type (str): Type of the event
        message (str): Event message
        severity (str): Event severity (low, medium, high, critical)
        
    Returns:
        Event: The created event
    """
    # Create the event
    event = Event(
        source=source,
        event_type=event_type,
        message=message,
        raw_data={'custom': True},
        severity=severity,
        timestamp=datetime.datetime.now()
    )
    
    logger.info(f"Created custom event: {event}")
    return event

def create_custom_analyzer():
    """
    Create a custom analyzer with specific rules.
    
    Returns:
        ThresholdAnalyzer: The configured analyzer
    """
    # Define analyzer configuration
    config = {
        'rules': [
            {
                'name': 'custom_rule',
                'description': 'Detect custom events',
                'source': 'custom',
                'event_type': 'custom_event',
                'threshold': 3,
                'timeframe': 60,
                'severity': 'medium'
            },
            {
                'name': 'critical_events',
                'description': 'Detect any critical events',
                'severity': 'critical',
                'threshold': 1,
                'timeframe': 300
            }
        ]
    }
    
    # Create the analyzer
    analyzer = ThresholdAnalyzer(config)
    logger.info("Created custom analyzer with 2 rules")
    
    return analyzer

def demo_event_analysis():
    """
    Demonstrate event analysis and alerting.
    """
    logger.info("Starting event analysis demonstration")
    
    # Create queues
    event_queue = queue.Queue()
    alert_queue = queue.Queue()
    
    # Create analyzer and alerter
    analyzer = create_custom_analyzer()
    alerter = ConsoleAlerter({'colors': True})
    
    # Start the alerter in a separate thread
    import threading
    alerter_thread = threading.Thread(
        target=alerter.run_alerter,
        args=(alert_queue,),
        daemon=True
    )
    alerter_thread.start()
    
    # Create and analyze some events
    for i in range(5):
        # Create a custom event
        event = create_custom_event(
            source='custom',
            event_type='custom_event',
            message=f"Custom event #{i+1}",
            severity='medium' if i < 4 else 'critical'
        )
        
        # Add to the event queue
        event_queue.put(event)
        
        # Manually analyze the event (normally done by the analyzer thread)
        alerts = analyzer.analyze_event(event)
        
        # If any alerts were generated, add them to the alert queue
        for alert in alerts:
            logger.info(f"Alert generated: {alert.message}")
            alert_queue.put(alert)
        
        # Sleep a bit to space out the events
        time.sleep(1)
    
    # Sleep to allow the alerter to process any pending alerts
    logger.info("Waiting for alerts to be processed...")
    time.sleep(3)
    
    logger.info("Event analysis demonstration completed")

def read_events_from_file(file_path):
    """
    Read events from a JSON file.
    
    Args:
        file_path (str): Path to the JSON file
        
    Returns:
        list: List of Event objects
    """
    import json
    events = []
    
    try:
        with open(file_path, 'r') as f:
            event_data = json.load(f)
            
            # Convert each JSON object to an Event
            for data in event_data:
                event = Event.from_dict(data)
                events.append(event)
                
        logger.info(f"Read {len(events)} events from {file_path}")
        return events
    except Exception as e:
        logger.error(f"Error reading events from {file_path}: {str(e)}")
        return []

def write_events_to_file(events, file_path):
    """
    Write events to a JSON file.
    
    Args:
        events (list): List of Event objects
        file_path (str): Path to the JSON file
    """
    import json
    
    try:
        # Convert events to dictionaries
        event_data = [event.to_dict() for event in events]
        
        with open(file_path, 'w') as f:
            json.dump(event_data, f, indent=2)
            
        logger.info(f"Wrote {len(events)} events to {file_path}")
    except Exception as e:
        logger.error(f"Error writing events to {file_path}: {str(e)}")

def demo_event_export_import():
    """
    Demonstrate exporting and importing events.
    """
    logger.info("Starting event export/import demonstration")
    
    # Create some events
    events = []
    for i in range(3):
        event = create_custom_event(
            source='export_demo',
            event_type='test_event',
            message=f"Export demo event #{i+1}",
            severity='low'
        )
        events.append(event)
    
    # Export to a file
    export_file = 'example_events.json'
    write_events_to_file(events, export_file)
    
    # Import from the file
    imported_events = read_events_from_file(export_file)
    
    # Verify the import
    if len(imported_events) == len(events):
        logger.info("Export/import successful - count matches")
    else:
        logger.warning("Export/import count mismatch")
    
    # Clean up
    try:
        os.remove(export_file)
        logger.info(f"Cleaned up {export_file}")
    except:
        pass
    
    logger.info("Event export/import demonstration completed")

def main():
    """
    Main entry point for the example script.
    """
    logger.info("Starting SIEM API Example")
    
    # Demonstrate event analysis
    demo_event_analysis()
    
    # Demonstrate event export/import
    demo_event_export_import()
    
    logger.info("SIEM API Example completed")
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 