#!/usr/bin/env python3
"""
Test Script for Enterprise SIEM Platform.

This script runs the SIEM platform with test data generation for development
and testing purposes. It simulates various security events to verify the
functionality of all components of the SIEM platform.
"""
import argparse
import logging
import os
import sys
import threading
import time
import queue

# Add the parent directory to the path so we can import from src
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.config_loader import load_config, setup_logging, ensure_directories
from src.utils.test_data_generator import (
    run_test_data_generator,
    generate_alertable_sequence,
    inject_events_into_queue
)
from src.collectors.windows_event_collector import WindowsEventCollector
from src.collectors.file_collector import FileCollector
from src.analyzers.threshold_analyzer import ThresholdAnalyzer
from src.alerting.console_alerter import ConsoleAlerter
from src.alerting.email_alerter import EmailAlerter
from src.dashboard.app import start_dashboard

def parse_arguments():
    """Parse command line arguments for the test script."""
    parser = argparse.ArgumentParser(description='Test Enterprise SIEM Platform')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--no-dashboard', action='store_true', help='Disable the web dashboard')
    parser.add_argument('--test-mode', choices=['random', 'alertable', 'both'], default='both',
                        help='Test data generation mode (random, alertable, or both)')
    parser.add_argument('--rate', type=float, default=0.5,
                        help='Events per second for random generation')
    parser.add_argument('--duration', type=int, default=300,
                        help='Duration in seconds to run the test (0 for indefinite)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO',
                        help='Logging level')
    return parser.parse_args()

def main():
    """Main entry point for the test script."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Set up logging
    logging_level = getattr(logging, args.log_level)
    logging.basicConfig(
        level=logging_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger(__name__)
    
    # Load configuration
    config = load_config(args.config)
    
    # Ensure required directories exist
    ensure_directories(config)
    
    logger.info("Starting Enterprise SIEM Platform in test mode")
    logger.info(f"Test mode: {args.test_mode}")
    logger.info(f"Event rate: {args.rate} per second")
    logger.info(f"Duration: {args.duration} seconds (0 = indefinite)")
    
    # Create event queues
    event_queue = queue.Queue()  # Queue for collected events
    alert_queue = queue.Queue()  # Queue for alerts
    
    # Initialize analyzers
    analyzers = []
    
    # Threshold Analyzer
    logger.info("Initializing Threshold Analyzer")
    threshold_analyzer = ThresholdAnalyzer(config.get('analyzers', {}).get('threshold', {}))
    analyzers.append(('Threshold Analyzer', threshold_analyzer, threshold_analyzer.run_analyzer))
    
    # Initialize alerters
    alerters = []
    
    # Console Alerter
    logger.info("Initializing Console Alerter")
    console_alerter = ConsoleAlerter(config.get('alerting', {}).get('console', {}))
    alerters.append(('Console Alerter', console_alerter, console_alerter.run_alerter))
    
    # Email Alerter (if enabled)
    if config.get('alerting', {}).get('email', {}).get('enabled', False):
        logger.info("Initializing Email Alerter")
        email_alerter = EmailAlerter(config.get('alerting', {}).get('email', {}))
        alerters.append(('Email Alerter', email_alerter, email_alerter.run_alerter))
    
    # Start all components in separate threads
    threads = []
    
    # Start analyzers
    for name, analyzer, run_func in analyzers:
        logger.info(f"Starting {name}")
        thread = threading.Thread(target=run_func, args=(event_queue, alert_queue), daemon=True)
        thread.start()
        threads.append((name, thread))
    
    # Start alerters
    for name, alerter, run_func in alerters:
        logger.info(f"Starting {name}")
        thread = threading.Thread(target=run_func, args=(alert_queue,), daemon=True)
        thread.start()
        threads.append((name, thread))
    
    # Start dashboard (if enabled)
    if not args.no_dashboard:
        dashboard_config = config.get('dashboard', {})
        dashboard_host = dashboard_config.get('host', '127.0.0.1')
        dashboard_port = dashboard_config.get('port', 5000)
        
        logger.info(f"Starting Dashboard on http://{dashboard_host}:{dashboard_port}")
        
        # Start dashboard in a separate thread
        dashboard_thread = threading.Thread(
            target=start_dashboard,
            args=(dashboard_host, dashboard_port, event_queue, alert_queue),
            daemon=True
        )
        dashboard_thread.start()
        threads.append(('Dashboard', dashboard_thread))
    
    # Generate and inject test data
    try:
        # If alertable or both, inject a sequence of events that should trigger alerts
        if args.test_mode in ['alertable', 'both']:
            logger.info("Generating alertable event sequence")
            alertable_events = generate_alertable_sequence()
            logger.info(f"Injecting {len(alertable_events)} alertable events")
            inject_events_into_queue(event_queue, alertable_events)
            
            # Give the system some time to process these events
            time.sleep(5)
        
        # If random or both, continuously generate random events
        if args.test_mode in ['random', 'both']:
            logger.info(f"Starting random event generator ({args.rate} events/sec for {args.duration} seconds)")
            run_test_data_generator(event_queue, args.duration, args.rate)
        elif args.duration > 0:
            # If we're not generating random events but have a duration, just wait
            logger.info(f"Waiting for {args.duration} seconds")
            time.sleep(args.duration)
        
        # After the data generation finishes, keep the system running if dashboard is enabled
        if not args.no_dashboard and args.duration > 0:
            logger.info("Test data generation complete. Dashboard is still running.")
            logger.info(f"Visit http://{dashboard_host}:{dashboard_port} to view the results.")
            logger.info("Press Ctrl+C to exit.")
            
            while True:
                # Check if all threads are still running
                for name, thread in threads:
                    if not thread.is_alive():
                        logger.error(f"{name} thread has died. Exiting...")
                        return 1
                
                time.sleep(1)
        
    except KeyboardInterrupt:
        logger.info("Test stopped by user (Ctrl+C pressed)")
    except Exception as e:
        logger.error(f"Error in test: {str(e)}", exc_info=True)
        return 1
    
    logger.info("Test completed successfully")
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 