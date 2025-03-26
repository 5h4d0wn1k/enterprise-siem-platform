"""
Enterprise SIEM Platform - Main Application

This is the main entry point for the SIEM platform. It initializes all components
and runs the main event loop.
"""
import os
import logging
import threading
import queue
import time
import argparse

from src.utils.config_loader import load_config, setup_logging, ensure_directories
from src.collectors.windows_event_collector import WindowsEventCollector
from src.collectors.file_collector import FileCollector
from src.analyzers.threshold_analyzer import ThresholdAnalyzer
from src.alerting.console_alerter import ConsoleAlerter
from src.alerting.email_alerter import EmailAlerter
from src.dashboard.app import start_dashboard

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Enterprise SIEM Platform')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--no-dashboard', action='store_true', help='Disable the web dashboard')
    return parser.parse_args()

def main():
    """Main entry point for the application."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Load configuration
    config = load_config(args.config)
    
    # Set up logging
    setup_logging(config)
    
    # Ensure required directories exist
    ensure_directories(config)
    
    # Create event queues
    event_queue = queue.Queue()  # Queue for collected events
    alert_queue = queue.Queue()  # Queue for alerts
    
    # Initialize collectors
    collectors = []
    
    # Windows Event Collector
    if config.get('collectors', {}).get('system', {}).get('enabled', False):
        logging.info("Initializing Windows Event Collector")
        windows_collector = WindowsEventCollector(config.get('collectors', {}).get('system', {}))
        collectors.append(('Windows Event Collector', windows_collector, windows_collector.run_collector))
    
    # File Collector
    if config.get('collectors', {}).get('file', {}).get('enabled', False):
        logging.info("Initializing File Collector")
        file_collector = FileCollector(config.get('collectors', {}).get('file', {}))
        collectors.append(('File Collector', file_collector, file_collector.run_collector))
    
    # Initialize analyzers
    analyzers = []
    
    # Threshold Analyzer
    if config.get('analyzers', {}).get('threshold', {}).get('enabled', False):
        logging.info("Initializing Threshold Analyzer")
        threshold_analyzer = ThresholdAnalyzer(config.get('analyzers', {}).get('threshold', {}))
        analyzers.append(('Threshold Analyzer', threshold_analyzer, threshold_analyzer.run_analyzer))
    
    # Initialize alerters
    alerters = []
    
    # Console Alerter
    if config.get('alerting', {}).get('console', {}).get('enabled', True):
        logging.info("Initializing Console Alerter")
        console_alerter = ConsoleAlerter(config.get('alerting', {}).get('console', {}))
        alerters.append(('Console Alerter', console_alerter, console_alerter.run_alerter))
    
    # Email Alerter
    if config.get('alerting', {}).get('email', {}).get('enabled', False):
        logging.info("Initializing Email Alerter")
        email_alerter = EmailAlerter(config.get('alerting', {}).get('email', {}))
        alerters.append(('Email Alerter', email_alerter, email_alerter.run_alerter))
    
    # Start all components in separate threads
    threads = []
    
    # Start collectors
    for name, collector, run_func in collectors:
        logging.info(f"Starting {name}")
        thread = threading.Thread(target=run_func, args=(event_queue,), daemon=True)
        thread.start()
        threads.append((name, thread))
    
    # Start analyzers
    for name, analyzer, run_func in analyzers:
        logging.info(f"Starting {name}")
        thread = threading.Thread(target=run_func, args=(event_queue, alert_queue), daemon=True)
        thread.start()
        threads.append((name, thread))
    
    # Start alerters
    for name, alerter, run_func in alerters:
        logging.info(f"Starting {name}")
        thread = threading.Thread(target=run_func, args=(alert_queue,), daemon=True)
        thread.start()
        threads.append((name, thread))
    
    # Start dashboard (if enabled)
    if not args.no_dashboard and config.get('dashboard', {}).get('enabled', True):
        dashboard_config = config.get('dashboard', {})
        dashboard_host = dashboard_config.get('host', '127.0.0.1')
        dashboard_port = dashboard_config.get('port', 5000)
        
        logging.info(f"Starting Dashboard on http://{dashboard_host}:{dashboard_port}")
        
        # Start dashboard in a separate thread
        dashboard_thread = threading.Thread(
            target=start_dashboard,
            args=(dashboard_host, dashboard_port, event_queue, alert_queue),
            daemon=True
        )
        dashboard_thread.start()
        threads.append(('Dashboard', dashboard_thread))
    
    # Main loop - keep the application running and monitor threads
    try:
        logging.info("Enterprise SIEM Platform started successfully")
        
        while True:
            # Check if all threads are still running
            for name, thread in threads:
                if not thread.is_alive():
                    logging.error(f"{name} thread has died. Exiting...")
                    return 1
            
            # Sleep to avoid high CPU usage
            time.sleep(1)
            
    except KeyboardInterrupt:
        logging.info("Enterprise SIEM Platform shutting down (Ctrl+C pressed)")
        return 0
    except Exception as e:
        logging.error(f"Unhandled exception in main loop: {str(e)}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code) 