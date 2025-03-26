#!/usr/bin/env python3
"""
Main entry point for the Enterprise SIEM Platform.
This script initializes and runs all components of the SIEM platform.
"""

import argparse
import logging
import os
import sys
import threading
import yaml
import time
import queue
from pathlib import Path

# Set up the Python path to include the project directory
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Import SIEM components
# These will be implemented in their respective modules
try:
    # Collectors
    from src.collectors.windows_event_collector import WindowsEventCollector
    from src.collectors.file_collector import FileCollector
    
    # Analyzers
    from src.analyzers.threshold_analyzer import ThresholdAnalyzer
    
    # Alerters
    from src.alerting.console_alerter import ConsoleAlerter
    from src.alerting.email_alerter import EmailAlerter
    
    # Dashboard
    from src.dashboard.app import start_dashboard
    
    # Utils
    from src.utils.config_loader import load_config
    from src.utils.event import Event
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Some components may not be fully implemented yet.")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Enterprise SIEM Platform')
    
    parser.add_argument('--config', '-c', 
                        default=os.path.join(current_dir, 'config', 'config.yaml'),
                        help='Path to configuration file')
    
    parser.add_argument('--log-level', '-l',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        default='INFO',
                        help='Set the logging level')
    
    parser.add_argument('--no-dashboard', '-nd',
                        action='store_true',
                        help='Disable the web dashboard')
    
    parser.add_argument('--console-only', '-co',
                        action='store_true',
                        help='Output alerts to console only, ignore other alerters')
    
    return parser.parse_args()

def setup_logging(log_level, log_file=None):
    """Configure logging for the application."""
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')
    
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        handlers=[
            logging.StreamHandler()  # Console handler
        ]
    )
    
    # Add file handler if log file is specified
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(file_handler)
    
    return logging.getLogger('siem')

def ensure_directories(config):
    """Ensure required directories exist."""
    dirs = [
        config['general']['data_dir'],
        config['general']['temp_dir'],
        os.path.dirname(config['general']['log_file'])
    ]
    
    for d in dirs:
        os.makedirs(d, exist_ok=True)

def load_collectors(config, event_queue):
    """Initialize and return collector objects based on configuration."""
    collectors = []
    
    # Windows Event Collector
    if config['collectors'].get('windows_event', {}).get('enable', False):
        try:
            win_config = config['collectors']['windows_event']
            win_collector = WindowsEventCollector(
                event_queue=event_queue,
                channels=win_config.get('channels', []),
                interval=win_config.get('interval', 30)
            )
            collectors.append(win_collector)
            logging.info("Windows Event Collector initialized")
        except Exception as e:
            logging.error(f"Failed to initialize Windows Event Collector: {e}")
    
    # File Collector
    if config['collectors'].get('file', {}).get('enable', False):
        try:
            file_config = config['collectors']['file']
            file_collector = FileCollector(
                event_queue=event_queue,
                files=file_config.get('files', []),
                interval=file_config.get('interval', 60)
            )
            collectors.append(file_collector)
            logging.info("File Collector initialized")
        except Exception as e:
            logging.error(f"Failed to initialize File Collector: {e}")
    
    return collectors

def load_analyzers(config, event_queue, alert_queue):
    """Initialize and return analyzer objects based on configuration."""
    analyzers = []
    
    # Threshold Analyzer
    if config['analyzers'].get('threshold', {}).get('enable', False):
        try:
            threshold_config = config['analyzers']['threshold']
            threshold_analyzer = ThresholdAnalyzer(
                event_queue=event_queue,
                alert_queue=alert_queue,
                rules=threshold_config.get('rules', [])
            )
            analyzers.append(threshold_analyzer)
            logging.info("Threshold Analyzer initialized")
        except Exception as e:
            logging.error(f"Failed to initialize Threshold Analyzer: {e}")
    
    return analyzers

def load_alerters(config, alert_queue, console_only=False):
    """Initialize and return alerter objects based on configuration."""
    alerters = []
    
    # Console Alerter (always included)
    try:
        console_config = config['alerters'].get('console', {})
        console_alerter = ConsoleAlerter(
            alert_queue=alert_queue,
            format=console_config.get('format', "{timestamp} [{severity}] {message}")
        )
        alerters.append(console_alerter)
        logging.info("Console Alerter initialized")
    except Exception as e:
        logging.error(f"Failed to initialize Console Alerter: {e}")
    
    # Skip other alerters if console_only is True
    if console_only:
        return alerters
    
    # Email Alerter
    if config['alerters'].get('email', {}).get('enable', False):
        try:
            email_config = config['alerters']['email']
            email_alerter = EmailAlerter(
                alert_queue=alert_queue,
                server=email_config.get('server'),
                port=email_config.get('port', 587),
                use_tls=email_config.get('use_tls', True),
                username=email_config.get('username'),
                password=email_config.get('password'),
                from_address=email_config.get('from_address'),
                to_addresses=email_config.get('to_addresses', []),
                subject_prefix=email_config.get('subject_prefix', "[SIEM ALERT]"),
                include_raw_data=email_config.get('include_raw_data', False)
            )
            alerters.append(email_alerter)
            logging.info("Email Alerter initialized")
        except Exception as e:
            logging.error(f"Failed to initialize Email Alerter: {e}")
    
    return alerters

def main():
    """Main function to run the SIEM platform."""
    # Parse command line arguments
    args = parse_arguments()
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Set up logging
        logger = setup_logging(
            args.log_level or config['general'].get('log_level', 'INFO'),
            config['general'].get('log_file')
        )
        
        # Ensure required directories exist
        ensure_directories(config)
        
        logger.info("Starting Enterprise SIEM Platform")
        
        # Create event and alert queues
        event_queue = queue.Queue()
        alert_queue = queue.Queue()
        
        # Initialize components
        collectors = load_collectors(config, event_queue)
        analyzers = load_analyzers(config, event_queue, alert_queue)
        alerters = load_alerters(config, alert_queue, args.console_only)
        
        # Start all components in separate threads
        threads = []
        
        # Start collectors
        for collector in collectors:
            thread = threading.Thread(target=collector.start, daemon=True)
            thread.start()
            threads.append(thread)
            logger.info(f"Started {collector.__class__.__name__}")
        
        # Start analyzers
        for analyzer in analyzers:
            thread = threading.Thread(target=analyzer.start, daemon=True)
            thread.start()
            threads.append(thread)
            logger.info(f"Started {analyzer.__class__.__name__}")
        
        # Start alerters
        for alerter in alerters:
            thread = threading.Thread(target=alerter.start, daemon=True)
            thread.start()
            threads.append(thread)
            logger.info(f"Started {alerter.__class__.__name__}")
        
        # Start dashboard if enabled
        dashboard_thread = None
        if config['dashboard'].get('enable', True) and not args.no_dashboard:
            dashboard_host = config['dashboard'].get('host', '127.0.0.1')
            dashboard_port = config['dashboard'].get('port', 5000)
            
            dashboard_thread = threading.Thread(
                target=start_dashboard,
                args=(dashboard_host, dashboard_port, event_queue, alert_queue),
                daemon=True
            )
            dashboard_thread.start()
            threads.append(dashboard_thread)
            logger.info(f"Started Dashboard on http://{dashboard_host}:{dashboard_port}")
        
        # Keep the main thread running
        try:
            while True:
                # Monitor threads
                for i, thread in enumerate(threads):
                    if not thread.is_alive():
                        logger.warning(f"Thread {i} has died. Restarting...")
                        if i < len(collectors):
                            new_thread = threading.Thread(target=collectors[i].start, daemon=True)
                        elif i < len(collectors) + len(analyzers):
                            analyzer_idx = i - len(collectors)
                            new_thread = threading.Thread(target=analyzers[analyzer_idx].start, daemon=True)
                        elif i < len(collectors) + len(analyzers) + len(alerters):
                            alerter_idx = i - len(collectors) - len(analyzers)
                            new_thread = threading.Thread(target=alerters[alerter_idx].start, daemon=True)
                        else:
                            # Dashboard thread
                            new_thread = threading.Thread(
                                target=start_dashboard,
                                args=(dashboard_host, dashboard_port, event_queue, alert_queue),
                                daemon=True
                            )
                        
                        new_thread.start()
                        threads[i] = new_thread
                
                time.sleep(5)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received. Shutting down...")
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
        finally:
            # Cleanup code could be added here
            logger.info("SIEM Platform shutting down")
    
    except Exception as e:
        print(f"Fatal error: {e}")
        if logger:
            logger.critical(f"Fatal error: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 