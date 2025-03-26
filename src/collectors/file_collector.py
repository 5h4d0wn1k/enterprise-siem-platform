"""
File Log Collector for Enterprise SIEM Platform.
"""
import os
import time
import logging
import datetime
import re
import glob
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src.utils.event import Event

class LogFileHandler(FileSystemEventHandler):
    """
    Handler for log file events.
    """
    
    def __init__(self, collector):
        """
        Initialize the log file handler.
        
        Args:
            collector (FileCollector): The parent collector
        """
        self.collector = collector
        self.logger = logging.getLogger(__name__)
    
    def on_modified(self, event):
        """
        Handle file modification events.
        
        Args:
            event: The file event
        """
        if not event.is_directory:
            self.logger.debug(f"File changed: {event.src_path}")
            self.collector.process_file(event.src_path)


class FileCollector:
    """
    Collects events from log files.
    """
    
    def __init__(self, config):
        """
        Initialize the File Log Collector.
        
        Args:
            config (dict): Configuration for the collector
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.sources = config.get('sources', [])
        self.collection_interval = config.get('collection_interval', 300)
        self.file_positions = {}  # Keep track of file positions
        self.observer = None
        
        # Compile common log patterns
        self.log_patterns = {
            'apache': re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<size>\d+)'),
            'nginx': re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - (?P<user>[^ ]*) \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<size>\d+)'),
            'windows': re.compile(r'\[(?P<timestamp>[^\]]+)\]\s+(?P<level>\w+)\s+(?P<message>.*)'),
            'syslog': re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>[^\s]+)\s+(?P<program>[^\[]+)(\[(?P<pid>\d+)\])?: (?P<message>.*)'),
        }
    
    def get_log_files(self):
        """
        Get all log files from configured sources.
        
        Returns:
            list: List of log file paths
        """
        log_files = []
        
        for source in self.sources:
            if not source.get('enabled', True):
                continue
                
            base_path = source.get('path', '')
            pattern = source.get('pattern', '*.log')
            
            # Get all matching files
            matches = glob.glob(os.path.join(base_path, pattern))
            log_files.extend(matches)
        
        return log_files
    
    def detect_log_type(self, line):
        """
        Detect the type of log file based on a sample line.
        
        Args:
            line (str): A sample line from the log file
            
        Returns:
            str: Log type name or 'unknown'
        """
        for log_type, pattern in self.log_patterns.items():
            if pattern.match(line):
                return log_type
        return 'unknown'
    
    def parse_log_line(self, line, log_type):
        """
        Parse a log line based on its type.
        
        Args:
            line (str): The log line to parse
            log_type (str): The type of log
            
        Returns:
            dict: Parsed log data or None if parsing failed
        """
        if log_type == 'unknown':
            # Basic parsing for unknown log types
            return {
                'timestamp': datetime.datetime.now().isoformat(),
                'message': line.strip(),
                'raw': line
            }
        
        pattern = self.log_patterns.get(log_type)
        if not pattern:
            return None
            
        match = pattern.match(line)
        if not match:
            return None
            
        # Convert the match to a dictionary
        data = match.groupdict()
        
        # Add the raw line
        data['raw'] = line
        
        return data
    
    def process_file(self, file_path):
        """
        Process a log file and generate events.
        
        Args:
            file_path (str): Path to the log file
            
        Returns:
            list: List of Event objects
        """
        events = []
        
        try:
            # Open the file and seek to the last position
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Get the last position or start from the beginning
                if file_path in self.file_positions:
                    f.seek(self.file_positions[file_path])
                else:
                    # For new files, start from the end
                    f.seek(0, os.SEEK_END)
                
                # Read and process new lines
                first_line = None
                log_type = 'unknown'
                
                for line in f:
                    # Skip empty lines
                    if not line.strip():
                        continue
                    
                    # For the first line, detect the log type
                    if first_line is None:
                        first_line = line
                        log_type = self.detect_log_type(line)
                        self.logger.debug(f"Detected log type: {log_type} for {file_path}")
                    
                    # Parse the log line
                    log_data = self.parse_log_line(line, log_type)
                    
                    if log_data:
                        # Determine severity (simple heuristic)
                        severity = 'low'
                        message = log_data.get('message', '')
                        
                        if 'error' in message.lower() or 'fail' in message.lower():
                            severity = 'high'
                        elif 'warn' in message.lower():
                            severity = 'medium'
                        
                        # Create an event
                        event = Event(
                            source='file_log',
                            event_type=f"file_{log_type}",
                            message=message,
                            raw_data=log_data,
                            severity=severity
                        )
                        
                        events.append(event)
                
                # Update the file position
                self.file_positions[file_path] = f.tell()
        
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {str(e)}")
        
        self.logger.debug(f"Processed {len(events)} events from {file_path}")
        return events
    
    def collect(self):
        """
        Collect events from log files.
        
        Returns:
            list: List of Event objects
        """
        all_events = []
        
        # Get all log files
        log_files = self.get_log_files()
        
        # Process each file
        for file_path in log_files:
            events = self.process_file(file_path)
            all_events.extend(events)
        
        self.logger.info(f"Collected {len(all_events)} events from log files")
        return all_events
    
    def start_watching(self):
        """
        Start watching log files for changes.
        """
        self.logger.info("Starting file watcher")
        
        # Create an observer
        self.observer = Observer()
        handler = LogFileHandler(self)
        
        # Watch each source directory
        for source in self.sources:
            if not source.get('enabled', True):
                continue
                
            path = source.get('path', '')
            if os.path.isdir(path):
                self.logger.info(f"Watching directory: {path}")
                self.observer.schedule(handler, path, recursive=True)
        
        # Start the observer
        self.observer.start()
    
    def stop_watching(self):
        """
        Stop watching log files.
        """
        if self.observer:
            self.logger.info("Stopping file watcher")
            self.observer.stop()
            self.observer.join()
    
    def run_collector(self, event_queue):
        """
        Run the collector continuously, adding events to the queue.
        
        Args:
            event_queue: Queue to add events to
        """
        self.logger.info("Starting File Log Collector")
        
        # Start watching files
        self.start_watching()
        
        try:
            while True:
                # Collect events (polling for files not covered by watchdog)
                events = self.collect()
                
                # Add events to the queue
                for event in events:
                    event_queue.put(event)
                
                # Sleep until next collection
                time.sleep(self.collection_interval)
                
        except KeyboardInterrupt:
            self.logger.info("File Log Collector stopped by user")
        except Exception as e:
            self.logger.error(f"Error in File Log Collector: {str(e)}")
        finally:
            # Stop watching
            self.stop_watching() 