"""
Windows Event Log Collector for Enterprise SIEM Platform.
"""
import logging
import datetime
import win32evtlog
import win32con
import win32evtlogutil
import time

from src.utils.event import Event

class WindowsEventCollector:
    """
    Collects events from Windows Event logs.
    """
    
    def __init__(self, config):
        """
        Initialize the Windows Event Log Collector.
        
        Args:
            config (dict): Configuration for the collector
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.sources = config.get('sources', [])
        self.collection_interval = config.get('collection_interval', 60)
        self.last_collection_time = None
        
    def collect(self):
        """
        Collect events from Windows Event logs.
        
        Returns:
            list: List of Event objects
        """
        collected_events = []
        current_time = datetime.datetime.now()
        
        # Only process sources that are enabled
        enabled_sources = [s for s in self.sources if s.get('enabled', True)]
        
        for source in enabled_sources:
            log_type = source.get('name', 'System')
            
            try:
                # Open the event log
                hand = win32evtlog.OpenEventLog(None, log_type)
                
                # Get the total number of records
                total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
                self.logger.debug(f"Found {total_records} records in {log_type} log")
                
                # Read events
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                # Process events
                for event in events:
                    # Get the timestamp
                    time_generated = event.TimeGenerated.Format()
                    event_time = datetime.datetime.strptime(time_generated, '%c')
                    
                    # Skip old events if we have a last collection time
                    if self.last_collection_time and event_time <= self.last_collection_time:
                        continue
                    
                    # Create an Event object
                    event_id = event.EventID & 0xFFFF  # Remove the high-order bits
                    source_name = str(event.SourceName)
                    
                    # Extract the message
                    try:
                        message = win32evtlogutil.SafeFormatMessage(event, log_type)
                    except Exception:
                        message = f"Event ID: {event_id} from {source_name}"
                    
                    # Create raw data dictionary
                    raw_data = {
                        'event_id': event_id,
                        'source_name': source_name,
                        'time_generated': time_generated,
                        'event_category': event.EventCategory,
                        'event_type': event.EventType,
                        'record_number': event.RecordNumber
                    }
                    
                    # Determine severity based on event type
                    severity = 'low'
                    if event.EventType == win32con.EVENTLOG_ERROR_TYPE:
                        severity = 'high'
                    elif event.EventType == win32con.EVENTLOG_WARNING_TYPE:
                        severity = 'medium'
                    
                    # Create the event
                    siem_event = Event(
                        source='windows_event',
                        event_type=f"{log_type.lower()}_{event_id}",
                        message=message,
                        raw_data=raw_data,
                        severity=severity,
                        timestamp=event_time
                    )
                    
                    collected_events.append(siem_event)
                
                # Close the handle
                win32evtlog.CloseEventLog(hand)
                
            except Exception as e:
                self.logger.error(f"Error collecting events from {log_type}: {str(e)}")
        
        # Update the last collection time
        self.last_collection_time = current_time
        
        self.logger.info(f"Collected {len(collected_events)} events from Windows Event logs")
        return collected_events
    
    def run_collector(self, event_queue):
        """
        Run the collector continuously, adding events to the queue.
        
        Args:
            event_queue: Queue to add events to
        """
        self.logger.info("Starting Windows Event Log Collector")
        
        while True:
            try:
                # Collect events
                events = self.collect()
                
                # Add events to the queue
                for event in events:
                    event_queue.put(event)
                
                # Sleep until next collection
                time.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in Windows Event Log Collector: {str(e)}")
                time.sleep(10)  # Sleep briefly before retrying 