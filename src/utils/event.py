"""
Event class for Enterprise SIEM Platform.
Represents a security event with various attributes and methods.
"""

import uuid
import json
import datetime
from typing import Dict, Any, Optional, List

class Event:
    """
    Represents a security event in the SIEM platform.
    Events are collected from various sources and analyzed for security incidents.
    """
    
    # Valid severity levels
    SEVERITY_LEVELS = ['info', 'low', 'medium', 'high', 'critical']
    
    def __init__(
        self,
        message: str,
        source: str,
        severity: str = 'info',
        event_type: Optional[str] = None,
        timestamp: Optional[datetime.datetime] = None,
        raw_data: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None
    ):
        """
        Initialize a new Event.
        
        Args:
            message (str): Human-readable event message
            source (str): Source of the event (e.g., 'Windows Event Log', 'Apache Log')
            severity (str): Severity level ('info', 'low', 'medium', 'high', 'critical')
            event_type (str, optional): Type of event (e.g., 'login', 'file_access')
            timestamp (datetime, optional): Event timestamp, defaults to current time
            raw_data (dict, optional): Raw event data for additional context
            event_id (str, optional): Unique ID for the event, auto-generated if not provided
        """
        self.id = event_id or str(uuid.uuid4())
        self.message = message
        self.source = source
        self.event_type = event_type
        self.timestamp = timestamp or datetime.datetime.now()
        self.raw_data = raw_data or {}
        
        # Validate and set severity
        if severity not in self.SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity level: {severity}. Must be one of {self.SEVERITY_LEVELS}")
        self.severity = severity
    
    def __str__(self) -> str:
        """Return string representation of the event."""
        return f"[{self.severity.upper()}] {self.source}: {self.message}"
    
    def __repr__(self) -> str:
        """Return detailed representation of the event."""
        return (f"Event(id='{self.id}', message='{self.message}', source='{self.source}', "
                f"severity='{self.severity}', event_type='{self.event_type}', "
                f"timestamp='{self.timestamp}')")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary.
        
        Returns:
            dict: Dictionary representation of the event
        """
        return {
            'id': self.id,
            'message': self.message,
            'source': self.source,
            'severity': self.severity,
            'event_type': self.event_type,
            'timestamp': self.timestamp.isoformat(),
            'raw_data': self.raw_data
        }
    
    def to_json(self) -> str:
        """
        Convert the event to JSON.
        
        Returns:
            str: JSON representation of the event
        """
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Event':
        """
        Create an Event from a dictionary.
        
        Args:
            data (dict): Dictionary containing event data
        
        Returns:
            Event: A new Event instance
        """
        # Parse timestamp if it's a string
        timestamp = data.get('timestamp')
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.datetime.fromisoformat(timestamp)
            except ValueError:
                # Try another common format if ISO format fails
                timestamp = datetime.datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
        
        return cls(
            message=data.get('message', ''),
            source=data.get('source', 'unknown'),
            severity=data.get('severity', 'info'),
            event_type=data.get('event_type'),
            timestamp=timestamp,
            raw_data=data.get('raw_data', {}),
            event_id=data.get('id')
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'Event':
        """
        Create an Event from a JSON string.
        
        Args:
            json_str (str): JSON string containing event data
        
        Returns:
            Event: A new Event instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def get_severity_level(self) -> int:
        """
        Get numeric severity level for comparison.
        
        Returns:
            int: Numeric severity level (0-4, with 4 being critical)
        """
        return self.SEVERITY_LEVELS.index(self.severity)
    
    def is_severe(self) -> bool:
        """
        Check if the event has high or critical severity.
        
        Returns:
            bool: True if severity is high or critical
        """
        return self.severity in ['high', 'critical']
    
    def add_context(self, key: str, value: Any) -> None:
        """
        Add additional context to the event.
        
        Args:
            key (str): Context key
            value (Any): Context value
        """
        self.raw_data[key] = value
    
    def add_related_event(self, event_id: str) -> None:
        """
        Add a related event ID to this event.
        
        Args:
            event_id (str): ID of related event
        """
        if 'related_events' not in self.raw_data:
            self.raw_data['related_events'] = []
        
        if event_id not in self.raw_data['related_events']:
            self.raw_data['related_events'].append(event_id)
    
    def get_related_events(self) -> List[str]:
        """
        Get list of related event IDs.
        
        Returns:
            list: List of related event IDs
        """
        return self.raw_data.get('related_events', []) 