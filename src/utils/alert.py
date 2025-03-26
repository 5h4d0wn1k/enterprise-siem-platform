"""
Alert class for Enterprise SIEM Platform.
Represents a security alert generated from analyzed events.
"""

import uuid
import json
import datetime
from typing import Dict, Any, Optional, List, Union

class Alert:
    """
    Represents a security alert in the SIEM platform.
    Alerts are generated when analysis rules identify security issues.
    """
    
    # Valid severity levels
    SEVERITY_LEVELS = ['info', 'low', 'medium', 'high', 'critical']
    
    def __init__(
        self,
        title: str,
        message: str,
        source: str,
        severity: str = 'medium',
        timestamp: Optional[datetime.datetime] = None,
        rule_name: Optional[str] = None,
        events: Optional[List[Dict[str, Any]]] = None,
        raw_data: Optional[Dict[str, Any]] = None,
        alert_id: Optional[str] = None
    ):
        """
        Initialize a new Alert.
        
        Args:
            title (str): Alert title
            message (str): Human-readable alert message
            source (str): Source of the alert (e.g., 'threshold_analyzer')
            severity (str): Severity level ('info', 'low', 'medium', 'high', 'critical')
            timestamp (datetime, optional): Alert timestamp, defaults to current time
            rule_name (str, optional): Name of the rule that triggered the alert
            events (list, optional): List of events that triggered the alert
            raw_data (dict, optional): Raw alert data for additional context
            alert_id (str, optional): Unique ID for the alert, auto-generated if not provided
        """
        self.id = alert_id or str(uuid.uuid4())
        self.title = title
        self.message = message
        self.source = source
        self.timestamp = timestamp or datetime.datetime.now()
        self.rule_name = rule_name
        self.events = events or []
        self.raw_data = raw_data or {}
        
        # Add matched events to raw_data for storage
        if events:
            self.raw_data['matched_events'] = events
        
        # Validate and set severity
        if severity not in self.SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity level: {severity}. Must be one of {self.SEVERITY_LEVELS}")
        self.severity = severity
        
        # Add rule_name to raw_data
        if rule_name:
            self.raw_data['rule_name'] = rule_name
    
    def __str__(self) -> str:
        """Return string representation of the alert."""
        return f"[{self.severity.upper()}] {self.title}: {self.message}"
    
    def __repr__(self) -> str:
        """Return detailed representation of the alert."""
        return (f"Alert(id='{self.id}', title='{self.title}', source='{self.source}', "
                f"severity='{self.severity}', timestamp='{self.timestamp}')")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the alert to a dictionary.
        
        Returns:
            dict: Dictionary representation of the alert
        """
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'source': self.source,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat(),
            'rule_name': self.rule_name,
            'raw_data': self.raw_data
        }
    
    def to_json(self) -> str:
        """
        Convert the alert to JSON.
        
        Returns:
            str: JSON representation of the alert
        """
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """
        Create an Alert from a dictionary.
        
        Args:
            data (dict): Dictionary containing alert data
        
        Returns:
            Alert: A new Alert instance
        """
        # Parse timestamp if it's a string
        timestamp = data.get('timestamp')
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.datetime.fromisoformat(timestamp)
            except ValueError:
                # Try another common format if ISO format fails
                timestamp = datetime.datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
        
        # Extract events from raw_data if present
        raw_data = data.get('raw_data', {})
        events = raw_data.get('matched_events', [])
        
        return cls(
            title=data.get('title', ''),
            message=data.get('message', ''),
            source=data.get('source', 'unknown'),
            severity=data.get('severity', 'medium'),
            timestamp=timestamp,
            rule_name=data.get('rule_name'),
            events=events,
            raw_data=raw_data,
            alert_id=data.get('id')
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'Alert':
        """
        Create an Alert from a JSON string.
        
        Args:
            json_str (str): JSON string containing alert data
        
        Returns:
            Alert: A new Alert instance
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
        Check if the alert has high or critical severity.
        
        Returns:
            bool: True if severity is high or critical
        """
        return self.severity in ['high', 'critical']
    
    def add_event(self, event: Union[Dict[str, Any], str]) -> None:
        """
        Add an event to this alert.
        
        Args:
            event (dict or str): Event dictionary or event ID
        """
        # If event is just an ID, add it as a string
        if isinstance(event, str):
            if 'event_ids' not in self.raw_data:
                self.raw_data['event_ids'] = []
            self.raw_data['event_ids'].append(event)
            return
        
        # Otherwise, add the full event to the matched_events list
        if 'matched_events' not in self.raw_data:
            self.raw_data['matched_events'] = []
        
        self.raw_data['matched_events'].append(event)
        self.events.append(event)
    
    def add_context(self, key: str, value: Any) -> None:
        """
        Add additional context to the alert.
        
        Args:
            key (str): Context key
            value (Any): Context value
        """
        self.raw_data[key] = value
    
    def get_matched_events(self) -> List[Dict[str, Any]]:
        """
        Get the list of events that triggered this alert.
        
        Returns:
            list: List of event dictionaries
        """
        return self.events 