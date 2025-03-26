"""
Enterprise SIEM Platform Dashboard

Flask application to display collected events, alerts, and system status.
"""

import os
import sys
import json
import logging
import threading
import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any, Union, Optional, Tuple
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash

# Add parent directory to path to import SIEM modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.event import Event
from utils.alert import Alert
from utils.config_loader import load_config

# Setup logging
logger = logging.getLogger('siem.dashboard')

# Flask application
app = Flask(__name__)

# Global variables to store events and alerts
events = []  # Store recent events (limit size)
alerts = []  # Store recent alerts (limit size)
event_stats = {  # Store event statistics
    'counts_by_severity': defaultdict(int),
    'counts_by_source': defaultdict(int),
    'counts_by_type': defaultdict(int),
    'events_over_time': [],
}
alert_stats = {  # Store alert statistics
    'counts_by_severity': defaultdict(int),
    'counts_by_rule': defaultdict(int),
    'alerts_over_time': [],
}
system_status = {  # Store system status
    'collectors': [],
    'analyzers': [],
    'alerters': [],
    'started_at': datetime.datetime.now().isoformat(),
    'events_processed': 0,
    'alerts_generated': 0,
    'last_updated': datetime.datetime.now().isoformat(),
}

# Maximum number of events and alerts to store
MAX_EVENTS = 1000
MAX_ALERTS = 500

# Lock for thread-safe updates
data_lock = threading.Lock()

def configure_app(config: Dict[str, Any]) -> None:
    """
    Configure the Flask application based on the SIEM configuration.
    
    Args:
        config: The SIEM configuration dictionary
    """
    dashboard_config = config.get('dashboard', {})
    
    # Set Flask secret key
    app.secret_key = dashboard_config.get('secret_key', os.urandom(24))
    
    # Set session lifetime
    app.permanent_session_lifetime = datetime.timedelta(
        seconds=dashboard_config.get('session_lifetime', 3600)
    )
    
    # Set debug mode
    app.debug = dashboard_config.get('debug', False)
    
    # Store some config in the app config
    app.config['SIEM_CONFIG'] = config
    app.config['DASHBOARD_CONFIG'] = dashboard_config
    app.config['REFRESH_INTERVAL'] = dashboard_config.get('refresh_interval', 30)
    app.config['CHART_LIMIT'] = dashboard_config.get('chart_limit', 100)
    app.config['TABLE_LIMIT'] = dashboard_config.get('table_limit', 50)
    app.config['TITLE'] = dashboard_config.get('title', 'Enterprise SIEM Dashboard')
    app.config['THEME'] = dashboard_config.get('theme', 'default')
    
    logger.info(f"Dashboard configured with refresh interval: {app.config['REFRESH_INTERVAL']}s")

def add_event(event: Event) -> None:
    """
    Add an event to the dashboard.
    
    Args:
        event: The event to add
    """
    with data_lock:
        # Convert Event to dictionary for storage
        event_dict = event.to_dict()
        
        # Add to events list
        events.append(event_dict)
        if len(events) > MAX_EVENTS:
            events.pop(0)
        
        # Update statistics
        event_stats['counts_by_severity'][event.severity] += 1
        event_stats['counts_by_source'][event.source] += 1
        
        # Extract event type from message or raw data
        event_type = "unknown"
        if hasattr(event, 'event_type'):
            event_type = event.event_type
        elif isinstance(event.raw_data, dict) and 'event_type' in event.raw_data:
            event_type = event.raw_data['event_type']
        
        event_stats['counts_by_type'][event_type] += 1
        
        # Add to timeline data
        event_time = event.timestamp.replace(second=0, microsecond=0).isoformat()
        found = False
        for i, time_point in enumerate(event_stats['events_over_time']):
            if time_point['time'] == event_time:
                event_stats['events_over_time'][i]['count'] += 1
                found = True
                break
        
        if not found:
            event_stats['events_over_time'].append({
                'time': event_time,
                'count': 1
            })
        
        # Sort timeline data
        event_stats['events_over_time'] = sorted(
            event_stats['events_over_time'], 
            key=lambda x: x['time']
        )
        
        # Limit timeline data points
        if len(event_stats['events_over_time']) > 100:
            event_stats['events_over_time'] = event_stats['events_over_time'][-100:]
        
        # Update system stats
        system_status['events_processed'] += 1
        system_status['last_updated'] = datetime.datetime.now().isoformat()

def add_alert(alert: Alert) -> None:
    """
    Add an alert to the dashboard.
    
    Args:
        alert: The alert to add
    """
    with data_lock:
        # Convert Alert to dictionary for storage
        alert_dict = alert.to_dict()
        
        # Add to alerts list
        alerts.append(alert_dict)
        if len(alerts) > MAX_ALERTS:
            alerts.pop(0)
        
        # Update statistics
        alert_stats['counts_by_severity'][alert.severity] += 1
        alert_stats['counts_by_rule'][alert.rule_name] += 1
        
        # Add to timeline data
        alert_time = alert.timestamp.replace(second=0, microsecond=0).isoformat()
        found = False
        for i, time_point in enumerate(alert_stats['alerts_over_time']):
            if time_point['time'] == alert_time:
                alert_stats['alerts_over_time'][i]['count'] += 1
                found = True
                break
        
        if not found:
            alert_stats['alerts_over_time'].append({
                'time': alert_time,
                'count': 1
            })
        
        # Sort timeline data
        alert_stats['alerts_over_time'] = sorted(
            alert_stats['alerts_over_time'], 
            key=lambda x: x['time']
        )
        
        # Limit timeline data points
        if len(alert_stats['alerts_over_time']) > 100:
            alert_stats['alerts_over_time'] = alert_stats['alerts_over_time'][-100:]
        
        # Update system stats
        system_status['alerts_generated'] += 1
        system_status['last_updated'] = datetime.datetime.now().isoformat()

def update_component_status(component_type: str, name: str, status: str, details: Dict[str, Any] = None) -> None:
    """
    Update the status of a system component.
    
    Args:
        component_type: Type of component (collector, analyzer, alerter)
        name: Name of the component
        status: Status string (running, stopped, error)
        details: Additional details about the component
    """
    if component_type not in ['collectors', 'analyzers', 'alerters']:
        logger.warning(f"Invalid component type: {component_type}")
        return
    
    with data_lock:
        # Find existing component
        found = False
        for i, component in enumerate(system_status[component_type]):
            if component['name'] == name:
                # Update existing component
                system_status[component_type][i].update({
                    'status': status,
                    'last_updated': datetime.datetime.now().isoformat(),
                    **(details or {})
                })
                found = True
                break
        
        if not found:
            # Add new component
            system_status[component_type].append({
                'name': name,
                'status': status,
                'added_at': datetime.datetime.now().isoformat(),
                'last_updated': datetime.datetime.now().isoformat(),
                **(details or {})
            })

@app.context_processor
def inject_template_vars() -> Dict[str, Any]:
    """Inject template variables."""
    return {
        'title': app.config.get('TITLE', 'Enterprise SIEM Dashboard'),
        'theme': app.config.get('THEME', 'default'),
        'refresh_interval': app.config.get('REFRESH_INTERVAL', 30),
        'current_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'system_uptime': get_uptime_string()
    }

def get_uptime_string() -> str:
    """
    Get a human-readable uptime string.
    
    Returns:
        str: Uptime string (e.g., "2 days, 3 hours, 45 minutes")
    """
    try:
        started_at = datetime.datetime.fromisoformat(system_status['started_at'])
        now = datetime.datetime.now()
        delta = now - started_at
        
        days = delta.days
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        parts = []
        if days > 0:
            parts.append(f"{days} {'day' if days == 1 else 'days'}")
        if hours > 0:
            parts.append(f"{hours} {'hour' if hours == 1 else 'hours'}")
        if minutes > 0:
            parts.append(f"{minutes} {'minute' if minutes == 1 else 'minutes'}")
        
        if not parts:
            return f"{seconds} seconds"
        return ", ".join(parts)
    except Exception as e:
        logger.error(f"Error calculating uptime: {e}")
        return "Unknown"

# Routes
@app.route('/')
def index() -> str:
    """
    Dashboard home page.
    
    Returns:
        str: Rendered HTML template
    """
    return render_template('index.html', 
                          event_stats=event_stats,
                          alert_stats=alert_stats,
                          system_status=system_status)

@app.route('/events')
def events_page() -> str:
    """
    Events page.
    
    Returns:
        str: Rendered HTML template
    """
    return render_template('events.html')

@app.route('/alerts')
def alerts_page() -> str:
    """
    Alerts page.
    
    Returns:
        str: Rendered HTML template
    """
    return render_template('alerts.html')

@app.route('/settings')
def settings_page() -> str:
    """
    Settings page.
    
    Returns:
        str: Rendered HTML template
    """
    return render_template('settings.html', 
                          config=app.config['SIEM_CONFIG'],
                          dashboard_config=app.config['DASHBOARD_CONFIG'])

@app.route('/api/events')
def api_events() -> Dict[str, Any]:
    """
    API endpoint to get events.
    
    Returns:
        dict: JSON response with events data
    """
    with data_lock:
        limit = request.args.get('limit', type=int, default=100)
        severity = request.args.get('severity')
        source = request.args.get('source')
        event_type = request.args.get('type')
        search = request.args.get('search', '').lower()
        
        # Filter events
        filtered_events = events
        if severity:
            filtered_events = [e for e in filtered_events if e['severity'] == severity]
        if source:
            filtered_events = [e for e in filtered_events if e['source'] == source]
        if event_type:
            filtered_events = [e for e in filtered_events if 
                             (e.get('event_type') == event_type or 
                             (isinstance(e.get('raw_data'), dict) and e.get('raw_data', {}).get('event_type') == event_type))]
        if search:
            filtered_events = [e for e in filtered_events if 
                             search in e['message'].lower() or 
                             search in e['source'].lower() or
                             search in json.dumps(e.get('raw_data', {})).lower()]
        
        # Get the most recent events up to the limit
        limited_events = filtered_events[-limit:]
        
        # Calculate counts for the filtered set
        unique_sources = list(set(e['source'] for e in filtered_events))
        unique_severities = list(set(e['severity'] for e in filtered_events))
        
        return {
            'events': limited_events[::-1],  # Reverse to get newest first
            'total': len(filtered_events),
            'sources': unique_sources,
            'severities': unique_severities,
            'returned': len(limited_events)
        }

@app.route('/api/alerts')
def api_alerts() -> Dict[str, Any]:
    """
    API endpoint to get alerts.
    
    Returns:
        dict: JSON response with alerts data
    """
    with data_lock:
        limit = request.args.get('limit', type=int, default=100)
        severity = request.args.get('severity')
        rule = request.args.get('rule')
        search = request.args.get('search', '').lower()
        
        # Filter alerts
        filtered_alerts = alerts
        if severity:
            filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity]
        if rule:
            filtered_alerts = [a for a in filtered_alerts if a['rule_name'] == rule]
        if search:
            filtered_alerts = [a for a in filtered_alerts if 
                             search in a['title'].lower() or 
                             search in a['message'].lower() or 
                             search in a['rule_name'].lower()]
        
        # Get the most recent alerts up to the limit
        limited_alerts = filtered_alerts[-limit:]
        
        # Calculate unique values for the filtered set
        unique_rules = list(set(a['rule_name'] for a in filtered_alerts))
        unique_severities = list(set(a['severity'] for a in filtered_alerts))
        
        return {
            'alerts': limited_alerts[::-1],  # Reverse to get newest first
            'total': len(filtered_alerts),
            'rules': unique_rules,
            'severities': unique_severities,
            'returned': len(limited_alerts)
        }

@app.route('/api/stats')
def api_stats() -> Dict[str, Any]:
    """
    API endpoint to get system statistics.
    
    Returns:
        dict: JSON response with system statistics
    """
    with data_lock:
        return {
            'event_stats': event_stats,
            'alert_stats': alert_stats,
            'system_status': system_status,
            'uptime': get_uptime_string(),
            'timestamp': datetime.datetime.now().isoformat()
        }

def run_dashboard(config: Dict[str, Any], event_queue: Optional[Any] = None, alert_queue: Optional[Any] = None) -> None:
    """
    Run the dashboard.
    
    Args:
        config: SIEM configuration
        event_queue: Queue for incoming events
        alert_queue: Queue for incoming alerts
    """
    # Configure the dashboard
    configure_app(config)
    
    # Set up dashboard host and port
    dashboard_config = config.get('dashboard', {})
    host = dashboard_config.get('host', '127.0.0.1')
    port = dashboard_config.get('port', 5000)
    debug = dashboard_config.get('debug', False)
    
    # Start a thread to process queues if provided
    if event_queue or alert_queue:
        processor_thread = threading.Thread(target=process_queues, 
                                          args=(event_queue, alert_queue), 
                                          daemon=True)
        processor_thread.start()
        logger.info("Started queue processor thread")
    
    # Start Flask application
    logger.info(f"Starting dashboard on {host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False, threaded=True)

def process_queues(event_queue: Optional[Any], alert_queue: Optional[Any]) -> None:
    """
    Process event and alert queues.
    
    Args:
        event_queue: Queue for incoming events
        alert_queue: Queue for incoming alerts
    """
    while True:
        try:
            # Process events
            if event_queue:
                while not event_queue.empty():
                    event = event_queue.get_nowait()
                    add_event(event)
                    event_queue.task_done()
            
            # Process alerts
            if alert_queue:
                while not alert_queue.empty():
                    alert = alert_queue.get_nowait()
                    add_alert(alert)
                    alert_queue.task_done()
            
            # Sleep to avoid high CPU usage
            import time
            time.sleep(0.1)
        except Exception as e:
            logger.error(f"Error processing queues: {e}")
            import time
            time.sleep(1)

if __name__ == '__main__':
    # This is only executed when the script is run directly
    print("This script is intended to be imported as a module.")
    print("To run the dashboard, use run_siem.py with dashboard enabled.")
    
    # For development testing
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--dev':
        # Load configuration
        config = load_config()
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Generate some sample data
        for i in range(20):
            # Create a sample event
            timestamp = datetime.datetime.now() - datetime.timedelta(minutes=i*5)
            event = Event(
                message=f"Sample event {i}",
                source="test",
                severity=["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
                timestamp=timestamp,
                raw_data={"event_type": ["authentication", "file_access", "network"][i % 3], "id": i}
            )
            add_event(event)
            
            # Create some sample alerts
            if i % 3 == 0:
                alert = Alert(
                    title=f"Sample alert {i//3}",
                    message=f"This is a sample alert ({i//3})",
                    source="test",
                    severity=["MEDIUM", "HIGH", "CRITICAL"][i//3 % 3],
                    timestamp=timestamp,
                    rule_name=["Failed Login", "Suspicious Access", "Network Scan"][i//3 % 3],
                    events=[event]
                )
                add_alert(alert)
        
        # Run the dashboard
        run_dashboard(config) 