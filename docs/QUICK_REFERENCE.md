# Enterprise SIEM Platform - Quick Reference Guide

This quick reference guide provides common commands and operations for using the Enterprise SIEM Platform.

**A product of Shadownik**

## Installation and Setup

### Windows

```batch
# Clone the repository
git clone https://github.com/5h4d0wn1k/enterprise-siem-platform.git
cd enterprise-siem-platform

# Install and run (creates virtual environment automatically)
run_siem.bat

# With custom configuration
run_siem.bat --config path/to/config.yaml
```

### Linux/macOS

```bash
# Clone the repository
git clone https://github.com/5h4d0wn1k/enterprise-siem-platform.git
cd enterprise-siem-platform

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the SIEM platform
python src/run_siem.py

# With custom configuration
python src/run_siem.py --config path/to/config.yaml
```

## Command-line Options

### Running the Platform

```bash
# Basic usage
python src/run_siem.py

# With custom configuration
python src/run_siem.py --config path/to/config.yaml

# Set logging level
python src/run_siem.py --log-level DEBUG

# Disable dashboard
python src/run_siem.py --no-dashboard

# Console alerting only
python src/run_siem.py --console-only

# Combine options
python src/run_siem.py --log-level DEBUG --config custom_config.yaml --console-only
```

### Test Mode

```bash
# Windows
run_test.bat --test-mode random --rate 0.5 --duration 300

# Linux/macOS
python test_siem.py --test-mode random --rate 0.5 --duration 300

# Generate alertable events
python test_siem.py --test-mode alertable

# Generate both random and alertable events
python test_siem.py --test-mode both --rate 1.0 --duration 600
```

## Dashboard

```
# Default URL
http://127.0.0.1:5000

# Configure custom port in config.yaml:
dashboard:
  port: 8080
  
# Then access via:
http://127.0.0.1:8080
```

## Configuration Examples

### Enable Windows Event Collection

```yaml
# In config.yaml
collectors:
  windows_event:
    enable: true
    channels:
      - 'Security'
      - 'System'
      - 'Application'
    event_ids:
      - 4624  # Successful login
      - 4625  # Failed login
    batch_size: 100
    poll_interval: 10
```

### Enable File Collection

```yaml
# In config.yaml
collectors:
  file:
    enable: true
    paths:
      - '/var/log/apache2/access.log'
      - '/var/log/auth.log'
    pattern: '.*'
    follow: true
    encoding: 'utf-8'
    poll_interval: 5
```

### Configure Email Alerts

```yaml
# In config.yaml
alerters:
  email:
    enable: true
    server: "smtp.example.com"
    port: 587
    use_tls: true
    username: "alerts@example.com"
    password: "your-password-here"
    from_address: "alerts@example.com"
    to_addresses:
      - "admin@example.com"
      - "security@example.com"
    min_severity: "MEDIUM"
```

### Add Threshold Rules

```yaml
# In config.yaml
analyzers:
  threshold:
    enable: true
    rules:
      - name: "Multiple Failed Logins"
        description: "Detects multiple failed login attempts for a single user"
        event_type: "authentication"
        field: "username"
        condition: "count"
        threshold: 5
        time_window: 300
        severity: "HIGH"
      
      - name: "Suspicious File Access"
        description: "Detects access to sensitive files"
        event_type: "file_access"
        field: "path"
        condition: "match"
        patterns:
          - "/etc/passwd"
          - "/etc/shadow"
        severity: "MEDIUM"
```

## Common API Usage

### Creating Custom Events

```python
from src.utils.event import Event
import datetime

# Create a simple event
event = Event(
    message="Suspicious login detected",
    source="custom_source",
    severity="medium",
    event_type="authentication",
    timestamp=datetime.datetime.now(),
    raw_data={"username": "admin", "ip_address": "192.168.1.100"}
)

# Print the event
print(event)

# Convert to dictionary
event_dict = event.to_dict()

# Convert to JSON
event_json = event.to_json()
```

### Creating Custom Alerts

```python
from src.utils.alert import Alert
import datetime

# Create an alert
alert = Alert(
    title="Multiple Failed Logins",
    message="3 failed login attempts for user admin",
    source="threshold_analyzer",
    severity="high",
    timestamp=datetime.datetime.now(),
    rule_name="failed_login_detection",
    events=[]  # Add event dictionaries here
)

# Print the alert
print(alert)

# Convert to dictionary
alert_dict = alert.to_dict()

# Convert to JSON
alert_json = alert.to_json()
```

### Extending the Platform

```python
# Example custom collector (save as src/collectors/custom_collector.py)
import logging
import time
from src.utils.event import Event

class CustomCollector:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.interval = config.get('interval', 60)
        
    def collect(self):
        events = []
        # Implement collection logic here
        events.append(Event(
            message="Custom collector event",
            source="custom_collector",
            severity="low"
        ))
        return events
        
    def run_collector(self, event_queue):
        while True:
            try:
                events = self.collect()
                for event in events:
                    event_queue.put(event)
                time.sleep(self.interval)
            except Exception as e:
                self.logger.error(f"Error in collector: {str(e)}")
                time.sleep(10)
```

## Troubleshooting

### Check Logs

```bash
# View log file
cat data/logs/siem.log

# View last 50 lines
tail -n 50 data/logs/siem.log

# Follow log updates
tail -f data/logs/siem.log

# Windows PowerShell equivalent
Get-Content -Path data\logs\siem.log -Tail 50 -Wait
```

### Check Dashboard Status

1. Access the dashboard at `http://127.0.0.1:5000`
2. Navigate to the System Status section
3. Check the status of each component (green = running, yellow = warning, red = error)

### Common Issues

1. **Dashboard doesn't start**
   - Check if port 5000 is already in use
   - Try a different port in `config.yaml`
   - Check log file for errors

2. **Windows Event Collection doesn't work**
   - Ensure running with admin privileges
   - Check PyWin32 installation: `pip install pywin32==306`
   - Verify event channel names are correct

3. **Email alerts not being sent**
   - Verify SMTP server settings
   - Check username and password
   - Try testing with a lower min_severity setting

4. **Performance issues**
   - Reduce polling intervals in configuration
   - Increase batch_size for collectors
   - Limit the number of events stored (MAX_EVENTS in dashboard/app.py)

## Further Documentation

For more detailed documentation, refer to:

- [User Guide](README.md)
- [Developer Guide](DEVELOPER_GUIDE.md) 