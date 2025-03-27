# Enterprise SIEM Platform Documentation

## Overview

The Enterprise SIEM Platform is a modular and extensible Security Information and Event Management (SIEM) system designed to collect, analyze, and respond to security events across your infrastructure. The platform provides robust log collection capabilities, real-time event analysis, configurable alerting mechanisms, and a comprehensive web dashboard for monitoring and management.

### Key Features

- **Multi-Source Log Collection**: Collects security events from Windows Event logs and file-based logs with expandable collector framework
- **Real-Time Event Analysis**: Analyzes events using configurable threshold-based rules to detect security incidents
- **Flexible Alerting System**: Delivers alerts via console and email with severity-based filtering
- **Interactive Dashboard**: Web-based interface for visualizing security events, alerts, and system status
- **Extensible Architecture**: Modular design allows for easy extension with new collectors, analyzers, and alerters
- **Test Framework**: Built-in test data generation for development and testing

## Installation

### Prerequisites

- **Python 3.8 or higher**
- For Windows Event log collection: Windows operating system
- For email alerting: SMTP server access

### Installation Steps

#### Windows

1. Clone the repository:
   ```
   git clone https://github.com/5h4d0wn1k/enterprise-siem-platform.git
   cd enterprise-siem-platform
   ```

2. Run the setup script which will automatically create a virtual environment and install dependencies:
   ```
   run_siem.bat
   ```

#### Linux/macOS

1. Clone the repository:
   ```
   git clone https://github.com/5h4d0wn1k/enterprise-siem-platform.git
   cd enterprise-siem-platform
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Run the SIEM platform:
   ```
   python src/run_siem.py
   ```

### Dependency Details

The platform requires the following Python packages (specified in requirements.txt):

- **Core functionality**:
  - python-dateutil: For date/time parsing and manipulation
  - schedule: For scheduling tasks
  - pyyaml: For configuration file parsing

- **Log Collection and Parsing**:
  - psutil: For system monitoring
  - watchdog: For file monitoring

- **Analysis and Correlation**:
  - pandas: For data analysis
  - numpy: For numerical operations

- **Dashboard**:
  - flask: For web dashboard
  - flask-wtf: For form handling
  - plotly: For interactive charts

- **Windows Support**:
  - pywin32: For Windows Event log access (Windows only)

## Running the Platform

### Basic Usage

#### Windows

To start the SIEM platform with default settings:

```
run_siem.bat
```

With custom configuration:

```
run_siem.bat --config path/to/config.yaml
```

#### Linux/macOS

To start the SIEM platform with default settings:

```
python src/run_siem.py
```

With custom configuration:

```
python src/run_siem.py --config path/to/config.yaml
```

### Command-line Options

The `run_siem.py` script supports the following command-line arguments:

- `--config`, `-c`: Path to configuration file (default: src/config/config.yaml)
- `--log-level`, `-l`: Set logging level (choices: DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--no-dashboard`, `-nd`: Disable the web dashboard
- `--console-only`, `-co`: Output alerts to console only, ignore other alerters

### Running in Test Mode

The platform includes a test mode that generates simulated security events for development and testing:

#### Windows

```
run_test.bat
```

With custom settings:

```
run_test.bat --test-mode random --rate 0.5 --duration 300
```

#### Linux/macOS

```
python test_siem.py
```

With custom settings:

```
python test_siem.py --test-mode random --rate 0.5 --duration 300
```

### Test Mode Options

- `--test-mode`: Test data generation mode (choices: random, alertable, both)
- `--rate`: Events per second for random generation
- `--duration`: Duration in seconds to run the test (0 for indefinite)
- `--log-level`: Logging level (choices: DEBUG, INFO, WARNING, ERROR)
- `--no-dashboard`: Disable the web dashboard

## Configuration

The system is configured through YAML files located in the `src/config/` directory. The main configuration file is `config.yaml`.

### Configuration File Structure

```yaml
# General settings
general:
  log_level: INFO  # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_file: data/logs/siem.log
  data_dir: data
  temp_dir: temp

# Log Collectors
collectors:
  # Windows Event Collector
  windows_event:
    enable: false  # Set to true to enable
    channels:
      - 'Security'
      - 'System'
      - 'Application'
    event_ids:  # Optional: specific event IDs to collect
      - 4624  # Successful login
      - 4625  # Failed login
    batch_size: 100
    poll_interval: 10  # seconds

  # File Collector (for log files)
  file:
    enable: false
    paths:
      - 'data/logs/sample_logs.log'
    pattern: '.*'  # Regex pattern to match lines
    follow: true
    encoding: 'utf-8'
    poll_interval: 5  # seconds

# Event Analyzers
analyzers:
  # Threshold Analyzer
  threshold:
    enable: true
    rules:
      - name: "Multiple Failed Logins"
        description: "Detects multiple failed login attempts for a single user"
        event_type: "authentication"
        field: "username"
        condition: "count"
        threshold: 5
        time_window: 300  # seconds
        severity: "HIGH"

# Alert Handlers
alerters:
  # Console Alerter
  console:
    enable: true
    min_severity: "LOW"  # Minimum severity to alert on

  # Email Alerter
  email:
    enable: false
    server: "smtp.example.com"
    port: 587
    use_tls: true
    username: "alerts@example.com"
    password: "your-password-here"
    from_address: "alerts@example.com"
    to_addresses:
      - "admin@example.com"
    min_severity: "MEDIUM"  # Only send emails for MEDIUM and above

# Dashboard Configuration
dashboard:
  enable: true
  host: "127.0.0.1"
  port: 5000
  debug: false
  secret_key: "change-this-to-a-secure-random-key"
  session_lifetime: 3600  # seconds
  theme: "default"
  title: "Enterprise SIEM Dashboard"
  refresh_interval: 30  # seconds
```

### Configuration Sections

#### General Configuration

The `general` section configures global settings for the SIEM platform:

| Setting | Description | Default |
|---------|-------------|---------|
| log_level | Logging level for the platform | INFO |
| log_file | Path to the log file | data/logs/siem.log |
| data_dir | Directory for data storage | data |
| temp_dir | Directory for temporary files | temp |

#### Collectors Configuration

The `collectors` section configures event sources:

##### Windows Event Collector

| Setting | Description | Default |
|---------|-------------|---------|
| enable | Enable/disable the collector | false |
| channels | Windows Event log channels to monitor | ['Security', 'System', 'Application'] |
| event_ids | Specific event IDs to collect (empty for all) | Various security event IDs |
| batch_size | Number of events to collect in a batch | 100 |
| poll_interval | Time between collection cycles (seconds) | 10 |

##### File Collector

| Setting | Description | Default |
|---------|-------------|---------|
| enable | Enable/disable the collector | false |
| paths | Paths to log files to monitor | [] |
| pattern | Regex pattern to match log lines | .* |
| follow | Whether to follow log file growth | true |
| encoding | File encoding | utf-8 |
| poll_interval | Time between collection cycles (seconds) | 5 |

#### Analyzers Configuration

The `analyzers` section configures event analysis:

##### Threshold Analyzer

| Setting | Description | Default |
|---------|-------------|---------|
| enable | Enable/disable the analyzer | true |
| rules | List of analysis rules | See below |

Each rule can include:

| Setting | Description |
|---------|-------------|
| name | Rule name |
| description | Rule description |
| event_type | Type of event to match |
| field | Field to evaluate |
| condition | Condition type (count, match) |
| threshold | Number of events to trigger alert |
| time_window | Time window for counting events (seconds) |
| severity | Alert severity if triggered |
| patterns | List of patterns to match (for match condition) |

#### Alerters Configuration

The `alerters` section configures alert delivery:

##### Console Alerter

| Setting | Description | Default |
|---------|-------------|---------|
| enable | Enable/disable the alerter | true |
| min_severity | Minimum severity to alert on | LOW |

##### Email Alerter

| Setting | Description | Default |
|---------|-------------|---------|
| enable | Enable/disable the alerter | false |
| server | SMTP server address | None |
| port | SMTP server port | 587 |
| use_tls | Use TLS for SMTP connection | true |
| username | SMTP username | None |
| password | SMTP password | None |
| from_address | Email sender address | None |
| to_addresses | List of recipient addresses | [] |
| min_severity | Minimum severity to alert on | MEDIUM |

#### Dashboard Configuration

The `dashboard` section configures the web interface:

| Setting | Description | Default |
|---------|-------------|---------|
| enable | Enable/disable the dashboard | true |
| host | Dashboard host address | 127.0.0.1 |
| port | Dashboard port | 5000 |
| debug | Enable debug mode | false |
| secret_key | Secret key for sessions | random key |
| session_lifetime | Session lifetime in seconds | 3600 |
| theme | Dashboard theme | default |
| title | Dashboard title | Enterprise SIEM Dashboard |
| refresh_interval | Dashboard refresh interval (seconds) | 30 |

## System Architecture

The Enterprise SIEM Platform is built with a modular, component-based architecture that enables easy extension and customization.

### Core Components

1. **Event Class**: Represents security events with severity levels and timestamps
2. **Alert Class**: Represents security alerts generated from events
3. **Collectors**: Gather events from various sources
4. **Analyzers**: Process events to detect security incidents
5. **Alerters**: Deliver alerts through different channels
6. **Dashboard**: Web-based user interface
7. **Configuration System**: YAML-based configuration

### Data Flow

```
Log Sources → Collectors → Event Queue → Analyzers → Alert Queue → Alerters
                                        ↓                ↓
                                    Dashboard ←────────────
```

1. **Collection**: Collectors gather events from log sources and add them to the event queue
2. **Analysis**: Analyzers process events from the queue and generate alerts when conditions are met
3. **Alerting**: Alerters deliver alerts through configured channels
4. **Visualization**: The dashboard displays events, alerts, and system status

### Threading Model

The platform uses a multi-threaded architecture:
- Each collector runs in its own thread
- Each analyzer runs in its own thread
- Each alerter runs in its own thread
- The dashboard runs in its own thread
- The main thread monitors the health of all components

## Dashboard

The web dashboard provides a comprehensive interface for monitoring and analyzing security events and alerts.

### Accessing the Dashboard

By default, the dashboard is accessible at:
```
http://127.0.0.1:5000
```

### Dashboard Pages

#### Home Page

The home page provides a high-level overview of the security posture:
- Summary statistics (event count, alert count, critical alerts)
- Events timeline chart
- Events by severity chart
- Event types distribution
- Event sources distribution
- Recent alerts
- System status

#### Events Page

The events page displays detailed information about security events:
- Filterable event list
- Search functionality
- Event details view
- Export capability

#### Alerts Page

The alerts page displays security alerts:
- Filterable alert list
- Search functionality
- Alert details with associated events
- Export capability

#### Settings Page

The settings page displays the current configuration:
- General settings
- Collector settings
- Analyzer settings
- Alerter settings
- Dashboard settings

### Dashboard Features

- **Real-time Updates**: Dashboard automatically refreshes at configurable intervals
- **Dark/Light Mode**: Toggle between dark and light themes
- **Responsive Design**: Works on desktop and mobile devices
- **Interactive Charts**: Hover and click interactions for detailed information
- **Data Export**: Export events and alerts to CSV format
- **Search and Filter**: Quickly find relevant events and alerts

## Event Types and Severity Levels

### Event Types

The platform supports various event types, including:

- **authentication**: Login/logout events
- **file_access**: File access and modification events
- **network**: Network connection and traffic events
- **system**: System events (startup, shutdown, service changes)
- **security**: Security-related events (antivirus, firewall, etc.)

### Severity Levels

Events and alerts have the following severity levels (from lowest to highest):

1. **LOW**: Informational events with minimal security impact
2. **MEDIUM**: Events that may indicate suspicious activity
3. **HIGH**: Events that likely indicate a security concern
4. **CRITICAL**: Events that require immediate attention

## Extending the Platform

The Enterprise SIEM Platform is designed to be easily extensible.

### Adding a New Collector

To create a custom collector:

1. Create a new Python file in the `src/collectors/` directory
2. Define a class that implements:
   - `__init__(self, config)`: Initialize the collector
   - `collect()`: Collect events
   - `run_collector(event_queue)`: Main execution method

Example:

```python
from src.utils.event import Event

class CustomCollector:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def collect(self):
        # Implement collection logic
        events = []
        # ... collect events ...
        return events
        
    def run_collector(self, event_queue):
        while True:
            try:
                events = self.collect()
                for event in events:
                    event_queue.put(event)
                time.sleep(self.config.get('interval', 60))
            except Exception as e:
                self.logger.error(f"Error in collector: {str(e)}")
                time.sleep(10)
```

3. Register the collector in `run_siem.py`
4. Add configuration in `config.yaml`

### Adding a New Analyzer

To create a custom analyzer:

1. Create a new Python file in the `src/analyzers/` directory
2. Define a class that implements:
   - `__init__(self, config)`: Initialize the analyzer
   - `analyze_event(event)`: Analyze a single event
   - `run_analyzer(event_queue, alert_queue)`: Main execution method

3. Register the analyzer in `run_siem.py`
4. Add configuration in `config.yaml`

### Adding a New Alerter

To create a custom alerter:

1. Create a new Python file in the `src/alerting/` directory
2. Define a class that implements:
   - `__init__(self, config)`: Initialize the alerter
   - `send_alert(alert)`: Send a single alert
   - `run_alerter(alert_queue)`: Main execution method

3. Register the alerter in `run_siem.py`
4. Add configuration in `config.yaml`

## API Usage

The platform provides a programmatic API for integration with other systems.

### Example: Creating Custom Events

```python
from src.utils.event import Event

# Create a custom event
event = Event(
    source='custom_source',
    event_type='custom_event',
    message='Custom security event detected',
    severity='medium',
    raw_data={'custom_field': 'custom_value'}
)

# Convert to dictionary
event_dict = event.to_dict()

# Convert to JSON
event_json = event.to_json()

# Create from dictionary
event_from_dict = Event.from_dict(event_dict)

# Create from JSON
event_from_json = Event.from_json(event_json)
```

### Example: Creating Custom Alerts

```python
from src.utils.alert import Alert

# Create a custom alert
alert = Alert(
    title='Security Alert',
    message='Multiple failed login attempts detected',
    source='custom_analyzer',
    rule_name='failed_login_detection',
    severity='high',
    events=[event.to_dict()]  # Add related events
)

# Convert to dictionary
alert_dict = alert.to_dict()

# Convert to JSON
alert_json = alert.to_json()
```

### Full API Example

See `examples/api_example.py` for a complete example of:
- Creating custom events
- Analyzing events with a custom rule set
- Generating and handling alerts

To run the API example:

#### Windows

```
examples\run_api_example.bat
```

#### Linux/macOS

```
python examples/api_example.py
```

## Custom Collector Example

The platform includes an example of a custom collector implementation in `examples/custom_collector_example.py`. This demonstrates how to create a collector that interfaces with external API services.

To run the custom collector example:

#### Windows

```
examples\run_custom_collector.bat
```

#### Linux/macOS

```
python examples/custom_collector_example.py
```

## Test Data Generation

The platform includes a test data generator (`src/utils/test_data_generator.py`) that can simulate various security events.

### Test Data Generation Features

- Generate random timestamps
- Generate random IP addresses
- Generate various event types:
  - Authentication events
  - File access events
  - Network events
  - System events
  - Security events
- Generate event sequences with configurable intervals
- Generate alertable event patterns to test analyzers

### Test Data Generator API

```python
from src.utils.test_data_generator import generate_random_event, generate_alertable_sequence

# Generate a random event
event = generate_random_event()

# Generate a specific event type
auth_event = generate_authentication_event(severity='medium')

# Generate a sequence of events that should trigger an alert
alertable_events = generate_alertable_sequence()
```

## Data Storage

The platform stores data in several locations:

- **Configuration**: `src/config/config.yaml`
- **Logs**: `data/logs/siem.log`
- **Temporary Data**: `temp/`

By default, events and alerts are stored in memory during runtime. For permanent storage, you would need to implement a database integration.

## Troubleshooting

### Common Issues

#### Dashboard Doesn't Start

- Check if port 5000 is already in use
- Check the log file for errors
- Ensure the dashboard is enabled in the configuration

#### Windows Event Collection Doesn't Work

- Ensure the platform is running with administrative privileges
- Ensure the Windows Event Collector is enabled in the configuration
- Check if PyWin32 is installed correctly

#### Email Alerts Aren't Sent

- Check SMTP server settings
- Verify username and password
- Check if email alerter is enabled
- Ensure the alert severity meets the minimum required level

### Debugging

To enable detailed debugging:

```
python src/run_siem.py --log-level DEBUG
```

Or modify the configuration:

```yaml
general:
  log_level: DEBUG
```

### Checking Component Status

The dashboard's system status page displays the current status of all components:
- Green: Component is running
- Yellow: Component is in warning state
- Red: Component is in error state
- Gray: Component is stopped

## Performance Considerations

### Memory Usage

- The platform keeps recent events and alerts in memory
- Configure `MAX_EVENTS` and `MAX_ALERTS` in `dashboard/app.py` to control memory usage

### CPU Usage

- Each collector, analyzer, and alerter runs in its own thread
- High event rates can increase CPU usage
- Adjust polling intervals in configuration to balance responsiveness and resource usage

### Network Usage

- The dashboard makes regular API requests to refresh data
- Adjust the refresh interval in the dashboard configuration to balance responsiveness and network usage
- Email alerting generates network traffic to the SMTP server

## Security Considerations

### Authentication

The dashboard does not include authentication by default. For production use, consider:

- Running behind a reverse proxy with authentication
- Implementing Flask authentication
- Restricting access through network controls

### Sensitive Data

- Avoid logging sensitive information in event messages
- Store SMTP passwords securely
- Change the default dashboard secret key

### Production Deployment

For production deployment:

- Use a production WSGI server instead of Flask's development server
- Set up proper logging and monitoring
- Configure all security-related options
- Implement authentication and authorization

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Contact

For support or questions, please open an issue in the GitHub repository. 