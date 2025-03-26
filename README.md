# Enterprise SIEM Platform

A modular and extensible Security Information and Event Management (SIEM) platform for collecting, analyzing, and responding to security events.

**A product of Shadownik**

## Features

- **Multi-Source Log Collection**: Collect security events from Windows Event logs and file-based logs with an expandable collector framework
- **Real-Time Event Analysis**: Analyze events using configurable threshold-based rules to detect security incidents
- **Flexible Alerting System**: Deliver alerts via console and email with severity-based filtering
- **Interactive Dashboard**: Web-based interface for visualizing security events, alerts, and system status with dark/light mode
- **Extensible Architecture**: Modular design allows for easy extension with new collectors, analyzers, and alerters
- **Test Framework**: Built-in test data generation for development and testing
- **Robust Error Handling**: Graceful recovery from component failures with automatic reconnection capabilities
- **Configurable Logging**: Comprehensive logging system with adjustable verbosity levels

## Getting Started

### Prerequisites

- Python 3.8 or higher
- For Windows Event log collection: Windows operating system
- For email alerting: SMTP server access

### Installation

#### Windows

1. Clone this repository:
   ```
   git clone https://github.com/5h4d0wn1k/enterprise-siem-platform.git
   cd enterprise-siem-platform
   ```

2. Run the setup script which will automatically create a virtual environment and install dependencies:
   ```
   run_siem.bat
   ```

#### Linux/macOS

1. Clone this repository:
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

### Command-line Options

The `run_siem.py` script supports the following command-line arguments:

- `--config`, `-c`: Path to configuration file (default: src/config/config.yaml)
- `--log-level`, `-l`: Set logging level (choices: DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--no-dashboard`, `-nd`: Disable the web dashboard
- `--console-only`, `-co`: Output alerts to console only, ignore other alerters

### Configuration

The system is configured through YAML files in the `src/config/` directory. The main configuration file is `config.yaml`.

Key configuration sections:

- **General**: Global settings like log level, data directories, and logging configuration
- **Collectors**: Configure Windows Event log sources and file-based log sources
- **Analyzers**: Define threshold-based rules for detecting security incidents
- **Alerters**: Configure alert delivery methods (console, email)
- **Dashboard**: Configure the web-based dashboard

### Testing

You can run the platform in test mode to generate sample events:

```
python test_siem.py --test-mode random --rate 0.5 --duration 300
```

Or use the Windows batch file:

```
run_test.bat --test-mode random --rate 0.5 --duration 300
```

Test mode options:
- `--test-mode`: Test data generation mode (choices: random, alertable, both)
- `--rate`: Events per second for random generation
- `--duration`: Duration in seconds to run the test (0 for indefinite)
- `--log-level`: Logging level (choices: DEBUG, INFO, WARNING, ERROR)

## Usage

### Dashboard

Once the SIEM platform is running, access the dashboard at:

```
http://localhost:5000
```

The dashboard provides:

- **Home Page**: Overview of security posture with key metrics and charts
- **Events Page**: Detailed event listing with search and filtering
- **Alerts Page**: Security alerts with filtering and event correlation
- **Settings Page**: Configuration overview and management

### Dashboard Features

- **Real-time Updates**: Dashboard automatically refreshes at configurable intervals
- **Dark/Light Mode**: Toggle between dark and light themes for user preference
- **Responsive Design**: Works on desktop and mobile devices
- **Interactive Charts**: Hover and click interactions for detailed information
- **Data Export**: Export events and alerts to CSV format
- **Search and Filter**: Quickly find relevant events and alerts

### Customization

The platform can be extended with:

- **New Collectors**: Add custom collectors for your specific log sources
- **Custom Analyzers**: Implement specialized detection rules and correlation
- **Additional Alerters**: Integrate with your notification systems
- **Dashboard Enhancements**: Add custom views and visualizations

## System Architecture

The Enterprise SIEM Platform is built with a modular, component-based architecture:

1. **Event Class**: Represents security events with severity levels and timestamps
2. **Alert Class**: Represents security alerts generated from events
3. **Collectors**: Gather events from various sources
4. **Analyzers**: Process events to detect security incidents
5. **Alerters**: Deliver alerts through different channels
6. **Dashboard**: Web-based user interface

Data flows through the system as follows:

```
Log Sources → Collectors → Event Queue → Analyzers → Alert Queue → Alerters
                                        ↓                ↓
                                    Dashboard ←────────────
```

## Project Structure

```
enterprise-siem-platform/
├── src/
│   ├── collectors/        # Log collection modules
│   │   ├── __init__.py
│   │   ├── file_collector.py
│   │   └── windows_event_collector.py
│   ├── analyzers/         # Event analysis and correlation
│   │   ├── __init__.py
│   │   └── threshold_analyzer.py
│   ├── alerting/          # Alert generation and delivery
│   │   ├── __init__.py
│   │   ├── console_alerter.py
│   │   └── email_alerter.py
│   ├── dashboard/         # Web interface
│   │   ├── __init__.py
│   │   ├── app.py
│   │   └── templates/
│   ├── utils/             # Utility functions
│   │   ├── __init__.py
│   │   ├── event.py
│   │   ├── alert.py
│   │   ├── config_loader.py
│   │   └── test_data_generator.py
│   ├── config/            # Configuration files
│   │   └── config.yaml
│   └── run_siem.py        # Main entry point
├── docs/                  # Documentation
│   ├── README.md
│   └── DEVELOPER_GUIDE.md
├── examples/              # Example extensions and API usage
│   ├── api_example.py
│   ├── custom_collector_example.py
│   └── run_api_example.bat
├── data/                  # Data storage
├── temp/                  # Temporary files
├── test_siem.py           # Test script
├── run_siem.bat           # Windows batch file
├── run_test.bat           # Windows test batch file
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

## API Usage

The platform provides a programmatic API for integration with other systems:

```python
from src.utils.event import Event
from src.utils.alert import Alert
from src.analyzers.threshold_analyzer import ThresholdAnalyzer
from src.alerting.console_alerter import ConsoleAlerter

# Create a custom event
event = Event(
    source='custom_source',
    event_type='custom_event',
    message='Custom security event detected',
    severity='medium'
)

# Create a custom analyzer
analyzer = ThresholdAnalyzer({
    'rules': [
        {
            'name': 'custom_rule',
            'description': 'Detect custom events',
            'event_type': 'custom_event',
            'threshold': 3,
            'time_window': 60
        }
    ]
})

# Analyze events
alerts = analyzer.analyze_event(event)

# Process alerts
alerter = ConsoleAlerter({})
for alert in alerts:
    alerter.send_alert(alert)
```

See `examples/api_example.py` for a complete demonstration of the API.

## Documentation

For more detailed documentation, see the `docs/` directory:

- [User Guide](docs/README.md) - Comprehensive guide for users and administrators
- [Developer Guide](docs/DEVELOPER_GUIDE.md) - Guide for developers extending the platform

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Developed by [Shadownik](https://github.com/5h4d0wn1k) - Providing enterprise-grade security solutions. 