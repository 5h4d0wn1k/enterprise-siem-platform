# Enterprise SIEM Platform Documentation

Welcome to the Enterprise SIEM Platform documentation. This documentation provides comprehensive information about installation, configuration, usage, and development of the platform.

**A product of Shadownik** - [GitHub: 5h4d0wn1k](https://github.com/5h4d0wn1k)

## Getting Started

- [README](README.md) - Overview and getting started guide
- [Quick Reference Guide](QUICK_REFERENCE.md) - Common commands and operations
- [Developer Guide](DEVELOPER_GUIDE.md) - Guide for developers

## Reference Documentation

- [CLI Reference](CLI_REFERENCE.md) - Command-line interface options
- [Configuration Guide](CONFIG_GUIDE.md) - Configuration options
- [Dashboard API](DASHBOARD_API.md) - API endpoint documentation

## System Architecture

The Enterprise SIEM Platform is designed with a modular architecture that consists of several components:

1. **Log Collectors** - Collect logs from various sources
2. **Event Queue** - Buffer for collected events
3. **Event Analyzers** - Analyze events for potential security threats
4. **Alert Queue** - Buffer for generated alerts
5. **Alerters** - Notify about detected security threats
6. **Dashboard** - Web interface for monitoring and configuration

Here's a simplified flow diagram:

```
┌───────────────┐     ┌─────────────┐     ┌───────────────┐     ┌────────────┐     ┌───────────┐
│ Log Collectors│────>│ Event Queue │────>│ Event Analyzers│────>│ Alert Queue│────>│ Alerters  │
└───────────────┘     └─────────────┘     └───────────────┘     └────────────┘     └───────────┘
                                                                       │
                                                                       │
                                                                       ▼
                                                                 ┌───────────┐
                                                                 │ Dashboard │
                                                                 └───────────┘
```

## Examples

### Example Configuration

```yaml
general:
  instance_name: "Production SIEM"
  data_dir: "data"
  max_events: 10000

collectors:
  windows_event:
    enable: true
    channels:
      - "Security"
      - "System"

analyzers:
  threshold:
    enable: true
    rules:
      - name: "Multiple Failed Logins"
        description: "Detects multiple failed login attempts"
        event_type: "authentication"
        field: "username"
        condition: "count"
        threshold: 5
        time_window: 300
        severity: "HIGH"

alerters:
  console:
    enable: true
    min_severity: "LOW"
  
  email:
    enable: true
    server: "smtp.example.com"
    to_addresses:
      - "security@example.com"
    min_severity: "MEDIUM"

dashboard:
  enable: true
  port: 5000
```

### Example Usage

Run the platform with default settings:
```bash
python src/run_siem.py
```

Run in test mode with generated events:
```bash
python test_siem.py --test-mode both --rate 1.0 --duration 300
```

## Support and Feedback

For issues, feature requests, or feedback, please create an issue in the project repository at [github.com/5h4d0wn1k/enterprise-siem-platform](https://github.com/5h4d0wn1k/enterprise-siem-platform).

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Developed by [Shadownik](https://github.com/5h4d0wn1k) - Providing enterprise-grade security solutions. 