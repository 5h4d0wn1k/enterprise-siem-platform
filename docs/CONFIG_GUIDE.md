# Configuration Guide

This document provides detailed information about the configuration options available for the Enterprise SIEM Platform.

## Configuration File Structure

The configuration file is in YAML format and consists of the following main sections:

- `general`: Global settings for the platform
- `collectors`: Settings for various log and event collectors
- `analyzers`: Settings for event analysis components
- `alerters`: Settings for alert notification systems
- `dashboard`: Settings for the web dashboard

## General Settings

```yaml
general:
  # Name of this SIEM instance
  instance_name: "Production SIEM"
  
  # Data directory for storing logs and other data
  data_dir: "data"
  
  # Temp directory for storing temporary files
  temp_dir: "temp"
  
  # Maximum number of events to keep in memory
  max_events: 10000
  
  # Maximum number of alerts to keep in memory
  max_alerts: 1000
  
  # Time zone settings (default: system time zone)
  timezone: "UTC"
```

## Collectors

### Windows Event Collector

Collects events from the Windows Event Log.

```yaml
collectors:
  windows_event:
    # Enable/disable this collector
    enable: true
    
    # Event log channels to monitor
    channels:
      - "Security"
      - "System"
      - "Application"
    
    # Specific event IDs to collect (empty = all)
    event_ids:
      - 4624  # Successful login
      - 4625  # Failed login
      - 4720  # User account created
    
    # Filter by keywords (optional)
    keywords:
      - "failure"
      - "audit"
    
    # Filter by level (optional): Critical, Error, Warning, Information, Verbose
    levels:
      - "Error"
      - "Warning"
    
    # Number of events to collect in each batch
    batch_size: 100
    
    # Interval in seconds between checks for new events
    poll_interval: 10
```

### File Collector

Collects events from log files.

```yaml
collectors:
  file:
    # Enable/disable this collector
    enable: true
    
    # Paths to log files to monitor
    paths:
      - "/var/log/apache2/access.log"
      - "/var/log/auth.log"
      - "C:/inetpub/logs/LogFiles/*.log"
    
    # Regular expression pattern to match log entries
    pattern: ".*"
    
    # Follow files (tail mode)
    follow: true
    
    # File encoding
    encoding: "utf-8"
    
    # Polling interval in seconds
    poll_interval: 5
    
    # Max file size to read at once (bytes)
    max_read_size: 8192
```

### Syslog Collector

Collects events from a Syslog server.

```yaml
collectors:
  syslog:
    # Enable/disable this collector
    enable: false
    
    # Bind address for the Syslog server
    bind_address: "0.0.0.0"
    
    # Port to listen on
    port: 514
    
    # Protocol (udp or tcp)
    protocol: "udp"
    
    # Maximum message size
    max_size: 8192
```

### API Collector

Collects events from a REST API.

```yaml
collectors:
  api:
    # Enable/disable this collector
    enable: false
    
    # API endpoint URL
    url: "https://api.example.com/events"
    
    # HTTP method
    method: "GET"
    
    # Authentication type (none, basic, token, oauth)
    auth_type: "token"
    
    # Authentication credentials
    auth:
      username: "api_user"
      password: "api_password"
      token: "api_token"
    
    # Headers to include in the request
    headers:
      Content-Type: "application/json"
      Accept: "application/json"
    
    # Request parameters
    params:
      limit: 100
    
    # Field containing the events in the response
    events_field: "data"
    
    # Polling interval in seconds
    poll_interval: 60
```

## Analyzers

### Threshold Analyzer

Analyzes events based on threshold conditions.

```yaml
analyzers:
  threshold:
    # Enable/disable this analyzer
    enable: true
    
    # Rules for threshold analysis
    rules:
      - name: "Multiple Failed Logins"
        description: "Detects multiple failed login attempts for a single user"
        # Event type to match
        event_type: "authentication"
        # Field to track
        field: "username"
        # Condition (count, unique, ratio, match, range)
        condition: "count"
        # Threshold value
        threshold: 5
        # Time window in seconds
        time_window: 300
        # Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
        severity: "HIGH"
      
      - name: "Suspicious File Access"
        description: "Detects access to sensitive files"
        event_type: "file_access"
        field: "path"
        condition: "match"
        patterns:
          - "/etc/passwd"
          - "/etc/shadow"
          - "C:\\Windows\\System32\\config\\SAM"
        severity: "MEDIUM"
      
      - name: "System Outage Rate"
        description: "Detects high rate of system outages"
        event_type: "system"
        field: "status"
        condition: "ratio"
        value: "down"
        ratio: 0.5
        time_window: 600
        min_sample: 10
        severity: "CRITICAL"
```

### Correlation Analyzer

Analyzes correlated events.

```yaml
analyzers:
  correlation:
    # Enable/disable this analyzer
    enable: true
    
    # Rules for correlation analysis
    rules:
      - name: "Successful Login After Multiple Failures"
        description: "Detects a successful login after multiple failures"
        # First condition
        first:
          event_type: "authentication"
          field: "status"
          value: "failure"
          count: 3
          window: 300
        # Follow-up condition
        followed_by:
          event_type: "authentication"
          field: "status"
          value: "success"
          window: 60
        # Group events by field
        group_by: "username"
        # Alert severity
        severity: "HIGH"
```

### Pattern Analyzer

Analyzes events based on patterns.

```yaml
analyzers:
  pattern:
    # Enable/disable this analyzer
    enable: true
    
    # Rules for pattern matching
    rules:
      - name: "Command Injection Attempt"
        description: "Detects potential command injection in web requests"
        event_type: "web_request"
        field: "url"
        patterns:
          - ";.*\\s"
          - "\\|.*\\s"
          - "`.*`"
        regex: true
        case_sensitive: false
        severity: "HIGH"
```

## Alerters

### Console Alerter

Sends alerts to the console.

```yaml
alerters:
  console:
    # Enable/disable this alerter
    enable: true
    
    # Minimum severity level to alert on
    min_severity: "LOW"
    
    # Include details of events in the alert
    include_events: true
    
    # Format for console output (text, json)
    format: "text"
    
    # Color-coded output
    color: true
```

### Email Alerter

Sends alerts via email.

```yaml
alerters:
  email:
    # Enable/disable this alerter
    enable: true
    
    # SMTP server settings
    server: "smtp.example.com"
    port: 587
    use_tls: true
    username: "alerts@example.com"
    password: "your-password-here"
    
    # Email settings
    from_address: "alerts@example.com"
    to_addresses:
      - "admin@example.com"
      - "security@example.com"
    
    # Minimum severity level to alert on
    min_severity: "MEDIUM"
    
    # Include details of events in the alert
    include_events: true
    
    # Subject template for emails
    subject_template: "[SIEM Alert] {severity}: {title}"
    
    # Throttling to avoid email floods
    throttle:
      enable: true
      max_alerts: 10
      time_window: 300
      summary_subject: "[SIEM] Alert Summary - {count} alerts in the last {window} seconds"
```

### Webhook Alerter

Sends alerts to a webhook endpoint.

```yaml
alerters:
  webhook:
    # Enable/disable this alerter
    enable: false
    
    # Webhook URL
    url: "https://hooks.example.com/siem/alerts"
    
    # HTTP method
    method: "POST"
    
    # Authentication type (none, basic, token)
    auth_type: "token"
    
    # Authentication credentials
    auth:
      token: "webhook_token"
    
    # Headers to include in the request
    headers:
      Content-Type: "application/json"
    
    # Minimum severity level to alert on
    min_severity: "HIGH"
    
    # Include details of events in the alert
    include_events: true
    
    # Retry settings for failed requests
    retry:
      enable: true
      max_retries: 3
      retry_delay: 5
```

### Slack Alerter

Sends alerts to a Slack channel.

```yaml
alerters:
  slack:
    # Enable/disable this alerter
    enable: false
    
    # Webhook URL for Slack
    webhook_url: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    
    # Channel to post to (overrides the webhook default if specified)
    channel: "#security-alerts"
    
    # Username to post as
    username: "SIEM Alert"
    
    # Emoji icon for the bot
    icon_emoji: ":warning:"
    
    # Minimum severity level to alert on
    min_severity: "MEDIUM"
    
    # Include details of events in the alert
    include_events: true
    
    # Message template
    template: "*{severity}*: {title}\n{message}"
    
    # Throttling to avoid channel floods
    throttle:
      enable: true
      max_alerts: 5
      time_window: 300
```

## Dashboard

Settings for the web dashboard.

```yaml
dashboard:
  # Enable/disable the dashboard
  enable: true
  
  # Host to bind to
  host: "0.0.0.0"
  
  # Port to listen on
  port: 5000
  
  # Use HTTPS
  use_https: false
  
  # Certificate and key files for HTTPS
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
  
  # Authentication settings
  auth:
    enable: false
    method: "basic"  # basic, ldap, oauth
    users:
      - username: "admin"
        password: "admin123"
        role: "admin"
      - username: "user"
        password: "user123"
        role: "viewer"
  
  # Session settings
  session:
    secret_key: "change-this-to-a-random-string"
    timeout: 3600  # seconds
  
  # UI settings
  ui:
    # Title for the dashboard
    title: "Enterprise SIEM Platform"
    
    # Default theme (light, dark)
    theme: "dark"
    
    # Refresh interval in seconds
    refresh_interval: 30
    
    # Maximum events to display
    max_events: 1000
    
    # Maximum alerts to display
    max_alerts: 500
    
    # Charts to display on the dashboard
    charts:
      - type: "bar"
        title: "Events by Source"
        field: "source"
        limit: 10
      
      - type: "pie"
        title: "Alerts by Severity"
        field: "severity"
      
      - type: "line"
        title: "Events Over Time"
        field: "timestamp"
        interval: "hour"
        window: 24
```

## Complete Example

Here's a complete configuration example with all sections:

```yaml
general:
  instance_name: "Production SIEM"
  data_dir: "data"
  temp_dir: "temp"
  max_events: 10000
  max_alerts: 1000
  timezone: "UTC"

collectors:
  windows_event:
    enable: true
    channels:
      - "Security"
      - "System"
    event_ids:
      - 4624
      - 4625
    batch_size: 100
    poll_interval: 10
  
  file:
    enable: true
    paths:
      - "C:/inetpub/logs/LogFiles/*.log"
      - "C:/Windows/System32/Winevt/Logs/Application.evtx"
    pattern: ".*"
    follow: true
    encoding: "utf-8"
    poll_interval: 5

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

alerters:
  console:
    enable: true
    min_severity: "LOW"
    include_events: true
    format: "text"
    color: true
  
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
    min_severity: "MEDIUM"
    include_events: true

dashboard:
  enable: true
  host: "0.0.0.0"
  port: 5000
  use_https: false
  auth:
    enable: false
  ui:
    title: "Enterprise SIEM Platform"
    theme: "dark"
    refresh_interval: 30
```

## Configuration Tips

1. **Start Simple**: Begin with a minimal configuration and add components as needed.
2. **Test Configuration**: Use the `test_siem.py` script to test your configuration.
3. **Security**: 
   - Store sensitive information like passwords in environment variables.
   - Use HTTPS for the dashboard in production.
   - Enable authentication for the dashboard in production.
4. **Performance**:
   - Adjust `poll_interval` values based on your environment.
   - Limit the number of events collected by using specific `event_ids` and `channels`.
   - Use appropriate `batch_size` values to balance between responsiveness and efficiency.
5. **Monitoring**: Set up the email alerter to monitor the health of the SIEM platform itself.

## Environment Variables

You can override configuration values using environment variables. The format is:

```
SIEM_SECTION_SUBSECTION_KEY=value
```

For example:
- `SIEM_GENERAL_MAX_EVENTS=20000`
- `SIEM_DASHBOARD_PORT=8080`
- `SIEM_ALERTERS_EMAIL_PASSWORD=secret123`

Environment variables take precedence over values in the configuration file. 