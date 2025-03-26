# Dashboard API Reference

This document provides detailed information about the API endpoints available in the Enterprise SIEM Platform dashboard.

## Overview

The dashboard includes a RESTful API that allows you to:
- Retrieve events and alerts
- Manage configurations
- Get system status information
- Perform administrative tasks

All API endpoints are accessible at `http://your-server:port/api/`.

## Authentication

### Basic Authentication

When dashboard authentication is enabled, API requests must include authentication credentials.

```
Authorization: Basic <base64-encoded-credentials>
```

Example:
```
Authorization: Basic YWRtaW46YWRtaW4xMjM=
```

### API Token Authentication

You can also use an API token for authentication:

```
Authorization: Bearer <api-token>
```

## API Endpoints

### Events

#### GET /api/events

Retrieve events with optional filtering.

**Parameters:**
- `limit` (optional): Maximum number of events to return (default: 100)
- `offset` (optional): Offset for pagination (default: 0)
- `source` (optional): Filter by source
- `severity` (optional): Filter by severity level
- `event_type` (optional): Filter by event type
- `from_time` (optional): Filter events after this time (ISO format)
- `to_time` (optional): Filter events before this time (ISO format)
- `search` (optional): Search in event message and raw data

**Response:**
```json
{
  "total": 1250,
  "limit": 100,
  "offset": 0,
  "events": [
    {
      "event_id": "e12345",
      "message": "Failed login attempt",
      "source": "windows_event",
      "severity": "medium",
      "event_type": "authentication",
      "timestamp": "2023-05-15T14:30:45.123Z",
      "raw_data": {
        "username": "admin",
        "ip_address": "192.168.1.100",
        "status": "failure"
      }
    },
    // Additional events...
  ]
}
```

#### GET /api/events/{event_id}

Retrieve a specific event by ID.

**Response:**
```json
{
  "event_id": "e12345",
  "message": "Failed login attempt",
  "source": "windows_event",
  "severity": "medium",
  "event_type": "authentication",
  "timestamp": "2023-05-15T14:30:45.123Z",
  "raw_data": {
    "username": "admin",
    "ip_address": "192.168.1.100",
    "status": "failure"
  }
}
```

#### GET /api/events/count

Get event count statistics.

**Parameters:**
- `group_by` (optional): Field to group by (source, severity, event_type)
- `from_time` (optional): Filter events after this time (ISO format)
- `to_time` (optional): Filter events before this time (ISO format)

**Response:**
```json
{
  "total": 1250,
  "groups": {
    "source": {
      "windows_event": 850,
      "file": 350,
      "syslog": 50
    },
    "severity": {
      "low": 600,
      "medium": 450,
      "high": 150,
      "critical": 50
    }
  }
}
```

### Alerts

#### GET /api/alerts

Retrieve alerts with optional filtering.

**Parameters:**
- `limit` (optional): Maximum number of alerts to return (default: 100)
- `offset` (optional): Offset for pagination (default: 0)
- `source` (optional): Filter by source
- `severity` (optional): Filter by severity level
- `rule_name` (optional): Filter by rule name
- `from_time` (optional): Filter alerts after this time (ISO format)
- `to_time` (optional): Filter alerts before this time (ISO format)
- `search` (optional): Search in alert title and message

**Response:**
```json
{
  "total": 145,
  "limit": 100,
  "offset": 0,
  "alerts": [
    {
      "alert_id": "a789",
      "title": "Multiple Failed Logins",
      "message": "5 failed login attempts for user admin",
      "source": "threshold_analyzer",
      "severity": "high",
      "timestamp": "2023-05-15T14:35:12.456Z",
      "rule_name": "failed_login_detection",
      "events": ["e12345", "e12346", "e12347", "e12348", "e12349"]
    },
    // Additional alerts...
  ]
}
```

#### GET /api/alerts/{alert_id}

Retrieve a specific alert by ID.

**Response:**
```json
{
  "alert_id": "a789",
  "title": "Multiple Failed Logins",
  "message": "5 failed login attempts for user admin",
  "source": "threshold_analyzer",
  "severity": "high",
  "timestamp": "2023-05-15T14:35:12.456Z",
  "rule_name": "failed_login_detection",
  "events": [
    {
      "event_id": "e12345",
      "message": "Failed login attempt",
      "source": "windows_event",
      "severity": "medium",
      "event_type": "authentication",
      "timestamp": "2023-05-15T14:30:45.123Z",
      "raw_data": {
        "username": "admin",
        "ip_address": "192.168.1.100",
        "status": "failure"
      }
    },
    // Additional events...
  ]
}
```

#### GET /api/alerts/count

Get alert count statistics.

**Parameters:**
- `group_by` (optional): Field to group by (source, severity, rule_name)
- `from_time` (optional): Filter alerts after this time (ISO format)
- `to_time` (optional): Filter alerts before this time (ISO format)

**Response:**
```json
{
  "total": 145,
  "groups": {
    "severity": {
      "low": 45,
      "medium": 65,
      "high": 30,
      "critical": 5
    },
    "rule_name": {
      "failed_login_detection": 75,
      "suspicious_file_access": 45,
      "command_injection_attempt": 25
    }
  }
}
```

### System Status

#### GET /api/status

Get system status information.

**Response:**
```json
{
  "status": "running",
  "uptime": 86400,
  "version": "1.0.0",
  "started_at": "2023-05-14T14:00:00.000Z",
  "components": {
    "collectors": {
      "windows_event": {
        "status": "running",
        "events_collected": 12500,
        "last_event": "2023-05-15T14:45:00.000Z"
      },
      "file": {
        "status": "running",
        "events_collected": 8500,
        "last_event": "2023-05-15T14:44:30.000Z"
      }
    },
    "analyzers": {
      "threshold": {
        "status": "running",
        "events_analyzed": 21000,
        "alerts_generated": 145
      }
    },
    "alerters": {
      "console": {
        "status": "running",
        "alerts_sent": 145
      },
      "email": {
        "status": "running",
        "alerts_sent": 85,
        "failed_attempts": 0
      }
    }
  },
  "resources": {
    "memory_usage": 128.5,
    "cpu_usage": 15.2,
    "event_queue_size": 12,
    "alert_queue_size": 3
  }
}
```

#### GET /api/status/collectors

Get status of collectors.

**Response:**
```json
{
  "collectors": {
    "windows_event": {
      "status": "running",
      "events_collected": 12500,
      "last_event": "2023-05-15T14:45:00.000Z",
      "config": {
        "channels": ["Security", "System"],
        "poll_interval": 10
      }
    },
    "file": {
      "status": "running",
      "events_collected": 8500,
      "last_event": "2023-05-15T14:44:30.000Z",
      "config": {
        "paths": ["C:/inetpub/logs/LogFiles/*.log"],
        "poll_interval": 5
      }
    }
  }
}
```

#### GET /api/status/analyzers

Get status of analyzers.

**Response:**
```json
{
  "analyzers": {
    "threshold": {
      "status": "running",
      "events_analyzed": 21000,
      "alerts_generated": 145,
      "rules_count": 3,
      "rules": [
        {
          "name": "Multiple Failed Logins",
          "alerts_generated": 75,
          "last_alert": "2023-05-15T14:35:12.456Z"
        },
        // Additional rules...
      ]
    }
  }
}
```

#### GET /api/status/alerters

Get status of alerters.

**Response:**
```json
{
  "alerters": {
    "console": {
      "status": "running",
      "alerts_sent": 145,
      "config": {
        "min_severity": "low"
      }
    },
    "email": {
      "status": "running",
      "alerts_sent": 85,
      "failed_attempts": 0,
      "config": {
        "min_severity": "medium",
        "server": "smtp.example.com"
      }
    }
  }
}
```

### Configuration

#### GET /api/config

Get current configuration (requires admin role).

**Response:**
```json
{
  "general": {
    "instance_name": "Production SIEM",
    "data_dir": "data",
    "temp_dir": "temp",
    "max_events": 10000,
    "max_alerts": 1000
  },
  "collectors": {
    // Collector configurations...
  },
  "analyzers": {
    // Analyzer configurations...
  },
  "alerters": {
    // Alerter configurations...
  },
  "dashboard": {
    // Dashboard configurations...
  }
}
```

#### PUT /api/config

Update configuration (requires admin role).

**Request Body:**
```json
{
  "general": {
    "max_events": 20000,
    "max_alerts": 2000
  },
  "dashboard": {
    "port": 8080,
    "ui": {
      "theme": "light"
    }
  }
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Configuration updated successfully",
  "restart_required": true
}
```

### Administrative

#### POST /api/auth/login

Authenticate with the API and get a token.

**Request Body:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response:**
```json
{
  "status": "success",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_at": "2023-05-16T14:00:00.000Z",
  "user": {
    "username": "admin",
    "role": "admin"
  }
}
```

#### POST /api/auth/logout

Invalidate current token.

**Response:**
```json
{
  "status": "success",
  "message": "Logged out successfully"
}
```

#### POST /api/restart

Restart the SIEM platform (requires admin role).

**Response:**
```json
{
  "status": "success",
  "message": "SIEM platform restarting"
}
```

## Webhook Integration

The SIEM platform can send alerts to external systems using webhooks. To integrate with the webhook alerter, configure an endpoint to receive HTTP POST requests with the following format:

**Alert Webhook Payload:**
```json
{
  "alert_id": "a789",
  "title": "Multiple Failed Logins",
  "message": "5 failed login attempts for user admin",
  "source": "threshold_analyzer",
  "severity": "high",
  "timestamp": "2023-05-15T14:35:12.456Z",
  "rule_name": "failed_login_detection",
  "instance_name": "Production SIEM",
  "events": [
    {
      "event_id": "e12345",
      "message": "Failed login attempt",
      "source": "windows_event",
      "severity": "medium",
      "event_type": "authentication",
      "timestamp": "2023-05-15T14:30:45.123Z",
      "raw_data": {
        "username": "admin",
        "ip_address": "192.168.1.100",
        "status": "failure"
      }
    },
    // Additional events...
  ]
}
```

## Example API Usage

### Python Example

```python
import requests
import json
from datetime import datetime, timedelta

# Base URL
base_url = "http://localhost:5000/api"

# Authentication
username = "admin"
password = "admin123"
auth = (username, password)

# Get events from the last hour
now = datetime.utcnow()
one_hour_ago = now - timedelta(hours=1)
from_time = one_hour_ago.isoformat() + "Z"

params = {
    "limit": 50,
    "severity": "high,critical",
    "from_time": from_time
}

response = requests.get(f"{base_url}/events", auth=auth, params=params)
events = response.json()

print(f"Found {events['total']} events")
for event in events['events']:
    print(f"{event['timestamp']} - {event['severity']} - {event['message']}")

# Get alert statistics
params = {
    "group_by": "severity"
}

response = requests.get(f"{base_url}/alerts/count", auth=auth, params=params)
alert_stats = response.json()

print(f"Total alerts: {alert_stats['total']}")
for severity, count in alert_stats['groups']['severity'].items():
    print(f"{severity}: {count}")
```

### JavaScript Example

```javascript
// Using fetch API
const baseUrl = 'http://localhost:5000/api';
const username = 'admin';
const password = 'admin123';
const authHeader = 'Basic ' + btoa(username + ':' + password);

// Get recent alerts
const getAlerts = async () => {
  const response = await fetch(`${baseUrl}/alerts?limit=10`, {
    headers: {
      'Authorization': authHeader
    }
  });
  
  const data = await response.json();
  console.log(`Found ${data.total} alerts`);
  
  data.alerts.forEach(alert => {
    console.log(`${alert.timestamp} - ${alert.severity} - ${alert.title}`);
  });
};

// Get system status
const getSystemStatus = async () => {
  const response = await fetch(`${baseUrl}/status`, {
    headers: {
      'Authorization': authHeader
    }
  });
  
  const status = await response.json();
  console.log(`System status: ${status.status}`);
  console.log(`Uptime: ${status.uptime} seconds`);
  
  Object.entries(status.components).forEach(([type, components]) => {
    console.log(`${type}:`);
    Object.entries(components).forEach(([name, info]) => {
      console.log(`  ${name}: ${info.status}`);
    });
  });
};

// Call the functions
getAlerts().catch(err => console.error('Error fetching alerts:', err));
getSystemStatus().catch(err => console.error('Error fetching status:', err));
```

## Rate Limiting

API requests are rate-limited to prevent abuse. The default limits are:

- Authenticated requests: 60 requests per minute
- Unauthenticated requests: 10 requests per minute

Rate limit headers are included in the response:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 58
X-RateLimit-Reset: 1683557400
```

When the rate limit is exceeded, a 429 Too Many Requests response is returned.

## Error Handling

All API endpoints use standard HTTP status codes to indicate success or failure:

- 200 OK: Request successful
- 400 Bad Request: Invalid request parameters
- 401 Unauthorized: Authentication failed
- 403 Forbidden: Insufficient permissions
- 404 Not Found: Resource not found
- 429 Too Many Requests: Rate limit exceeded
- 500 Internal Server Error: Server error

Error responses include a JSON body with details:

```json
{
  "status": "error",
  "code": "invalid_parameter",
  "message": "Invalid parameter: severity must be one of low, medium, high, critical",
  "details": {
    "parameter": "severity",
    "value": "invalid",
    "allowed": ["low", "medium", "high", "critical"]
  }
}
``` 