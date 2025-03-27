# AI Modules for Enterprise SIEM Platform

**A product of Shadownik**

This document provides a comprehensive overview of the AI capabilities integrated into the Enterprise SIEM Platform, including both the Anomaly Detection and Data Security Posture Management (DSPM) modules.

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [AI-Based Threat Detection](#ai-based-threat-detection)
   - [Isolation Forest for Anomaly Detection](#isolation-forest-for-anomaly-detection)
   - [How Anomaly Detection Works](#how-anomaly-detection-works)
   - [Feature Contribution Analysis](#feature-contribution-analysis)
   - [Integration with Alert System](#integration-with-alert-system)
4. [Data Security Posture Management (DSPM)](#data-security-posture-management-dspm)
   - [Sensitive Data Discovery](#sensitive-data-discovery)
   - [Risk Assessment](#risk-assessment)
   - [Compliance Mapping](#compliance-mapping)
   - [Scheduled Scanning](#scheduled-scanning)
5. [Configuration Options](#configuration-options)
   - [AI Module Configuration](#ai-module-configuration)
   - [DSPM Configuration](#dspm-configuration)
   - [Custom Patterns and Rules](#custom-patterns-and-rules)
6. [Extending AI Capabilities](#extending-ai-capabilities)
   - [Adding New Models](#adding-new-models)
   - [Training Custom Models](#training-custom-models)
   - [Adding Custom Scanners](#adding-custom-scanners)
7. [Performance Considerations](#performance-considerations)
8. [Troubleshooting](#troubleshooting)
9. [Future Development](#future-development)

## Introduction

The AI modules in the Enterprise SIEM Platform enhance security monitoring by providing advanced threat detection through anomaly detection and sensitive data management through DSPM capabilities. These modules work together with the core SIEM functionality to provide a comprehensive security solution.

Key benefits include:

- **Reduced False Positives**: AI-based anomaly detection helps identify truly suspicious behavior by learning normal patterns.
- **Automated Sensitive Data Discovery**: Automatically identify and classify sensitive data across your organization.
- **Explainable Results**: All AI findings include detailed explanations of why certain events or findings were flagged.
- **Continuous Learning**: Models can be retrained over time to adapt to changing environments.
- **Compliance Support**: Direct mapping between findings and compliance frameworks.

## Architecture Overview

The AI functionality is structured into discrete modules:

```
src/ai/
├── core/               # Core AI framework components
│   └── model_registry.py
├── models/             # AI models for various detection tasks
│   └── anomaly/
│       └── isolation_forest.py
├── dspm/               # Data Security Posture Management
│   ├── base_scanner.py
│   ├── file_scanner.py
│   └── dspm_manager.py
├── integration/        # Integration with SIEM components
│   └── siem_integrator.py
├── config/             # Configuration files
│   ├── ai_config.yaml
│   └── dspm_config.yaml
└── examples/           # Example usage
    └── anomaly_detection_example.py
```

The architecture follows these principles:

1. **Modularity**: Each AI capability is built as a separate module that can be enabled/disabled.
2. **Standardized Interfaces**: Common interfaces for models and scanners to allow for easy extension.
3. **SIEM Integration**: Seamless integration with existing alert mechanisms and event processing.
4. **Configurability**: Extensive configuration options for adapting to different environments.

## AI-Based Threat Detection

### Isolation Forest for Anomaly Detection

The primary anomaly detection method used is Isolation Forest, which is particularly effective at identifying outliers in high-dimensional data without requiring extensive training data:

- **Working Principle**: Isolates anomalies by randomly selecting features and split values, building a forest of isolation trees.
- **Advantages**: Works well with high-dimensional data, efficient computation, doesn't require normal distribution.
- **Implementation**: The `IsolationForestDetector` class provides a comprehensive implementation with additional explainability features.

### How Anomaly Detection Works

1. **Feature Extraction**: Security events are processed to extract numerical features for analysis.
2. **Training**: The Isolation Forest model is trained on historical data to learn the normal patterns.
3. **Detection**: New events are scored based on how easily they can be isolated (high scores indicate anomalies).
4. **Explanation**: Anomalous events include an explanation of why they were flagged.
5. **Alerting**: High-scoring anomalies are converted to alerts in the SIEM platform.

Example detection code:

```python
from src.ai.integration.siem_integrator import get_integrator

# Get the integrator
integrator = get_integrator()

# Process events through AI models
integrator.process_events(events)

# The results will be delivered through callbacks
```

### Feature Contribution Analysis

A unique aspect of our anomaly detection implementation is the ability to identify which features contributed most to an anomaly score:

1. **Perturbing Features**: Each feature is adjusted to its mean value to measure its effect on the anomaly score.
2. **Contribution Scoring**: The difference in anomaly scores before and after perturbation indicates contribution.
3. **Reporting**: Top contributing features are included in anomaly explanations.

This provides security analysts with clear insights into why an event was flagged as anomalous.

### Integration with Alert System

Anomaly detection is fully integrated with the SIEM alert system:

1. The AI module processes events through the `siem_integrator.py` component.
2. Detected anomalies above a configurable threshold generate alerts.
3. Alerts include detailed information about the anomaly, including:
   - Event details (source, timestamp, etc.)
   - Anomaly score
   - Reason for the anomaly
   - Contributing factors
   - Severity level derived from the anomaly score

## Data Security Posture Management (DSPM)

The DSPM module provides comprehensive visibility into sensitive data across your organization.

### Sensitive Data Discovery

DSPM scans for sensitive data using pattern matching and AI-based classification:

1. **Pattern-Based Detection**: Uses regular expressions to identify known patterns of sensitive data (SSNs, credit cards, etc.)
2. **Context Analysis**: Evaluates the surrounding context to confirm findings and assess risk
3. **Data Classification**: Categorizes findings according to sensitivity and applicable regulations

The `FileScanner` implementation scans text-based files for sensitive information patterns.

### Risk Assessment

Each finding is automatically assigned a risk level based on:

1. **Data Type**: Different types of sensitive data have inherent risk levels
2. **Confidence Level**: Higher confidence findings have higher risk
3. **Context Factors**: Accessible location, permissions, etc.

The risk levels (low, medium, high, critical) help prioritize remediation efforts.

### Compliance Mapping

DSPM findings are automatically mapped to relevant compliance frameworks:

1. **Framework Definitions**: Configuration defines compliance frameworks like PCI-DSS, GDPR, HIPAA
2. **Data Type Mapping**: Each data type is associated with relevant frameworks
3. **Requirement Tracking**: Specific compliance requirements are linked to findings

This provides a clear view of compliance posture and helps meet regulatory requirements.

### Scheduled Scanning

The DSPM Manager (`dspm_manager.py`) coordinates scanning according to the configured schedule:

1. **Targets Configuration**: Define paths, databases, or other resources to scan
2. **Scheduling**: Configure how often each target should be scanned (hourly, daily, weekly, monthly)
3. **Scan Execution**: Scans run in background threads to avoid impacting performance
4. **Result Processing**: Findings are processed, stored, and can generate alerts based on severity

Example for manually triggering a scan:

```python
from src.ai.dspm.dspm_manager import get_dspm_manager

# Get the DSPM manager
dspm_manager = get_dspm_manager()

# Run a scan on a specific path
result = dspm_manager.run_scan("/path/to/scan")

# Access findings
for finding in result.findings:
    print(f"Found {finding.data_type} in {finding.location} with risk {finding.risk_level}")
```

## Configuration Options

### AI Module Configuration

The AI module configuration (`ai_config.yaml`) includes options for:

- **Models**: Configure anomaly detection models (isolation_forest, etc.)
- **Processing**: Batch size, intervals, queue limits
- **Integration**: Alert thresholds, result storage
- **Maintenance**: Model update frequency, training data retention
- **Logging**: Logging level and metrics

Example configuration excerpt:

```yaml
models:
  anomaly_detection:
    enabled: true
    model_type: isolation_forest
    model_path: models/anomaly/isolation_forest_model.pkl
    threshold: 0.85
    features:
      - login_attempt_count
      - session_duration
      - bytes_transferred
      # ... other features
```

### DSPM Configuration

The DSPM configuration (`dspm_config.yaml`) includes:

- **Scanners**: File scanner, database scanner configurations
- **Targets**: What to scan and how often
- **Sensitive Data Types**: What types of data to look for
- **Alerting**: When and how to generate alerts
- **Compliance**: Define compliance frameworks and requirements

Example configuration excerpt:

```yaml
scanners:
  file_scanner:
    enabled: true
    max_file_size: 10485760  # 10MB
    excluded_dirs: 
      - .git
      - node_modules
    # ... other settings
    
targets:
  - name: "source_code"
    path: "./src"
    scanner: "file_scanner"
    recursive: true
    schedule: "daily"
```

### Custom Patterns and Rules

Both modules support custom extensions:

- **Custom Data Patterns**: Add new patterns for sensitive data detection
- **Custom Anomaly Features**: Configure which features to extract from events
- **Threshold Adjustments**: Fine-tune sensitivity for different use cases

## Extending AI Capabilities

### Adding New Models

The AI framework is designed for extensibility:

1. Create a new model class implementing the required interface
2. Register the model in the `model_registry.py`
3. Add appropriate configuration in `ai_config.yaml`

### Training Custom Models

Models can be trained on your specific environment:

```python
from src.ai.integration.siem_integrator import get_integrator

# Get the integrator
integrator = get_integrator()

# Train a model with your events
integrator.train_model("anomaly_detection", training_events, save_model=True)
```

### Adding Custom Scanners

The DSPM framework allows for custom scanners:

1. Create a new scanner class inheriting from `BaseScanner`
2. Implement the required methods (especially `scan()`)
3. Register the scanner in the DSPM manager
4. Add configuration in `dspm_config.yaml`

## Performance Considerations

The AI modules are designed for efficiency:

- **Batch Processing**: Events are processed in batches to optimize throughput
- **Configurable Resource Usage**: Thread counts, batch sizes, and other parameters can be tuned
- **Selective Scanning**: DSPM scanners can exclude irrelevant files/directories
- **Caching**: Model results can be cached to avoid repeated computation

## Troubleshooting

Common issues and solutions:

| Issue | Possible Cause | Solution |
|-------|---------------|----------|
| High false positive rate | Model threshold too low | Increase the anomaly threshold in config |
| Missing sensitive data | Pattern not defined | Add custom patterns for specific data types |
| High CPU usage | Too many concurrent scans | Adjust worker count and batch size |
| Model not learning | Insufficient training data | Collect more representative training data |
| Slow scanning performance | Scanning large files | Adjust excluded files/directories or max file size |

## Future Development

Planned enhancements for the AI modules:

1. **Behavioral Analysis Models**: Sequence-based models for detecting unusual activity patterns
2. **Natural Language Processing**: Enhanced sensitive data detection in unstructured text
3. **Reinforcement Learning**: Adaptive models that learn from analyst feedback
4. **Federated Learning**: Distributed training across multiple deployments
5. **Advanced Visualization**: Interactive explanations of AI findings
6. **Auto-remediation**: Automated actions for certain types of findings

---

For more information or to contribute to the development of the AI modules, please contact the Shadownik team or visit our [GitHub repository](https://github.com/5h4d0wn1k/enterprise-siem-platform). 