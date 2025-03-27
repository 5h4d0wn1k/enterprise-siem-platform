# AI Module for Enterprise SIEM Platform

This directory contains the AI components for enhancing the Enterprise SIEM Platform with advanced threat detection and data security posture management capabilities.

## Directory Structure

```
src/ai/
├── core/                   # Core AI framework components
│   ├── __init__.py
│   ├── model_registry.py   # Central model management
│   ├── feature_store.py    # Feature extraction and storage
│   └── inference_engine.py # Model inference orchestration
│
├── models/                 # ML model implementations
│   ├── __init__.py
│   ├── anomaly/            # Anomaly detection models
│   │   ├── __init__.py
│   │   ├── statistical.py  # Statistical anomaly detection
│   │   ├── isolation_forest.py
│   │   ├── autoencoder.py
│   │   └── ensemble.py     # Ensemble methods
│   │
│   ├── behavioral/         # Behavioral analysis models
│   │   ├── __init__.py
│   │   ├── uba.py          # User Behavior Analytics
│   │   ├── sequence.py     # Sequential pattern analysis
│   │   ├── graph_models.py # Graph-based analysis
│   │   └── lstm.py         # LSTM sequence models
│   │
│   ├── classification/     # Classification models
│   │   ├── __init__.py
│   │   ├── text_classifier.py
│   │   ├── data_classifier.py
│   │   └── multi_modal.py  # Multi-modal classification
│   │
│   └── correlation/        # Event correlation models
│       ├── __init__.py
│       ├── bayesian.py     # Bayesian correlation networks
│       ├── graph_corr.py   # Graph-based correlation
│       └── temporal.py     # Temporal correlation models
│
├── data/                   # Data processing components
│   ├── __init__.py
│   ├── preprocessing.py    # Data preprocessing pipelines
│   ├── feature_extraction.py
│   ├── encoders.py         # Custom data encoders
│   └── validation.py       # Data quality validation
│
├── dspm/                   # Data Security Posture Management
│   ├── __init__.py
│   ├── discovery.py        # Data discovery engine
│   ├── classification.py   # Data classification
│   ├── access_analytics.py # Access pattern analytics
│   └── flow_monitoring.py  # Data flow monitoring
│
├── training/               # Model training infrastructure
│   ├── __init__.py
│   ├── trainer.py          # Base trainer class
│   ├── pipelines.py        # Training pipelines
│   ├── hyper_param.py      # Hyperparameter optimization
│   └── evaluation.py       # Model evaluation
│
├── integration/            # Integration with existing components
│   ├── __init__.py
│   ├── collectors.py       # Collector integration
│   ├── analyzers.py        # Analyzer integration
│   ├── alerters.py         # Alerter integration
│   └── dashboard.py        # Dashboard integration
│
├── utils/                  # AI-specific utilities
│   ├── __init__.py
│   ├── explainability.py   # Model explanation tools
│   ├── metrics.py          # AI performance metrics
│   ├── visualization.py    # AI result visualization
│   └── config.py           # AI configuration management
│
└── api/                    # API for AI components
    ├── __init__.py
    ├── rest.py             # REST API for AI services
    ├── batch.py            # Batch processing API
    └── stream.py           # Streaming API
```

## Component Overview

### Core Framework

The core framework provides the foundation for all AI capabilities:

- **Model Registry**: Central repository for managing all ML models, including versioning, deployment tracking, and A/B testing capabilities.
- **Feature Store**: Manages feature extraction, storage, and retrieval for both training and inference.
- **Inference Engine**: Orchestrates model inference, including model selection, ensemble methods, and result aggregation.

### Models

The models directory contains implementations of various machine learning approaches:

- **Anomaly Detection**: Models for identifying unusual patterns in security events.
- **Behavioral Analysis**: Models for understanding and profiling entity behaviors.
- **Classification**: Models for categorizing data, events, and security incidents.
- **Correlation**: Models for connecting related events into meaningful attack chains.

### Data Processing

Components for handling data throughout the AI pipeline:

- **Preprocessing**: Data cleaning, normalization, and transformation.
- **Feature Extraction**: Converting raw events into meaningful features for ML models.
- **Encoders**: Custom encoders for different data types.
- **Validation**: Ensuring data quality for both training and inference.

### Data Security Posture Management (DSPM)

Specialized components for implementing DSPM capabilities:

- **Discovery**: Automated tools for discovering and cataloging data.
- **Classification**: Data sensitivity classification models.
- **Access Analytics**: Tools for analyzing data access patterns.
- **Flow Monitoring**: Components for monitoring and analyzing data movement.

### Training Infrastructure

Components for building and training ML models:

- **Trainer**: Base classes for implementing model training.
- **Pipelines**: End-to-end training workflows.
- **Hyperparameter Optimization**: Tools for tuning model parameters.
- **Evaluation**: Framework for assessing model performance.

### Integration

Components that connect AI systems with the existing SIEM platform:

- **Collectors**: Integration with log and event collectors.
- **Analyzers**: Integration with the analysis pipeline.
- **Alerters**: Providing AI-enhanced alerts.
- **Dashboard**: Visualizing AI insights in the dashboard.

### Utilities

Supporting tools for AI components:

- **Explainability**: Tools for explaining model decisions.
- **Metrics**: Custom metrics for AI performance.
- **Visualization**: Custom visualizations for AI results.
- **Config**: Configuration management for AI components.

### API

APIs for interacting with AI components:

- **REST API**: HTTP endpoints for AI services.
- **Batch API**: Tools for batch processing data.
- **Stream API**: Streaming interfaces for real-time analysis.

## Getting Started with Development

1. **Environment Setup**:
   ```bash
   pip install -r requirements-ai.txt
   ```

2. **Model Development**:
   - Extend the base classes in `models/` to implement new techniques
   - Use the training framework in `training/` for model development
   - Validate using the evaluation tools

3. **Integration**:
   - Integrate with existing components using the integration helpers
   - Register models in the model registry for production use
   - Configure the inference engine for your models

4. **Testing**:
   - Unit tests for models in the `tests/ai/` directory
   - Integration tests for AI components
   - Performance benchmarking tools

## Usage Examples

### Basic Model Registration

```python
from src.ai.core.model_registry import ModelRegistry

# Register a new model
model_registry = ModelRegistry()
model_registry.register_model(
    name="user_behavior_lstm",
    version="1.0.0",
    model_path="/path/to/model",
    metadata={
        "description": "User behavior LSTM model",
        "feature_list": ["login_time", "resource_access", "command_seq"],
        "performance": {
            "precision": 0.92,
            "recall": 0.85,
            "f1": 0.88
        }
    }
)

# Retrieve a model for inference
model = model_registry.get_model("user_behavior_lstm", "1.0.0")
```

### Anomaly Detection

```python
from src.ai.models.anomaly.isolation_forest import IsolationForestDetector

# Create a detector
detector = IsolationForestDetector(
    n_estimators=100,
    contamination=0.01,
    feature_names=["request_count", "bytes_sent", "login_failures"]
)

# Train the detector
detector.train(training_data)

# Detect anomalies
anomalies = detector.detect(new_events)
for anomaly in anomalies:
    print(f"Anomaly detected: {anomaly.score} - {anomaly.reason}")
```

### Data Classification

```python
from src.ai.dspm.classification import SensitivityClassifier

# Initialize classifier
classifier = SensitivityClassifier()

# Classify data
results = classifier.classify_data(documents)
for result in results:
    print(f"Document: {result.id}")
    print(f"Classification: {result.sensitivity_level}")
    print(f"Confidence: {result.confidence}")
    print(f"Matched rules: {result.matched_rules}")
```

## Configuration

AI components are configured through a combination of YAML configuration files and environment variables. Key configuration files:

- `ai_config.yaml`: Main configuration for AI components
- `models_config.yaml`: Model-specific configurations
- `feature_store.yaml`: Feature store configuration
- `dspm_config.yaml`: DSPM-specific configuration

## Performance Considerations

- Use batch processing for non-time-critical components
- Enable GPU acceleration for supported models
- Configure caching for frequently used features
- Adjust model complexity based on available resources
- Use the performance monitoring tools in `utils/metrics.py`

## Security Best Practices

- Encrypt sensitive training data
- Implement access controls for model management
- Validate inputs to prevent adversarial attacks
- Audit all model operations
- Regularly review model performance and bias

## Additional Resources

- [Model Development Guide](../docs/model_development.md)
- [Feature Engineering Best Practices](../docs/feature_engineering.md)
- [AI Performance Optimization](../docs/ai_performance.md)
- [DSPM Implementation Guide](../docs/dspm_guide.md) 