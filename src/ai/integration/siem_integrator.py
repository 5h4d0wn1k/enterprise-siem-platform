"""
SIEM AI Integrator

This module serves as a bridge between the core SIEM platform and the AI components.
It provides a unified interface for the SIEM platform to utilize AI capabilities
for advanced threat detection, data security posture management, and other AI-enhanced
security functions.
"""

import os
import sys
import logging
import threading
import queue
import time
import json
from typing import Dict, List, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass
import datetime
import importlib

# Import from src.utils
from src.utils.event import Event
from src.utils.alert import Alert
from src.utils.config_loader import ConfigLoader


class AIModelNotFoundError(Exception):
    """Exception raised when an AI model is not found."""
    pass


class AIModelNotLoadedError(Exception):
    """Exception raised when an AI model has not been loaded."""
    pass


@dataclass
class AIResult:
    """Result from an AI operation."""
    model_name: str
    result_type: str
    result_data: Dict[str, Any]
    timestamp: datetime.datetime = datetime.datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "model_name": self.model_name,
            "result_type": self.result_type,
            "result_data": self.result_data,
            "timestamp": self.timestamp.isoformat()
        }


class SIEMIntegrator:
    """
    Integrates AI capabilities with the SIEM platform.
    
    This class handles:
    - Loading and managing AI models
    - Processing events through AI models
    - Converting AI results to SIEM alerts
    - Providing a consistent interface for the SIEM platform
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the SIEM AI Integrator.
        
        Args:
            config_path: Path to the AI configuration file
        """
        self.logger = logging.getLogger(__name__)
        self.config_path = config_path
        
        # Initialize configuration
        self.config = self._load_config()
        
        # Dictionary to store loaded models
        self.models = {}
        
        # Event processing queue and thread
        self.event_queue = queue.Queue()
        self.processing_thread = None
        self.should_stop = threading.Event()
        
        # Callbacks
        self.alert_callback = None
        self.result_callback = None
        
        # Load models specified in configuration
        self._load_models()
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Load the AI configuration.
        
        Returns:
            Configuration dictionary
        """
        if not self.config_path:
            self.config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "config/ai_config.yaml"
            )
        
        try:
            config_loader = ConfigLoader()
            config = config_loader.load_config(self.config_path)
            self.logger.info(f"Loaded AI configuration from {self.config_path}")
            return config
        except Exception as e:
            self.logger.error(f"Failed to load AI configuration: {str(e)}")
            # Return default configuration
            return {
                "models": {
                    "anomaly_detection": {
                        "enabled": True,
                        "model_type": "isolation_forest",
                        "model_path": "models/anomaly/isolation_forest_model.pkl",
                        "threshold": 0.85,
                        "batch_size": 100
                    },
                    "data_classification": {
                        "enabled": False,
                        "model_type": "text_classifier",
                        "model_path": "models/classification/data_classifier_model.pkl"
                    }
                },
                "processing": {
                    "batch_size": 100,
                    "processing_interval": 5,  # seconds
                    "max_queue_size": 10000
                },
                "integration": {
                    "alert_on_anomaly": True,
                    "min_anomaly_score": 0.8,
                    "store_ai_results": True
                }
            }
    
    def _load_models(self) -> None:
        """Load AI models specified in the configuration."""
        if "models" not in self.config:
            self.logger.warning("No models specified in configuration")
            return
        
        for model_name, model_config in self.config["models"].items():
            if not model_config.get("enabled", True):
                self.logger.info(f"Model {model_name} is disabled, skipping")
                continue
            
            try:
                self._load_model(model_name, model_config)
            except Exception as e:
                self.logger.error(f"Failed to load model {model_name}: {str(e)}")
    
    def _load_model(self, model_name: str, model_config: Dict[str, Any]) -> None:
        """
        Load a specific AI model.
        
        Args:
            model_name: Name of the model
            model_config: Model configuration
        """
        model_type = model_config.get("model_type")
        model_path = model_config.get("model_path")
        
        if not model_type:
            self.logger.error(f"No model_type specified for {model_name}")
            return
        
        if not model_path:
            self.logger.error(f"No model_path specified for {model_name}")
            return
        
        # Convert relative path to absolute path
        if not os.path.isabs(model_path):
            model_path = os.path.abspath(os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "..",
                model_path
            ))
        
        # Import the appropriate model module
        try:
            # Dynamically import the model class based on model_type
            if model_type == "isolation_forest":
                from src.ai.models.anomaly.isolation_forest import IsolationForestDetector
                model_class = IsolationForestDetector
            elif model_type == "text_classifier":
                # This is a placeholder - implement the actual import
                self.logger.warning(f"Text classifier not yet implemented")
                return
            else:
                self.logger.error(f"Unknown model type: {model_type}")
                return
            
            # Check if model file exists
            if not os.path.exists(model_path):
                self.logger.warning(
                    f"Model file {model_path} not found for {model_name}. "
                    f"The model will need to be trained before use."
                )
                # Create a new model instance without loading
                model = model_class()
            else:
                # Load the model
                model = model_class.load(model_path)
                self.logger.info(f"Loaded model {model_name} from {model_path}")
            
            # Store the model
            self.models[model_name] = {
                "instance": model,
                "config": model_config,
                "type": model_type,
                "path": model_path,
                "last_used": None
            }
            
        except ImportError as e:
            self.logger.error(f"Failed to import model module for {model_type}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Failed to load model {model_name}: {str(e)}")
    
    def start_processing(self) -> None:
        """Start the event processing thread."""
        if self.processing_thread is not None and self.processing_thread.is_alive():
            self.logger.warning("Processing thread is already running")
            return
        
        self.should_stop.clear()
        self.processing_thread = threading.Thread(
            target=self._processing_loop,
            daemon=True
        )
        self.processing_thread.start()
        self.logger.info("Started AI event processing thread")
    
    def stop_processing(self) -> None:
        """Stop the event processing thread."""
        if self.processing_thread is None or not self.processing_thread.is_alive():
            self.logger.warning("Processing thread is not running")
            return
        
        self.should_stop.set()
        self.processing_thread.join(timeout=10)
        if self.processing_thread.is_alive():
            self.logger.warning("Processing thread did not terminate gracefully")
        else:
            self.logger.info("Stopped AI event processing thread")
        self.processing_thread = None
    
    def _processing_loop(self) -> None:
        """Main event processing loop."""
        batch_size = self.config.get("processing", {}).get("batch_size", 100)
        processing_interval = self.config.get("processing", {}).get("processing_interval", 5)
        
        while not self.should_stop.is_set():
            try:
                # Process events in batches
                batch = []
                try:
                    # Get events from the queue
                    while len(batch) < batch_size:
                        try:
                            event = self.event_queue.get(block=False)
                            batch.append(event)
                            self.event_queue.task_done()
                        except queue.Empty:
                            break
                except Exception as e:
                    self.logger.error(f"Error getting events from queue: {str(e)}")
                
                # If we have events to process
                if batch:
                    self.logger.debug(f"Processing batch of {len(batch)} events")
                    self._process_event_batch(batch)
                
                # Sleep for the processing interval
                time.sleep(processing_interval)
            except Exception as e:
                self.logger.error(f"Error in processing loop: {str(e)}")
    
    def _process_event_batch(self, events: List[Event]) -> None:
        """
        Process a batch of events through all enabled models.
        
        Args:
            events: List of events to process
        """
        for model_name, model_info in self.models.items():
            if not self.config.get("models", {}).get(model_name, {}).get("enabled", True):
                continue
            
            try:
                model_instance = model_info["instance"]
                model_type = model_info["type"]
                
                # Update last used timestamp
                model_info["last_used"] = datetime.datetime.now()
                
                # Process based on model type
                if model_type == "isolation_forest":
                    # Run anomaly detection
                    results = model_instance.detect(events)
                    
                    # Process the results
                    self._process_anomaly_results(model_name, results, events)
                
                # Add other model types here
            except Exception as e:
                self.logger.error(f"Error processing events with model {model_name}: {str(e)}")
    
    def _process_anomaly_results(
        self, 
        model_name: str, 
        results: List[Any], 
        events: List[Event]
    ) -> None:
        """
        Process anomaly detection results.
        
        Args:
            model_name: Name of the model
            results: List of anomaly results
            events: Original events
        """
        # Get alert configuration
        alert_on_anomaly = self.config.get("integration", {}).get("alert_on_anomaly", True)
        min_anomaly_score = self.config.get("integration", {}).get("min_anomaly_score", 0.8)
        
        # Map of event IDs to events
        event_map = {event.id: event for event in events}
        
        for result in results:
            # Only process if it's an anomaly
            if not result.is_anomaly:
                continue
            
            # Only alert if score is above threshold
            if result.score < min_anomaly_score:
                continue
            
            # Create AI result
            ai_result = AIResult(
                model_name=model_name,
                result_type="anomaly",
                result_data=result.to_dict()
            )
            
            # Call result callback if set
            if self.result_callback:
                try:
                    self.result_callback(ai_result)
                except Exception as e:
                    self.logger.error(f"Error in result callback: {str(e)}")
            
            # Create alert if configured
            if alert_on_anomaly and self.alert_callback:
                try:
                    # Get original event
                    event = event_map.get(result.event_id)
                    if not event:
                        self.logger.warning(f"Event {result.event_id} not found for alert creation")
                        continue
                    
                    # Create alert
                    alert = self._create_alert_from_anomaly(result, event)
                    
                    # Call alert callback
                    self.alert_callback(alert)
                except Exception as e:
                    self.logger.error(f"Error creating alert from anomaly: {str(e)}")
    
    def _create_alert_from_anomaly(self, anomaly_result: Any, event: Event) -> Alert:
        """
        Create an alert from an anomaly result.
        
        Args:
            anomaly_result: Anomaly detection result
            event: Original event
            
        Returns:
            Alert object
        """
        # Extract information from the event
        if hasattr(event, "raw_data") and event.raw_data:
            source_ip = event.raw_data.get("source_ip", "unknown")
            user = event.raw_data.get("user", "unknown")
            source = event.raw_data.get("source", event.source)
        else:
            source_ip = "unknown"
            user = "unknown"
            source = event.source
        
        # Create alert title
        title = f"AI Anomaly Detected: {anomaly_result.reason}"
        
        # Create detailed message
        message = (
            f"AI-based anomaly detection identified unusual behavior.\n\n"
            f"Details:\n"
            f"- Event ID: {event.id}\n"
            f"- Source: {source}\n"
            f"- User: {user}\n"
            f"- Source IP: {source_ip}\n"
            f"- Anomaly Score: {anomaly_result.score:.2f}\n"
            f"- Reason: {anomaly_result.reason}\n\n"
            f"Top Contributing Factors:\n"
        )
        
        # Add top contributing factors
        sorted_contribs = sorted(
            anomaly_result.feature_contributions.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:5]
        
        for feature, contrib in sorted_contribs:
            if contrib > 0:
                feature_value = anomaly_result.features.get(feature, "N/A")
                message += f"- {feature}: {feature_value} (contribution: {contrib:.2f})\n"
        
        # Set severity based on anomaly score
        if anomaly_result.score >= 0.95:
            severity = "critical"
        elif anomaly_result.score >= 0.9:
            severity = "high"
        elif anomaly_result.score >= 0.8:
            severity = "medium"
        else:
            severity = "low"
        
        # Create the alert
        alert = Alert(
            title=title,
            message=message,
            source="ai_module",
            severity=severity,
            rule_name="AI Anomaly Detection",
            events=[event],
            raw_data={
                "ai_result": anomaly_result.to_dict(),
                "model_name": "anomaly_detection",
                "result_type": "anomaly"
            }
        )
        
        return alert
    
    def process_event(self, event: Event) -> None:
        """
        Process an event through the AI models.
        
        This method adds the event to the processing queue.
        
        Args:
            event: Event to process
        """
        max_queue_size = self.config.get("processing", {}).get("max_queue_size", 10000)
        
        if self.event_queue.qsize() >= max_queue_size:
            self.logger.warning(
                f"Event queue is full ({self.event_queue.qsize()} items), "
                f"dropping new event"
            )
            return
        
        self.event_queue.put(event)
    
    def process_events(self, events: List[Event]) -> None:
        """
        Process multiple events through the AI models.
        
        This method adds the events to the processing queue.
        
        Args:
            events: List of events to process
        """
        for event in events:
            self.process_event(event)
    
    def set_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        """
        Set a callback function for alerts.
        
        Args:
            callback: Function to call with alerts
        """
        self.alert_callback = callback
    
    def set_result_callback(self, callback: Callable[[AIResult], None]) -> None:
        """
        Set a callback function for AI results.
        
        Args:
            callback: Function to call with AI results
        """
        self.result_callback = callback
    
    def get_model_info(self, model_name: str) -> Dict[str, Any]:
        """
        Get information about a loaded model.
        
        Args:
            model_name: Name of the model
            
        Returns:
            Model information dictionary
            
        Raises:
            AIModelNotFoundError: If the model is not loaded
        """
        if model_name not in self.models:
            raise AIModelNotFoundError(f"Model {model_name} not found")
        
        model_info = self.models[model_name]
        return {
            "type": model_info["type"],
            "path": model_info["path"],
            "config": model_info["config"],
            "last_used": model_info["last_used"]
        }
    
    def get_all_model_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about all loaded models.
        
        Returns:
            Dictionary mapping model names to model information
        """
        return {
            model_name: {
                "type": model_info["type"],
                "path": model_info["path"],
                "config": model_info["config"],
                "last_used": model_info["last_used"]
            }
            for model_name, model_info in self.models.items()
        }
    
    def run_manual_detection(
        self, 
        events: List[Event], 
        model_name: str = "anomaly_detection"
    ) -> List[Any]:
        """
        Manually run detection on events.
        
        This method bypasses the processing queue and directly processes
        the events with the specified model.
        
        Args:
            events: List of events to process
            model_name: Name of the model to use
            
        Returns:
            List of detection results
            
        Raises:
            AIModelNotFoundError: If the model is not loaded
            AIModelNotLoadedError: If the model instance is not available
        """
        if model_name not in self.models:
            raise AIModelNotFoundError(f"Model {model_name} not found")
        
        model_info = self.models[model_name]
        model_instance = model_info["instance"]
        
        if not model_instance:
            raise AIModelNotLoadedError(f"Model {model_name} not loaded")
        
        # Update last used timestamp
        model_info["last_used"] = datetime.datetime.now()
        
        # Process based on model type
        if model_info["type"] == "isolation_forest":
            # Run anomaly detection
            results = model_instance.detect(events)
            return results
        
        # Add other model types here
        
        raise ValueError(f"Unsupported model type: {model_info['type']}")
    
    def train_model(
        self, 
        model_name: str, 
        training_events: List[Event],
        save_model: bool = True
    ) -> None:
        """
        Train a model on events.
        
        Args:
            model_name: Name of the model to train
            training_events: List of events for training
            save_model: Whether to save the model after training
            
        Raises:
            AIModelNotFoundError: If the model is not loaded
            AIModelNotLoadedError: If the model instance is not available
        """
        if model_name not in self.models:
            raise AIModelNotFoundError(f"Model {model_name} not found")
        
        model_info = self.models[model_name]
        model_instance = model_info["instance"]
        
        if not model_instance:
            raise AIModelNotLoadedError(f"Model {model_name} not loaded")
        
        # Train based on model type
        if model_info["type"] == "isolation_forest":
            # Get model path for saving
            model_path = model_info["path"] if save_model else None
            
            # Train the model
            model_instance.train(training_events, save_path=model_path)
            self.logger.info(f"Trained model {model_name}")
            
            if save_model:
                self.logger.info(f"Saved model {model_name} to {model_path}")
        else:
            raise ValueError(f"Unsupported model type: {model_info['type']}")
    
    def shutdown(self) -> None:
        """Shut down the integrator and clean up resources."""
        self.stop_processing()
        self.logger.info("SIEM AI Integrator shut down")


# Singleton instance
_integrator = None


def get_integrator(config_path: Optional[str] = None) -> SIEMIntegrator:
    """
    Get the global integrator instance.
    
    Args:
        config_path: Path to the AI configuration file
        
    Returns:
        SIEMIntegrator instance
    """
    global _integrator
    if _integrator is None:
        _integrator = SIEMIntegrator(config_path)
    return _integrator 