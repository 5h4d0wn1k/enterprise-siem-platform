#!/usr/bin/env python3
"""
Example script demonstrating the use of Isolation Forest for anomaly detection
in the Enterprise SIEM Platform.

This script:
1. Loads sample security events
2. Trains an isolation forest detector
3. Detects anomalies in new events
4. Displays anomaly results with explanations

Usage:
    python anomaly_detection_example.py
"""

import sys
import os
import json
import logging
import datetime
from typing import List, Dict, Any
import random

# Add parent directory to path to import from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.ai.models.anomaly.isolation_forest import IsolationForestDetector
from src.utils.event import Event

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def generate_sample_events(num_events: int = 1000) -> List[Dict[str, Any]]:
    """
    Generate sample security events for demonstration.
    
    These events simulate login attempts with various attributes.
    
    Args:
        num_events: Number of events to generate
        
    Returns:
        List of event dictionaries
    """
    events = []
    
    # Define normal ranges for features
    ranges = {
        "login_attempt_count": (1, 5),
        "session_duration": (60, 3600),  # 1 minute to 1 hour
        "bytes_transferred": (100, 10000),
        "connection_count": (1, 10),
        "authentication_failures": (0, 2),
        "time_since_last_login": (3600, 86400),  # 1 hour to 1 day
        "process_count": (1, 20),
        "cpu_usage": (0.1, 50.0),
        "memory_usage": (50, 500),  # MB
    }
    
    # Generate event IDs
    event_ids = [f"EVENT-{i:06d}" for i in range(num_events)]
    
    # Generate timestamps within the last 7 days
    now = datetime.datetime.now()
    seven_days_ago = now - datetime.timedelta(days=7)
    timestamps = [
        (seven_days_ago + datetime.timedelta(
            seconds=random.randint(0, 7 * 24 * 3600)
        )).isoformat()
        for _ in range(num_events)
    ]
    
    # Define sources
    sources = ["windows_security", "linux_auth", "vpn", "firewall", "webapp"]
    
    # Define users (mostly normal with some service accounts)
    normal_users = [f"user{i:03d}" for i in range(1, 51)]
    service_accounts = ["svc_backup", "svc_monitor", "svc_admin", "system"]
    users = normal_users + service_accounts
    
    # Define source IPs (mostly internal, some external)
    internal_ips = [f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}" 
                    for _ in range(50)]
    external_ips = [f"{random.randint(1, 223)}.{random.randint(0, 255)}."
                    f"{random.randint(0, 255)}.{random.randint(0, 255)}" 
                    for _ in range(10)]
    source_ips = internal_ips + external_ips
    
    # Generate normal events
    for i in range(num_events - 20):  # Reserve 20 events for anomalies
        event = {
            "event_id": event_ids[i],
            "timestamp": timestamps[i],
            "source": random.choice(sources),
            "event_type": "authentication",
            "user": random.choice(normal_users),  # Normal users only
            "source_ip": random.choice(internal_ips),  # Internal IPs only
            "success": random.random() > 0.05,  # 5% chance of failure
        }
        
        # Add numeric features within normal ranges
        for feature, (min_val, max_val) in ranges.items():
            event[feature] = random.uniform(min_val, max_val)
        
        # Adjust authentication failures based on success
        if event["success"]:
            event["authentication_failures"] = 0
        else:
            event["authentication_failures"] = random.randint(1, 3)
        
        events.append(event)
    
    # Generate anomalous events
    for i in range(num_events - 20, num_events):
        event = {
            "event_id": event_ids[i],
            "timestamp": timestamps[i],
            "source": random.choice(sources),
            "event_type": "authentication",
        }
        
        # Choose anomaly type
        anomaly_type = random.choice([
            "unusual_user",
            "unusual_ip",
            "high_login_attempts",
            "high_data_transfer",
            "high_auth_failures",
            "unusual_time",
            "unusual_process_count",
            "unusual_resource_usage"
        ])
        
        if anomaly_type == "unusual_user":
            event["user"] = random.choice(service_accounts)
            event["source_ip"] = random.choice(external_ips)
            event["success"] = random.random() > 0.5
        elif anomaly_type == "unusual_ip":
            event["user"] = random.choice(normal_users)
            event["source_ip"] = random.choice(external_ips)
            event["success"] = random.random() > 0.5
        elif anomaly_type == "high_login_attempts":
            event["user"] = random.choice(normal_users)
            event["source_ip"] = random.choice(internal_ips)
            event["login_attempt_count"] = random.randint(20, 100)
            event["success"] = random.random() > 0.7
        elif anomaly_type == "high_data_transfer":
            event["user"] = random.choice(normal_users)
            event["source_ip"] = random.choice(internal_ips)
            event["bytes_transferred"] = random.randint(50000, 1000000)
            event["success"] = True
        elif anomaly_type == "high_auth_failures":
            event["user"] = random.choice(normal_users)
            event["source_ip"] = random.choice(internal_ips)
            event["authentication_failures"] = random.randint(10, 20)
            event["success"] = False
        elif anomaly_type == "unusual_time":
            event["user"] = random.choice(normal_users)
            event["source_ip"] = random.choice(internal_ips)
            event["time_since_last_login"] = random.randint(604800, 2592000)  # 1-4 weeks
            event["success"] = True
        elif anomaly_type == "unusual_process_count":
            event["user"] = random.choice(normal_users)
            event["source_ip"] = random.choice(internal_ips)
            event["process_count"] = random.randint(50, 200)
            event["success"] = True
        elif anomaly_type == "unusual_resource_usage":
            event["user"] = random.choice(normal_users)
            event["source_ip"] = random.choice(internal_ips)
            event["cpu_usage"] = random.uniform(80.0, 100.0)
            event["memory_usage"] = random.randint(1000, 8000)
            event["success"] = True
        
        # Add remaining features within normal ranges
        for feature, (min_val, max_val) in ranges.items():
            if feature not in event:
                event[feature] = random.uniform(min_val, max_val)
        
        events.append(event)
    
    # Shuffle events
    random.shuffle(events)
    
    return events


def main():
    """Run the anomaly detection example."""
    logger.info("Starting anomaly detection example")
    
    # Generate sample data
    logger.info("Generating sample events")
    all_events = generate_sample_events(1000)
    
    # Split into training and testing sets (80/20 split)
    train_size = int(0.8 * len(all_events))
    train_events = all_events[:train_size]
    test_events = all_events[train_size:]
    
    logger.info(f"Training with {len(train_events)} events, testing with {len(test_events)} events")
    
    # Feature names to use
    feature_names = [
        "login_attempt_count",
        "session_duration",
        "bytes_transferred",
        "connection_count",
        "authentication_failures",
        "time_since_last_login",
        "process_count",
        "cpu_usage",
        "memory_usage"
    ]
    
    # Create and train the detector
    detector = IsolationForestDetector(
        n_estimators=100,
        contamination=0.02,  # Expect 2% anomalies
        feature_names=feature_names,
        random_state=42
    )
    
    # Convert events to Event objects
    train_event_objects = [
        Event(
            id=event["event_id"],
            source=event["source"],
            timestamp=event["timestamp"],
            raw_data=event
        )
        for event in train_events
    ]
    
    test_event_objects = [
        Event(
            id=event["event_id"],
            source=event["source"],
            timestamp=event["timestamp"],
            raw_data=event
        )
        for event in test_events
    ]
    
    # Train the detector
    logger.info("Training isolation forest detector")
    detector.train(train_event_objects)
    
    # Save the model
    model_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../models/anomaly'))
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, 'isolation_forest_model.pkl')
    detector.save(model_path)
    logger.info(f"Model saved to {model_path}")
    
    # Detect anomalies in test data
    logger.info("Detecting anomalies in test data")
    results = detector.detect(test_event_objects)
    
    # Count anomalies
    anomaly_count = sum(1 for r in results if r.is_anomaly)
    logger.info(f"Detected {anomaly_count} anomalies in {len(test_events)} test events")
    
    # Display anomalies
    print("\n===== ANOMALY DETECTION RESULTS =====\n")
    
    for result in results:
        if result.is_anomaly:
            # Get the event
            event = next(e.raw_data for e in test_event_objects if e.id == result.event_id)
            
            print(f"ANOMALY DETECTED: {result.event_id}")
            print(f"User: {event.get('user', 'N/A')}")
            print(f"Source IP: {event.get('source_ip', 'N/A')}")
            print(f"Timestamp: {event.get('timestamp', 'N/A')}")
            print(f"Anomaly Score: {result.score:.4f}")
            print(f"Reason: {result.reason}")
            
            # Print top contributing features
            sorted_contribs = sorted(
                result.feature_contributions.items(),
                key=lambda x: abs(x[1]),
                reverse=True
            )[:3]
            
            print("Top contributing features:")
            for feature, contrib in sorted_contribs:
                print(f"  - {feature}: {contrib:.4f} (value: {result.features[feature]:.2f})")
            
            print("")
    
    # Load the model and test it
    logger.info("Testing model loading")
    loaded_detector = IsolationForestDetector.load(model_path)
    
    # Test a single event
    test_event = test_event_objects[0]
    results = loaded_detector.detect([test_event])
    
    logger.info("Anomaly detection example completed")


if __name__ == "__main__":
    main() 