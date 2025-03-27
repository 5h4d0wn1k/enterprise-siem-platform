"""
Isolation Forest implementation for anomaly detection in Enterprise SIEM Platform.

This module provides an implementation of the Isolation Forest algorithm for detecting
anomalies in security events. It builds on scikit-learn's IsolationForest and adds
additional functionality for explaining anomalies and customizing the algorithm
for security event data.
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Union, Optional, Tuple
from dataclasses import dataclass
import pickle
import os
import datetime
from sklearn.ensemble import IsolationForest as SklearnIsolationForest
from sklearn.preprocessing import StandardScaler

from src.utils.event import Event


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""
    
    event_id: str
    score: float  # Anomaly score (higher means more anomalous)
    is_anomaly: bool  # True if anomalous
    reason: str  # Explanation of anomaly
    features: Dict[str, float]  # Feature values for the event
    feature_contributions: Dict[str, float]  # Contribution of each feature to anomaly score
    detection_time: datetime.datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "score": self.score,
            "is_anomaly": self.is_anomaly,
            "reason": self.reason,
            "features": self.features,
            "feature_contributions": self.feature_contributions,
            "detection_time": self.detection_time.isoformat()
        }


class IsolationForestDetector:
    """
    Anomaly detector based on Isolation Forest algorithm.
    
    The Isolation Forest algorithm isolates observations by randomly selecting a feature
    and then randomly selecting a split value between the maximum and minimum values of
    that feature. This recursive partitioning can be represented by a tree structure.
    
    Anomalies are observations that need fewer splits to be isolated, i.e., they
    have shorter average path lengths in the trees.
    """
    
    def __init__(
        self,
        n_estimators: int = 100,
        max_samples: Union[int, float, str] = "auto",
        contamination: float = 0.1,
        max_features: Union[int, float] = 1.0,
        bootstrap: bool = False,
        feature_names: List[str] = None,
        threshold: float = None,
        random_state: int = 42
    ):
        """
        Initialize the Isolation Forest detector.
        
        Args:
            n_estimators: Number of isolation trees
            max_samples: Number of samples to draw for each tree
            contamination: Expected proportion of anomalies
            max_features: Number of features to draw for each tree
            bootstrap: Whether to use bootstrap sampling
            feature_names: Names of features to use
            threshold: Custom threshold for anomaly detection (overrides contamination)
            random_state: Random seed for reproducibility
        """
        self.logger = logging.getLogger(__name__)
        
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.max_features = max_features
        self.bootstrap = bootstrap
        self.feature_names = feature_names
        self.threshold = threshold
        self.random_state = random_state
        
        # Initialize models
        self.model = None
        self.scaler = StandardScaler()
        
        # Store training data statistics
        self.feature_ranges = {}
        self.mean_path_length = None
        self.expected_avg_path_length = None
        
    def _extract_features(
        self,
        events: List[Union[Event, Dict[str, Any]]]
    ) -> pd.DataFrame:
        """
        Extract features from events.
        
        Args:
            events: List of Event objects or dictionaries
            
        Returns:
            DataFrame with extracted features
        """
        feature_data = []
        
        for event in events:
            # Convert to dictionary if it's an Event object
            if isinstance(event, Event):
                event_dict = event.raw_data
                event_dict["event_id"] = event.id
            else:
                event_dict = event
            
            # Extract features
            features = {}
            
            # Add a unique identifier
            features["event_id"] = event_dict.get("event_id", "")
            
            # Extract requested features
            if self.feature_names:
                for feature_name in self.feature_names:
                    if feature_name in event_dict:
                        features[feature_name] = event_dict[feature_name]
                    else:
                        # Try to extract from nested dictionaries
                        value = self._extract_nested_value(event_dict, feature_name)
                        if value is not None:
                            features[feature_name] = value
                        else:
                            features[feature_name] = 0  # Default value
            else:
                # Use all numeric values as features
                for key, value in event_dict.items():
                    if isinstance(value, (int, float)) and key != "event_id":
                        features[key] = value
            
            feature_data.append(features)
        
        # Convert to DataFrame
        df = pd.DataFrame(feature_data)
        
        # Update feature names if not specified
        if not self.feature_names:
            self.feature_names = [col for col in df.columns if col != "event_id"]
        
        return df
    
    def _extract_nested_value(
        self,
        data: Dict[str, Any],
        key_path: str,
        separator: str = "."
    ) -> Any:
        """
        Extract a value from a nested dictionary.
        
        Args:
            data: Dictionary to extract from
            key_path: Path to the value (e.g., "user.login.count")
            separator: Separator for keys
            
        Returns:
            Extracted value or None if not found
        """
        keys = key_path.split(separator)
        current = data
        
        try:
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return None
            
            # Only return if it's a numeric value
            if isinstance(current, (int, float)):
                return current
            return None
        except:
            return None
    
    def _preprocess_features(self, df: pd.DataFrame) -> np.ndarray:
        """
        Preprocess features for model training.
        
        Args:
            df: DataFrame with features
            
        Returns:
            Preprocessed feature array
        """
        # Select relevant columns
        feature_df = df[self.feature_names]
        
        # Store feature ranges
        for feature in self.feature_names:
            self.feature_ranges[feature] = (
                float(feature_df[feature].min()),
                float(feature_df[feature].max())
            )
        
        # Scale features
        X = self.scaler.fit_transform(feature_df)
        
        return X
    
    def _preprocess_inference(self, df: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
        """
        Preprocess features for inference.
        
        Args:
            df: DataFrame with features
            
        Returns:
            Tuple of (preprocessed feature array, list of event IDs)
        """
        # Extract event IDs
        event_ids = df["event_id"].tolist()
        
        # Select relevant columns
        feature_df = df[self.feature_names]
        
        # Scale features
        X = self.scaler.transform(feature_df)
        
        return X, event_ids
    
    def _calculate_feature_contributions(
        self,
        X: np.ndarray,
        scores: np.ndarray
    ) -> List[Dict[str, float]]:
        """
        Calculate contribution of each feature to anomaly scores.
        
        This is a simple implementation that estimates feature contributions
        by perturbing each feature and measuring the change in anomaly score.
        
        Args:
            X: Feature array
            scores: Anomaly scores
            
        Returns:
            List of dictionaries mapping feature names to contribution scores
        """
        contributions = []
        
        for i in range(X.shape[0]):
            feature_contribs = {}
            baseline_score = scores[i]
            
            for j, feature_name in enumerate(self.feature_names):
                # Create a perturbed sample
                X_perturbed = X[i].copy()
                
                # Set the feature to its mean value (0 after scaling)
                X_perturbed[j] = 0
                
                # Calculate the new score
                new_score = self.model.score_samples([X_perturbed])[0]
                
                # Calculate the contribution as the difference in scores
                contribution = baseline_score - new_score
                
                feature_contribs[feature_name] = float(contribution)
            
            contributions.append(feature_contribs)
        
        return contributions
    
    def _generate_reason(
        self,
        features: Dict[str, float],
        contributions: Dict[str, float]
    ) -> str:
        """
        Generate a human-readable reason for an anomaly.
        
        Args:
            features: Feature values
            contributions: Feature contributions
            
        Returns:
            Explanation string
        """
        # Sort features by contribution
        sorted_contribs = sorted(
            contributions.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )
        
        # Take top 3 contributing features
        top_features = sorted_contribs[:3]
        
        reason_parts = []
        
        for feature_name, contribution in top_features:
            if contribution > 0:
                if feature_name in self.feature_ranges:
                    min_val, max_val = self.feature_ranges[feature_name]
                    feature_value = features[feature_name]
                    
                    # Determine if the value is high or low
                    mid_point = (min_val + max_val) / 2
                    
                    if feature_value > mid_point:
                        reason_parts.append(
                            f"Unusually high {feature_name} ({feature_value:.2f})"
                        )
                    else:
                        reason_parts.append(
                            f"Unusually low {feature_name} ({feature_value:.2f})"
                        )
                else:
                    reason_parts.append(f"Unusual {feature_name} value")
        
        if reason_parts:
            return "Anomaly detected due to: " + ", ".join(reason_parts)
        else:
            return "Anomaly detected due to unusual combination of features"
    
    def train(
        self,
        events: List[Union[Event, Dict[str, Any]]],
        save_path: Optional[str] = None
    ) -> None:
        """
        Train the isolation forest model on the provided events.
        
        Args:
            events: List of events or event dictionaries
            save_path: Optional path to save the trained model
        """
        self.logger.info(f"Training Isolation Forest with {len(events)} events")
        
        # Extract features
        df = self._extract_features(events)
        
        # Preprocess features
        X = self._preprocess_features(df)
        
        # Train the model
        self.model = SklearnIsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            max_features=self.max_features,
            bootstrap=self.bootstrap,
            random_state=self.random_state
        )
        
        self.model.fit(X)
        
        # Calculate statistics
        self.mean_path_length = self.model.decision_function(X).mean()
        n_samples = X.shape[0]
        self.expected_avg_path_length = 2 * (np.log(n_samples - 1) + 0.5772156649) - (2 * (n_samples - 1) / n_samples)
        
        self.logger.info(f"Isolation Forest trained successfully with {len(self.feature_names)} features")
        
        # Save the model if requested
        if save_path:
            self.save(save_path)
    
    def detect(
        self,
        events: List[Union[Event, Dict[str, Any]]],
        threshold: Optional[float] = None
    ) -> List[AnomalyResult]:
        """
        Detect anomalies in the provided events.
        
        Args:
            events: List of events or event dictionaries
            threshold: Custom threshold for anomaly detection
            
        Returns:
            List of anomaly results
        """
        if self.model is None:
            raise ValueError("Model not trained yet. Call train() first.")
        
        self.logger.info(f"Detecting anomalies in {len(events)} events")
        
        # Extract features
        df = self._extract_features(events)
        
        # Preprocess features
        X, event_ids = self._preprocess_inference(df)
        
        # Detect anomalies
        scores = -self.model.score_samples(X)  # Negated for easier interpretation
        
        # Use the provided threshold or the one from initialization
        threshold_value = threshold or self.threshold
        
        # If no threshold is provided, use the contamination-based threshold
        if threshold_value is None:
            n_samples = len(scores)
            threshold_value = np.percentile(scores, 100 * (1 - self.contamination))
        
        # Calculate feature contributions
        contributions = self._calculate_feature_contributions(X, scores)
        
        # Create results
        results = []
        
        for i, (event_id, score) in enumerate(zip(event_ids, scores)):
            is_anomaly = score > threshold_value
            
            # Get original feature values
            feature_values = {
                feature: df.loc[df["event_id"] == event_id, feature].iloc[0]
                for feature in self.feature_names
            }
            
            # Generate reason
            reason = self._generate_reason(feature_values, contributions[i]) if is_anomaly else ""
            
            result = AnomalyResult(
                event_id=event_id,
                score=float(score),
                is_anomaly=is_anomaly,
                reason=reason,
                features=feature_values,
                feature_contributions=contributions[i],
                detection_time=datetime.datetime.now()
            )
            
            results.append(result)
        
        # Log results
        anomaly_count = sum(1 for r in results if r.is_anomaly)
        self.logger.info(f"Detected {anomaly_count} anomalies in {len(events)} events")
        
        return results
    
    def save(self, path: str) -> None:
        """
        Save the model to a file.
        
        Args:
            path: Path to save the model
        """
        model_data = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "feature_ranges": self.feature_ranges,
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "contamination": self.contamination,
            "max_features": self.max_features,
            "bootstrap": self.bootstrap,
            "threshold": self.threshold,
            "random_state": self.random_state,
            "mean_path_length": self.mean_path_length,
            "expected_avg_path_length": self.expected_avg_path_length
        }
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        with open(path, "wb") as f:
            pickle.dump(model_data, f)
        
        self.logger.info(f"Model saved to {path}")
    
    @classmethod
    def load(cls, path: str) -> 'IsolationForestDetector':
        """
        Load a model from a file.
        
        Args:
            path: Path to the model file
            
        Returns:
            Loaded model
        """
        with open(path, "rb") as f:
            model_data = pickle.load(f)
        
        # Create a new instance
        detector = cls(
            n_estimators=model_data["n_estimators"],
            max_samples=model_data["max_samples"],
            contamination=model_data["contamination"],
            max_features=model_data["max_features"],
            bootstrap=model_data["bootstrap"],
            feature_names=model_data["feature_names"],
            threshold=model_data["threshold"],
            random_state=model_data["random_state"]
        )
        
        # Restore model state
        detector.model = model_data["model"]
        detector.scaler = model_data["scaler"]
        detector.feature_ranges = model_data["feature_ranges"]
        detector.mean_path_length = model_data["mean_path_length"]
        detector.expected_avg_path_length = model_data["expected_avg_path_length"]
        
        detector.logger.info(f"Model loaded from {path}")
        
        return detector 