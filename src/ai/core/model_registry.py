"""
Model Registry for Enterprise SIEM Platform.

Provides centralized management of machine learning models, including versioning,
metadata tracking, and deployment.
"""

import os
import json
import logging
import datetime
from typing import Dict, Any, List, Optional, Union
import hashlib
import yaml
from pathlib import Path
import shutil


class ModelVersion:
    """Represents a specific version of a model."""
    
    def __init__(
        self,
        version: str,
        model_path: str,
        created_at: datetime.datetime = None,
        metadata: Dict[str, Any] = None,
        status: str = "development"
    ):
        """
        Initialize a model version.
        
        Args:
            version: Version string (semantic versioning recommended)
            model_path: Path to the model artifacts
            created_at: Creation timestamp
            metadata: Additional model metadata
            status: Model status (development, staging, production, archived)
        """
        self.version = version
        self.model_path = model_path
        self.created_at = created_at or datetime.datetime.now()
        self.metadata = metadata or {}
        
        # Validate status
        valid_statuses = ["development", "staging", "production", "archived"]
        if status not in valid_statuses:
            raise ValueError(f"Status must be one of {valid_statuses}")
        self.status = status
        
        # Track usage statistics
        self.inference_count = 0
        self.last_used = None
        self.performance_metrics = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": self.version,
            "model_path": self.model_path,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
            "status": self.status,
            "inference_count": self.inference_count,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "performance_metrics": self.performance_metrics
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModelVersion':
        """Create from dictionary."""
        created_at = datetime.datetime.fromisoformat(data["created_at"])
        last_used = None
        if data.get("last_used"):
            last_used = datetime.datetime.fromisoformat(data["last_used"])
        
        model_version = cls(
            version=data["version"],
            model_path=data["model_path"],
            created_at=created_at,
            metadata=data["metadata"],
            status=data["status"]
        )
        
        model_version.inference_count = data.get("inference_count", 0)
        model_version.last_used = last_used
        model_version.performance_metrics = data.get("performance_metrics", {})
        
        return model_version
    
    def record_inference(self) -> None:
        """Record a model inference."""
        self.inference_count += 1
        self.last_used = datetime.datetime.now()
    
    def update_metrics(self, metrics: Dict[str, float]) -> None:
        """Update performance metrics."""
        self.performance_metrics.update(metrics)


class Model:
    """Represents a model with multiple versions."""
    
    def __init__(
        self,
        name: str,
        description: str = "",
        model_type: str = "classifier",
        tags: List[str] = None
    ):
        """
        Initialize a model.
        
        Args:
            name: Unique model name
            description: Model description
            model_type: Type of model (classifier, anomaly_detector, etc.)
            tags: Tags for categorization
        """
        self.name = name
        self.description = description
        self.model_type = model_type
        self.tags = tags or []
        self.versions: Dict[str, ModelVersion] = {}
        self.created_at = datetime.datetime.now()
        self.default_version = None
    
    def add_version(self, version: ModelVersion) -> None:
        """Add a new version to the model."""
        if version.version in self.versions:
            raise ValueError(f"Version {version.version} already exists for model {self.name}")
        
        self.versions[version.version] = version
        
        # If this is the first version, set it as default
        if not self.default_version:
            self.default_version = version.version
    
    def get_version(self, version: str = None) -> ModelVersion:
        """Get a specific version of the model."""
        if version is None:
            if self.default_version is None:
                raise ValueError(f"No default version set for model {self.name}")
            return self.versions[self.default_version]
        
        if version not in self.versions:
            raise ValueError(f"Version {version} not found for model {self.name}")
        
        return self.versions[version]
    
    def set_default_version(self, version: str) -> None:
        """Set the default version of the model."""
        if version not in self.versions:
            raise ValueError(f"Version {version} not found for model {self.name}")
        
        self.default_version = version
    
    def list_versions(self) -> List[Dict[str, Any]]:
        """List all versions of the model."""
        return [
            {
                "version": v.version,
                "status": v.status,
                "created_at": v.created_at.isoformat(),
                "is_default": v.version == self.default_version
            }
            for v in self.versions.values()
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "model_type": self.model_type,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "default_version": self.default_version,
            "versions": {
                version: model_version.to_dict()
                for version, model_version in self.versions.items()
            }
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Model':
        """Create from dictionary."""
        model = cls(
            name=data["name"],
            description=data["description"],
            model_type=data["model_type"],
            tags=data["tags"]
        )
        
        model.created_at = datetime.datetime.fromisoformat(data["created_at"])
        model.default_version = data["default_version"]
        
        for version_key, version_data in data["versions"].items():
            model_version = ModelVersion.from_dict(version_data)
            model.versions[version_key] = model_version
        
        return model


class ModelRegistry:
    """
    Central registry for managing machine learning models.
    
    The registry handles:
    - Model versioning
    - Metadata management
    - Model lifecycle (dev, staging, production, archived)
    - A/B testing configuration
    - Performance tracking
    """
    
    def __init__(self, storage_path: str = None):
        """
        Initialize the model registry.
        
        Args:
            storage_path: Path for storing registry data
        """
        self.logger = logging.getLogger(__name__)
        
        # Use default path if none provided
        if storage_path is None:
            storage_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "storage",
                "models"
            )
        
        self.storage_path = storage_path
        self.registry_file = os.path.join(storage_path, "registry.json")
        self.models: Dict[str, Model] = {}
        
        # Create storage directory if it doesn't exist
        os.makedirs(storage_path, exist_ok=True)
        
        # Load registry if it exists
        if os.path.exists(self.registry_file):
            self._load_registry()
        else:
            self._save_registry()
    
    def _load_registry(self) -> None:
        """Load registry from disk."""
        try:
            with open(self.registry_file, "r") as f:
                data = json.load(f)
            
            for model_name, model_data in data.items():
                self.models[model_name] = Model.from_dict(model_data)
            
            self.logger.info(f"Loaded {len(self.models)} models from registry")
        except Exception as e:
            self.logger.error(f"Error loading registry: {str(e)}")
            self.models = {}
    
    def _save_registry(self) -> None:
        """Save registry to disk."""
        try:
            data = {
                name: model.to_dict()
                for name, model in self.models.items()
            }
            
            with open(self.registry_file, "w") as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"Saved {len(self.models)} models to registry")
        except Exception as e:
            self.logger.error(f"Error saving registry: {str(e)}")
    
    def register_model(
        self,
        name: str,
        version: str,
        model_path: str,
        description: str = "",
        model_type: str = "classifier",
        tags: List[str] = None,
        metadata: Dict[str, Any] = None,
        status: str = "development",
        make_default: bool = False
    ) -> None:
        """
        Register a new model or model version.
        
        Args:
            name: Model name
            version: Model version
            model_path: Path to model artifacts
            description: Model description
            model_type: Type of model
            tags: Model tags
            metadata: Additional metadata
            status: Model status
            make_default: Whether to make this the default version
        """
        # Check if model exists
        if name not in self.models:
            self.models[name] = Model(
                name=name,
                description=description,
                model_type=model_type,
                tags=tags
            )
        
        # Create model version
        model_version = ModelVersion(
            version=version,
            model_path=model_path,
            metadata=metadata,
            status=status
        )
        
        # Add to model
        model = self.models[name]
        model.add_version(model_version)
        
        # Set as default if requested
        if make_default:
            model.set_default_version(version)
        
        # Save registry
        self._save_registry()
        
        self.logger.info(f"Registered model {name} version {version}")
    
    def get_model(
        self,
        name: str,
        version: str = None
    ) -> ModelVersion:
        """
        Get a model version.
        
        Args:
            name: Model name
            version: Model version (None for default)
            
        Returns:
            ModelVersion object
        """
        if name not in self.models:
            raise ValueError(f"Model {name} not found in registry")
        
        model = self.models[name]
        model_version = model.get_version(version)
        
        # Record usage
        model_version.record_inference()
        self._save_registry()
        
        return model_version
    
    def list_models(self) -> List[Dict[str, Any]]:
        """
        List all registered models.
        
        Returns:
            List of model information
        """
        return [
            {
                "name": model.name,
                "description": model.description,
                "type": model.model_type,
                "tags": model.tags,
                "versions": len(model.versions),
                "default_version": model.default_version
            }
            for model in self.models.values()
        ]
    
    def list_model_versions(self, name: str) -> List[Dict[str, Any]]:
        """
        List all versions of a model.
        
        Args:
            name: Model name
            
        Returns:
            List of version information
        """
        if name not in self.models:
            raise ValueError(f"Model {name} not found in registry")
        
        return self.models[name].list_versions()
    
    def update_model_status(
        self,
        name: str,
        version: str,
        status: str
    ) -> None:
        """
        Update a model version's status.
        
        Args:
            name: Model name
            version: Model version
            status: New status
        """
        if name not in self.models:
            raise ValueError(f"Model {name} not found in registry")
        
        model = self.models[name]
        model_version = model.get_version(version)
        
        # Validate status
        valid_statuses = ["development", "staging", "production", "archived"]
        if status not in valid_statuses:
            raise ValueError(f"Status must be one of {valid_statuses}")
        
        model_version.status = status
        self._save_registry()
        
        self.logger.info(f"Updated model {name} version {version} status to {status}")
    
    def update_model_metrics(
        self,
        name: str,
        version: str,
        metrics: Dict[str, float]
    ) -> None:
        """
        Update a model version's performance metrics.
        
        Args:
            name: Model name
            version: Model version
            metrics: Performance metrics
        """
        if name not in self.models:
            raise ValueError(f"Model {name} not found in registry")
        
        model = self.models[name]
        model_version = model.get_version(version)
        
        model_version.update_metrics(metrics)
        self._save_registry()
        
        self.logger.info(f"Updated metrics for model {name} version {version}")
    
    def delete_model(self, name: str) -> None:
        """
        Delete a model from the registry.
        
        Args:
            name: Model name
        """
        if name not in self.models:
            raise ValueError(f"Model {name} not found in registry")
        
        del self.models[name]
        self._save_registry()
        
        self.logger.info(f"Deleted model {name} from registry")
    
    def delete_model_version(self, name: str, version: str) -> None:
        """
        Delete a model version from the registry.
        
        Args:
            name: Model name
            version: Model version
        """
        if name not in self.models:
            raise ValueError(f"Model {name} not found in registry")
        
        model = self.models[name]
        
        if version not in model.versions:
            raise ValueError(f"Version {version} not found for model {name}")
        
        # Check if this is the default version
        if model.default_version == version:
            raise ValueError(f"Cannot delete default version {version} of model {name}")
        
        del model.versions[version]
        self._save_registry()
        
        self.logger.info(f"Deleted model {name} version {version}")
    
    def export_model(
        self,
        name: str,
        version: str,
        export_path: str
    ) -> str:
        """
        Export a model to a new location.
        
        Args:
            name: Model name
            version: Model version
            export_path: Path to export to
            
        Returns:
            Path to exported model
        """
        if name not in self.models:
            raise ValueError(f"Model {name} not found in registry")
        
        model = self.models[name]
        model_version = model.get_version(version)
        
        # Create export directory
        os.makedirs(export_path, exist_ok=True)
        
        # Copy model files
        model_dir = model_version.model_path
        target_dir = os.path.join(export_path, f"{name}_{version}")
        
        if os.path.isdir(model_dir):
            shutil.copytree(model_dir, target_dir)
        else:
            shutil.copy2(model_dir, target_dir)
        
        # Create metadata file
        metadata = {
            "name": name,
            "version": version,
            "description": model.description,
            "model_type": model.model_type,
            "tags": model.tags,
            "created_at": model_version.created_at.isoformat(),
            "metadata": model_version.metadata,
            "performance_metrics": model_version.performance_metrics
        }
        
        with open(os.path.join(target_dir, "metadata.yaml"), "w") as f:
            yaml.dump(metadata, f, default_flow_style=False)
        
        self.logger.info(f"Exported model {name} version {version} to {target_dir}")
        return target_dir
    
    def import_model(
        self,
        import_path: str,
        make_default: bool = False
    ) -> Dict[str, str]:
        """
        Import a model from a location.
        
        Args:
            import_path: Path to import from
            make_default: Whether to make this the default version
            
        Returns:
            Dictionary with model name and version
        """
        # Check if import path exists
        if not os.path.exists(import_path):
            raise ValueError(f"Import path {import_path} does not exist")
        
        # Load metadata
        metadata_file = os.path.join(import_path, "metadata.yaml")
        if not os.path.exists(metadata_file):
            raise ValueError(f"Metadata file not found in {import_path}")
        
        with open(metadata_file, "r") as f:
            metadata = yaml.safe_load(f)
        
        # Extract model information
        name = metadata["name"]
        version = metadata["version"]
        description = metadata.get("description", "")
        model_type = metadata.get("model_type", "classifier")
        tags = metadata.get("tags", [])
        model_metadata = metadata.get("metadata", {})
        
        # Register model
        self.register_model(
            name=name,
            version=version,
            model_path=import_path,
            description=description,
            model_type=model_type,
            tags=tags,
            metadata=model_metadata,
            make_default=make_default
        )
        
        # Update performance metrics if available
        if "performance_metrics" in metadata:
            self.update_model_metrics(
                name=name,
                version=version,
                metrics=metadata["performance_metrics"]
            )
        
        self.logger.info(f"Imported model {name} version {version} from {import_path}")
        return {"name": name, "version": version}
    
    def get_models_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        """
        Get all models with a specific tag.
        
        Args:
            tag: Tag to filter by
            
        Returns:
            List of model information
        """
        return [
            {
                "name": model.name,
                "description": model.description,
                "type": model.model_type,
                "tags": model.tags,
                "versions": len(model.versions),
                "default_version": model.default_version
            }
            for model in self.models.values()
            if tag in model.tags
        ]
    
    def get_models_by_type(self, model_type: str) -> List[Dict[str, Any]]:
        """
        Get all models of a specific type.
        
        Args:
            model_type: Type to filter by
            
        Returns:
            List of model information
        """
        return [
            {
                "name": model.name,
                "description": model.description,
                "type": model.model_type,
                "tags": model.tags,
                "versions": len(model.versions),
                "default_version": model.default_version
            }
            for model in self.models.values()
            if model.model_type == model_type
        ] 