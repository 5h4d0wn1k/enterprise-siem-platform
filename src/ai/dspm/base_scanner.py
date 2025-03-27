"""
Base Data Security Posture Management (DSPM) Scanner

This module provides the base class for DSPM scanners in the Enterprise SIEM Platform.
DSPM scanners are responsible for discovering, classifying, and analyzing sensitive 
data across the organization's environment to help maintain proper security controls.
"""

import os
import logging
import datetime
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union, Set, Tuple
from dataclasses import dataclass


@dataclass
class SensitiveDataFinding:
    """Represents a finding of sensitive data."""
    
    # Basic information
    finding_id: str
    timestamp: datetime.datetime
    scanner_id: str
    data_type: str
    confidence: float  # 0.0 to 1.0
    
    # Location information
    source_type: str  # 'file', 'database', 'api', etc.
    location: str  # File path, database name, etc.
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    
    # Context
    context: Optional[str] = None
    masked_context: Optional[str] = None  # Context with sensitive data masked
    
    # Metadata
    owner: Optional[str] = None
    created_date: Optional[datetime.datetime] = None
    modified_date: Optional[datetime.datetime] = None
    access_count: Optional[int] = None
    last_accessed: Optional[datetime.datetime] = None
    
    # Risk assessment
    risk_level: Optional[str] = None  # 'low', 'medium', 'high', 'critical'
    risk_factors: Optional[Dict[str, Any]] = None
    
    # Compliance information
    compliance_frameworks: Optional[List[str]] = None  # 'GDPR', 'HIPAA', etc.
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "finding_id": self.finding_id,
            "timestamp": self.timestamp.isoformat(),
            "scanner_id": self.scanner_id,
            "data_type": self.data_type,
            "confidence": self.confidence,
            "source_type": self.source_type,
            "location": self.location
        }
        
        # Add optional fields if they exist
        if self.line_number is not None:
            result["line_number"] = self.line_number
        
        if self.column_number is not None:
            result["column_number"] = self.column_number
        
        if self.context:
            result["context"] = self.context
        
        if self.masked_context:
            result["masked_context"] = self.masked_context
        
        if self.owner:
            result["owner"] = self.owner
        
        if self.created_date:
            result["created_date"] = self.created_date.isoformat()
        
        if self.modified_date:
            result["modified_date"] = self.modified_date.isoformat()
        
        if self.access_count is not None:
            result["access_count"] = self.access_count
        
        if self.last_accessed:
            result["last_accessed"] = self.last_accessed.isoformat()
        
        if self.risk_level:
            result["risk_level"] = self.risk_level
        
        if self.risk_factors:
            result["risk_factors"] = self.risk_factors
        
        if self.compliance_frameworks:
            result["compliance_frameworks"] = self.compliance_frameworks
        
        return result


@dataclass
class ScanResult:
    """Represents the result of a DSPM scan."""
    
    # Basic information
    scan_id: str
    scanner_id: str
    start_time: datetime.datetime
    end_time: datetime.datetime
    
    # Scope information
    target: str  # What was scanned (path, database, etc.)
    scope: Dict[str, Any]  # Details about what was included/excluded
    
    # Findings
    findings: List[SensitiveDataFinding]
    
    # Summary
    total_items_scanned: int
    total_findings: int
    findings_by_type: Dict[str, int]
    findings_by_risk_level: Dict[str, int]
    
    # Errors
    errors: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "scanner_id": self.scanner_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "target": self.target,
            "scope": self.scope,
            "findings": [finding.to_dict() for finding in self.findings],
            "total_items_scanned": self.total_items_scanned,
            "total_findings": self.total_findings,
            "findings_by_type": self.findings_by_type,
            "findings_by_risk_level": self.findings_by_risk_level,
            "errors": self.errors
        }


class BaseScanner(ABC):
    """
    Base class for DSPM scanners.
    
    This class defines the interface for all scanners and provides common
    functionality for managing scans, tracking progress, and reporting results.
    """
    
    def __init__(
        self,
        scanner_id: str,
        config: Dict[str, Any]
    ):
        """
        Initialize the scanner.
        
        Args:
            scanner_id: Unique identifier for this scanner
            config: Scanner configuration
        """
        self.scanner_id = scanner_id
        self.config = config
        self.logger = logging.getLogger(f"dspm.scanner.{scanner_id}")
        
        # Default configuration values
        self.min_confidence = config.get("min_confidence", 0.8)
        self.sensitive_data_types = config.get(
            "sensitive_data_types",
            ["credit_card", "ssn", "email", "password"]
        )
        self.max_findings_per_source = config.get("max_findings_per_source", 1000)
        
        # Scan state
        self.current_scan_id = None
        self.current_scan_start_time = None
        self.current_scan_target = None
        self.current_scan_findings = []
        self.current_scan_errors = []
        self.items_scanned = 0
    
    @abstractmethod
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Scan a target for sensitive data.
        
        Args:
            target: The target to scan (path, database, etc.)
            options: Additional scan options
            
        Returns:
            Scan result
        """
        pass
    
    def start_scan(self, target: str, scope: Dict[str, Any]) -> str:
        """
        Start a new scan.
        
        Args:
            target: The target to scan
            scope: Scan scope details
            
        Returns:
            Scan ID
        """
        import uuid
        
        # Generate a scan ID
        scan_id = f"scan-{uuid.uuid4()}"
        
        # Record scan start
        self.current_scan_id = scan_id
        self.current_scan_start_time = datetime.datetime.now()
        self.current_scan_target = target
        self.current_scan_scope = scope
        self.current_scan_findings = []
        self.current_scan_errors = []
        self.items_scanned = 0
        
        self.logger.info(f"Starting scan {scan_id} of {target}")
        
        return scan_id
    
    def end_scan(self) -> ScanResult:
        """
        End the current scan and return the results.
        
        Returns:
            Scan result
        """
        if not self.current_scan_id:
            raise ValueError("No scan is currently in progress")
        
        # Calculate summary statistics
        findings_by_type = {}
        findings_by_risk_level = {}
        
        for finding in self.current_scan_findings:
            # Count by type
            if finding.data_type in findings_by_type:
                findings_by_type[finding.data_type] += 1
            else:
                findings_by_type[finding.data_type] = 1
            
            # Count by risk level
            if finding.risk_level:
                if finding.risk_level in findings_by_risk_level:
                    findings_by_risk_level[finding.risk_level] += 1
                else:
                    findings_by_risk_level[finding.risk_level] = 1
        
        # Create scan result
        result = ScanResult(
            scan_id=self.current_scan_id,
            scanner_id=self.scanner_id,
            start_time=self.current_scan_start_time,
            end_time=datetime.datetime.now(),
            target=self.current_scan_target,
            scope=self.current_scan_scope,
            findings=self.current_scan_findings,
            total_items_scanned=self.items_scanned,
            total_findings=len(self.current_scan_findings),
            findings_by_type=findings_by_type,
            findings_by_risk_level=findings_by_risk_level,
            errors=self.current_scan_errors
        )
        
        # Log scan completion
        self.logger.info(
            f"Completed scan {self.current_scan_id} with "
            f"{len(self.current_scan_findings)} findings across "
            f"{self.items_scanned} items"
        )
        
        # Reset scan state
        self.current_scan_id = None
        self.current_scan_start_time = None
        self.current_scan_target = None
        self.current_scan_scope = None
        self.current_scan_findings = []
        self.current_scan_errors = []
        self.items_scanned = 0
        
        return result
    
    def add_finding(self, finding: SensitiveDataFinding) -> None:
        """
        Add a finding to the current scan.
        
        Args:
            finding: Finding to add
        """
        if not self.current_scan_id:
            raise ValueError("No scan is currently in progress")
        
        # Check if we have reached the maximum findings per source
        source_findings = sum(
            1 for f in self.current_scan_findings
            if f.location == finding.location
        )
        
        if source_findings >= self.max_findings_per_source:
            self.logger.warning(
                f"Maximum findings ({self.max_findings_per_source}) reached "
                f"for {finding.location}, ignoring additional findings"
            )
            return
        
        # Add the finding
        self.current_scan_findings.append(finding)
    
    def add_error(self, error: Dict[str, Any]) -> None:
        """
        Add an error to the current scan.
        
        Args:
            error: Error details
        """
        if not self.current_scan_id:
            raise ValueError("No scan is currently in progress")
        
        # Add timestamp if not present
        if "timestamp" not in error:
            error["timestamp"] = datetime.datetime.now().isoformat()
        
        # Add the error
        self.current_scan_errors.append(error)
        
        # Log the error
        self.logger.error(f"Scan error: {error.get('message', 'Unknown error')}")
    
    def increment_scanned_items(self, count: int = 1) -> None:
        """
        Increment the count of scanned items.
        
        Args:
            count: Number of items to add to the count
        """
        if not self.current_scan_id:
            raise ValueError("No scan is currently in progress")
        
        self.items_scanned += count
    
    @staticmethod
    def calculate_risk_level(
        data_type: str,
        confidence: float,
        context: Dict[str, Any]
    ) -> str:
        """
        Calculate the risk level for a finding.
        
        Args:
            data_type: Type of sensitive data
            confidence: Confidence score (0.0 to 1.0)
            context: Additional context about the finding
            
        Returns:
            Risk level ('low', 'medium', 'high', 'critical')
        """
        # Default risk levels by data type
        default_risk_levels = {
            "credit_card": "high",
            "ssn": "high",
            "password": "high",
            "api_key": "high",
            "email": "medium",
            "phone_number": "medium",
            "address": "medium",
            "ip_address": "low",
            "date_of_birth": "medium",
            "name": "low"
        }
        
        # Get base risk level
        base_risk = default_risk_levels.get(data_type, "medium")
        
        # Adjust based on confidence
        if confidence < 0.7:
            # Lower risk for low confidence findings
            if base_risk == "critical":
                return "high"
            elif base_risk == "high":
                return "medium"
            elif base_risk == "medium":
                return "low"
            else:
                return "low"
        elif confidence > 0.9:
            # Higher risk for high confidence findings
            if base_risk == "high":
                return "critical"
            elif base_risk == "medium":
                return "high"
            elif base_risk == "low":
                return "medium"
            else:
                return base_risk
        
        # Consider accessibility
        public_access = context.get("public_access", False)
        if public_access and base_risk in ("medium", "high"):
            # Increase risk for publicly accessible data
            if base_risk == "medium":
                return "high"
            else:
                return "critical"
        
        return base_risk 