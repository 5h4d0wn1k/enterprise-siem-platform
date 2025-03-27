"""
Data Security Posture Management (DSPM) Manager

This module manages DSPM operations in the Enterprise SIEM Platform.
It coordinates multiple scanners, schedules scans, and processes results
to maintain visibility into sensitive data across the organization.
"""

import os
import sys
import logging
import threading
import time
import json
import datetime
import uuid
from typing import Dict, List, Any, Optional, Union, Set, Tuple
import importlib
import queue
import traceback

from src.ai.dspm.base_scanner import BaseScanner, ScanResult, SensitiveDataFinding
from src.ai.dspm.file_scanner import FileScanner
from src.utils.config_loader import ConfigLoader


class DspmManager:
    """
    Manager for Data Security Posture Management (DSPM) operations.
    
    This class manages scanners, schedules scans, and processes results
    to help identify and protect sensitive data across the organization.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the DSPM Manager.
        
        Args:
            config_path: Path to the DSPM configuration file
        """
        self.logger = logging.getLogger("dspm.manager")
        
        # Load configuration
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize scanners
        self.scanners = {}
        self._load_scanners()
        
        # Scan state
        self.active_scans = {}
        self.scan_results = {}
        self.last_scan_times = {}
        
        # Scan scheduling
        self.scheduler_thread = None
        self.should_stop = threading.Event()
        
        # Results processing
        self.result_queue = queue.Queue()
        self.processor_thread = None
        
        # Handlers
        self.scan_started_handlers = []
        self.scan_completed_handlers = []
        self.finding_handlers = []
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Load the DSPM configuration.
        
        Returns:
            Configuration dictionary
        """
        if not self.config_path:
            # Default configuration path
            self.config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "config/dspm_config.yaml"
            )
        
        try:
            config_loader = ConfigLoader()
            config = config_loader.load_config(self.config_path)
            self.logger.info(f"Loaded DSPM configuration from {self.config_path}")
            return config
        except Exception as e:
            self.logger.error(f"Failed to load DSPM configuration: {str(e)}")
            # Return default configuration
            return {
                "enabled": True,
                "scan_interval": 24,  # Hours between scans
                "scanners": {
                    "file_scanner": {
                        "enabled": True,
                        "max_file_size": 10485760,  # 10MB
                        "excluded_dirs": [".git", "node_modules", "venv", "__pycache__"],
                        "excluded_files": [],
                        "included_extensions": [],
                        "excluded_extensions": [],
                        "max_workers": 4
                    }
                },
                "targets": [
                    {
                        "name": "source_code",
                        "path": "./src",
                        "scanner": "file_scanner",
                        "recursive": True,
                        "schedule": "daily"
                    }
                ],
                "sensitive_data_types": [
                    "credit_card",
                    "ssn",
                    "email",
                    "password",
                    "api_key",
                    "address",
                    "phone_number"
                ],
                "min_confidence": 0.8,
                "result_retention": 90,  # Days to keep results
                "max_findings_per_source": 1000
            }
    
    def _load_scanners(self) -> None:
        """Load DSPM scanners specified in the configuration."""
        if not self.config.get("enabled", True):
            self.logger.info("DSPM is disabled in configuration")
            return
        
        scanners_config = self.config.get("scanners", {})
        
        # Default scanners
        self._register_scanner("file_scanner", FileScanner(
            scanner_id="file_scanner",
            config=scanners_config.get("file_scanner", {})
        ))
        
        # Add other scanners from the configuration
        for scanner_id, scanner_config in scanners_config.items():
            if scanner_id != "file_scanner" and scanner_config.get("enabled", True):
                try:
                    # Check if there's a custom scanner class specified
                    scanner_class = scanner_config.get("class")
                    if scanner_class:
                        # Try to import the scanner class
                        module_path, class_name = scanner_class.rsplit(".", 1)
                        module = importlib.import_module(module_path)
                        scanner_cls = getattr(module, class_name)
                        
                        # Create the scanner instance
                        scanner = scanner_cls(
                            scanner_id=scanner_id,
                            config=scanner_config
                        )
                        
                        # Register the scanner
                        self._register_scanner(scanner_id, scanner)
                except Exception as e:
                    self.logger.error(f"Failed to load scanner {scanner_id}: {str(e)}")
                    self.logger.debug(traceback.format_exc())
    
    def _register_scanner(self, scanner_id: str, scanner: BaseScanner) -> None:
        """
        Register a scanner with the manager.
        
        Args:
            scanner_id: Scanner identifier
            scanner: Scanner instance
        """
        if scanner_id in self.scanners:
            self.logger.warning(f"Scanner {scanner_id} is already registered, replacing")
        
        self.scanners[scanner_id] = scanner
        self.logger.info(f"Registered scanner: {scanner_id}")
    
    def start(self) -> None:
        """Start the DSPM manager."""
        if not self.config.get("enabled", True):
            self.logger.info("DSPM is disabled in configuration, not starting")
            return
        
        # Start result processor
        self.should_stop.clear()
        self.processor_thread = threading.Thread(
            target=self._result_processor_loop,
            daemon=True
        )
        self.processor_thread.start()
        
        # Start scheduler
        self.scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            daemon=True
        )
        self.scheduler_thread.start()
        
        self.logger.info("DSPM manager started")
    
    def stop(self) -> None:
        """Stop the DSPM manager."""
        self.should_stop.set()
        
        # Wait for threads to terminate
        if self.processor_thread:
            self.processor_thread.join(timeout=10)
        
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=10)
        
        self.logger.info("DSPM manager stopped")
    
    def _scheduler_loop(self) -> None:
        """Main scheduler loop."""
        while not self.should_stop.is_set():
            try:
                # Check for scheduled scans
                self._check_scheduled_scans()
                
                # Sleep for a while
                time.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"Error in scheduler loop: {str(e)}")
    
    def _check_scheduled_scans(self) -> None:
        """Check for scans that need to be scheduled."""
        now = datetime.datetime.now()
        targets = self.config.get("targets", [])
        
        for target in targets:
            target_name = target.get("name", target.get("path", "unknown"))
            
            # Skip if target is disabled
            if not target.get("enabled", True):
                continue
            
            # Get the scanner
            scanner_id = target.get("scanner", "file_scanner")
            if scanner_id not in self.scanners:
                self.logger.warning(f"Scanner {scanner_id} not found for target {target_name}")
                continue
            
            # Check when the target was last scanned
            last_scan_time = self.last_scan_times.get(target_name)
            
            # Determine if a scan is due
            should_scan = False
            
            if not last_scan_time:
                # Never scanned before
                should_scan = True
            else:
                # Check schedule
                schedule = target.get("schedule", "daily")
                
                if schedule == "hourly":
                    # Scan if it's been more than an hour
                    should_scan = (now - last_scan_time).total_seconds() >= 3600
                elif schedule == "daily":
                    # Scan if it's been more than a day
                    should_scan = (now - last_scan_time).total_seconds() >= 86400
                elif schedule == "weekly":
                    # Scan if it's been more than a week
                    should_scan = (now - last_scan_time).total_seconds() >= 604800
                elif schedule == "monthly":
                    # Scan if it's been more than 30 days
                    should_scan = (now - last_scan_time).total_seconds() >= 2592000
            
            # Start scan if due
            if should_scan:
                self.logger.info(f"Scheduling scan for target {target_name}")
                
                # Start the scan in a separate thread
                scan_thread = threading.Thread(
                    target=self._run_scan,
                    args=(target,),
                    daemon=True
                )
                scan_thread.start()
    
    def _run_scan(self, target: Dict[str, Any]) -> None:
        """
        Run a scan for a target.
        
        Args:
            target: Target configuration
        """
        target_name = target.get("name", target.get("path", "unknown"))
        target_path = target.get("path")
        scanner_id = target.get("scanner", "file_scanner")
        
        if not target_path:
            self.logger.error(f"No path specified for target {target_name}")
            return
        
        try:
            # Get the scanner
            scanner = self.scanners.get(scanner_id)
            if not scanner:
                self.logger.error(f"Scanner {scanner_id} not found")
                return
            
            # Set up scan options
            options = {
                "recursive": target.get("recursive", True)
            }
            
            # Get additional options
            for key, value in target.items():
                if key not in ["name", "path", "scanner", "recursive", "schedule", "enabled"]:
                    options[key] = value
            
            # Generate a scan ID
            scan_id = f"scan-{uuid.uuid4()}"
            
            # Record scan start
            self.active_scans[scan_id] = {
                "target": target_name,
                "scanner": scanner_id,
                "start_time": datetime.datetime.now(),
                "path": target_path
            }
            
            # Notify handlers
            for handler in self.scan_started_handlers:
                try:
                    handler(scan_id, target)
                except Exception as e:
                    self.logger.error(f"Error in scan started handler: {str(e)}")
            
            # Run the scan
            self.logger.info(f"Starting scan {scan_id} of {target_path} with {scanner_id}")
            result = scanner.scan(target_path, options)
            
            # Update last scan time
            self.last_scan_times[target_name] = datetime.datetime.now()
            
            # Remove from active scans
            scan_info = self.active_scans.pop(scan_id, None)
            
            # Store the result
            self.scan_results[scan_id] = result
            
            # Queue for processing
            self.result_queue.put((scan_id, result))
            
            # Log completion
            self.logger.info(
                f"Completed scan {scan_id} with "
                f"{result.total_findings} findings across "
                f"{result.total_items_scanned} items"
            )
            
            # Notify handlers
            for handler in self.scan_completed_handlers:
                try:
                    handler(scan_id, result)
                except Exception as e:
                    self.logger.error(f"Error in scan completed handler: {str(e)}")
            
        except Exception as e:
            self.logger.error(f"Error running scan for target {target_name}: {str(e)}")
            self.logger.debug(traceback.format_exc())
    
    def _result_processor_loop(self) -> None:
        """Process scan results."""
        while not self.should_stop.is_set():
            try:
                # Get a result from the queue
                try:
                    scan_id, result = self.result_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Process findings
                self._process_findings(scan_id, result)
                
                # Mark task as done
                self.result_queue.task_done()
            except Exception as e:
                self.logger.error(f"Error processing results: {str(e)}")
    
    def _process_findings(self, scan_id: str, result: ScanResult) -> None:
        """
        Process findings from a scan.
        
        Args:
            scan_id: Scan identifier
            result: Scan result
        """
        # Process each finding
        for finding in result.findings:
            # Call handlers
            for handler in self.finding_handlers:
                try:
                    handler(scan_id, finding)
                except Exception as e:
                    self.logger.error(f"Error in finding handler: {str(e)}")
    
    def add_scan_started_handler(self, handler: callable) -> None:
        """
        Add a handler for scan started events.
        
        Args:
            handler: Function to call when a scan starts
        """
        self.scan_started_handlers.append(handler)
    
    def add_scan_completed_handler(self, handler: callable) -> None:
        """
        Add a handler for scan completed events.
        
        Args:
            handler: Function to call when a scan completes
        """
        self.scan_completed_handlers.append(handler)
    
    def add_finding_handler(self, handler: callable) -> None:
        """
        Add a handler for finding events.
        
        Args:
            handler: Function to call for each finding
        """
        self.finding_handlers.append(handler)
    
    def run_scan(
        self,
        path: str,
        scanner_id: str = "file_scanner",
        options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """
        Run a scan manually.
        
        Args:
            path: Path to scan
            scanner_id: Scanner to use
            options: Scan options
            
        Returns:
            Scan result
        """
        if scanner_id not in self.scanners:
            raise ValueError(f"Scanner {scanner_id} not found")
        
        scanner = self.scanners[scanner_id]
        
        if options is None:
            options = {}
        
        # Generate a scan ID
        scan_id = f"scan-{uuid.uuid4()}"
        
        # Record scan start
        self.active_scans[scan_id] = {
            "target": path,
            "scanner": scanner_id,
            "start_time": datetime.datetime.now(),
            "path": path,
            "manual": True
        }
        
        # Notify handlers
        target_info = {
            "name": f"manual-{os.path.basename(path)}",
            "path": path,
            "scanner": scanner_id
        }
        for handler in self.scan_started_handlers:
            try:
                handler(scan_id, target_info)
            except Exception as e:
                self.logger.error(f"Error in scan started handler: {str(e)}")
        
        # Run the scan
        self.logger.info(f"Starting manual scan {scan_id} of {path} with {scanner_id}")
        result = scanner.scan(path, options)
        
        # Remove from active scans
        scan_info = self.active_scans.pop(scan_id, None)
        
        # Store the result
        self.scan_results[scan_id] = result
        
        # Queue for processing
        self.result_queue.put((scan_id, result))
        
        # Log completion
        self.logger.info(
            f"Completed manual scan {scan_id} with "
            f"{result.total_findings} findings across "
            f"{result.total_items_scanned} items"
        )
        
        # Notify handlers
        for handler in self.scan_completed_handlers:
            try:
                handler(scan_id, result)
            except Exception as e:
                self.logger.error(f"Error in scan completed handler: {str(e)}")
        
        return result
    
    def get_active_scans(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about active scans.
        
        Returns:
            Dictionary mapping scan IDs to scan information
        """
        return self.active_scans.copy()
    
    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """
        Get the result of a scan.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Scan result or None if not found
        """
        return self.scan_results.get(scan_id)
    
    def get_scan_results(self) -> Dict[str, ScanResult]:
        """
        Get all scan results.
        
        Returns:
            Dictionary mapping scan IDs to scan results
        """
        return self.scan_results.copy()


# Singleton instance
_dspm_manager = None


def get_dspm_manager(config_path: Optional[str] = None) -> DspmManager:
    """
    Get the global DSPM manager instance.
    
    Args:
        config_path: Path to the DSPM configuration file
        
    Returns:
        DspmManager instance
    """
    global _dspm_manager
    if _dspm_manager is None:
        _dspm_manager = DspmManager(config_path)
    return _dspm_manager 