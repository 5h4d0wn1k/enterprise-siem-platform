"""
File-based Data Security Posture Management (DSPM) Scanner

This module provides a scanner for detecting sensitive data in files.
It uses regular expressions and ML-based methods to identify and classify sensitive
information in various file types.
"""

import os
import logging
import re
import datetime
import uuid
import json
import glob
import mimetypes
from typing import Dict, List, Any, Optional, Set, Tuple, Pattern, Union
import concurrent.futures
from dataclasses import dataclass, field

from src.ai.dspm.base_scanner import BaseScanner, SensitiveDataFinding, ScanResult


@dataclass
class DataPattern:
    """Definition of a sensitive data pattern."""
    
    name: str
    regex: Pattern
    description: str
    examples: List[str] = field(default_factory=list)
    masked_format: str = "{type}****{type}"  # Format for masking sensitive data
    requires_validation: bool = False  # Whether additional validation is needed
    validation_func: Optional[callable] = None  # Function to validate matches
    compliance_frameworks: List[str] = field(default_factory=list)  # Associated frameworks


class FileScanner(BaseScanner):
    """
    Scanner for detecting sensitive data in files.
    
    This scanner can analyze text-based files for sensitive information
    like PII, credentials, and other types of sensitive data.
    """
    
    # Define common file extensions by type
    TEXT_EXTENSIONS = {
        '.txt', '.md', '.csv', '.log', '.json', '.xml', '.yaml', '.yml',
        '.html', '.htm', '.css', '.js', '.ts', '.py', '.java', '.c', '.cpp',
        '.cs', '.go', '.rb', '.php', '.pl', '.sh', '.bat', '.ps1', '.sql',
        '.config', '.ini', '.conf', '.properties', '.env'
    }
    
    DOCUMENT_EXTENSIONS = {
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
        '.rtf', '.odt', '.ods', '.odp'
    }
    
    # Define regex patterns for sensitive data
    DEFAULT_PATTERNS = [
        DataPattern(
            name="credit_card",
            regex=re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"),
            description="Credit Card Number",
            masked_format="CCNUM****{last4}",
            requires_validation=True,
            compliance_frameworks=["PCI-DSS", "GDPR"]
        ),
        DataPattern(
            name="ssn",
            regex=re.compile(r"\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d|7[012]))([-]?)(?!00)\d\d\3(?!0000)\d{4}\b"),
            description="Social Security Number",
            masked_format="SSN****{last4}",
            compliance_frameworks=["HIPAA", "GDPR"]
        ),
        DataPattern(
            name="email",
            regex=re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
            description="Email Address",
            masked_format="{username_prefix}****@{domain}",
            compliance_frameworks=["GDPR", "CCPA"]
        ),
        DataPattern(
            name="ip_address",
            regex=re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
            description="IP Address",
            masked_format="IP****{last_octet}",
        ),
        DataPattern(
            name="password",
            regex=re.compile(r"(?i)(?:password|passwd|pwd)[\s:=]+['\"]*([^\s'\",;]{8,})['\"]?"),
            description="Password",
            masked_format="PASSWORD****",
            compliance_frameworks=["GDPR", "HIPAA", "PCI-DSS"]
        ),
        DataPattern(
            name="api_key",
            regex=re.compile(r"(?i)(?:api[_-]?key|access[_-]?key|secret[_-]?key|app[_-]?key)[\s:=]+['\"]*([a-zA-Z0-9_\-\.]{16,})['\"]*"),
            description="API Key",
            masked_format="APIKEY****",
            compliance_frameworks=["GDPR", "PCI-DSS"]
        ),
        DataPattern(
            name="aws_key",
            regex=re.compile(r"AKIA[0-9A-Z]{16}"),
            description="AWS Access Key",
            masked_format="AWSKEY****",
            compliance_frameworks=["PCI-DSS"]
        ),
        DataPattern(
            name="phone_number",
            regex=re.compile(r"\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
            description="Phone Number",
            masked_format="PHONE****{last4}",
            compliance_frameworks=["GDPR", "HIPAA", "CCPA"]
        )
    ]
    
    def __init__(
        self,
        scanner_id: str = "file_scanner",
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the file scanner.
        
        Args:
            scanner_id: Unique identifier for this scanner
            config: Scanner configuration
        """
        if config is None:
            config = {}
        
        super().__init__(scanner_id, config)
        
        # Set up patterns
        self.patterns = self._setup_patterns(
            config.get("custom_patterns", [])
        )
        
        # Configure file handling
        self.max_file_size = config.get("max_file_size", 10 * 1024 * 1024)  # Default 10MB
        self.excluded_dirs = set(config.get("excluded_dirs", [".git", "node_modules", "venv", "__pycache__"]))
        self.excluded_files = set(config.get("excluded_files", []))
        self.included_extensions = set(config.get("included_extensions", []))
        self.excluded_extensions = set(config.get("excluded_extensions", []))
        self.max_line_length = config.get("max_line_length", 10000)
        
        # Configure concurrency
        self.max_workers = config.get("max_workers", 4)
    
    def _setup_patterns(self, custom_patterns: List[Dict[str, Any]]) -> List[DataPattern]:
        """
        Set up data detection patterns.
        
        Args:
            custom_patterns: Custom patterns to add
            
        Returns:
            List of DataPattern objects
        """
        patterns = list(self.DEFAULT_PATTERNS)
        
        # Add custom patterns
        for pattern_def in custom_patterns:
            try:
                pattern = DataPattern(
                    name=pattern_def["name"],
                    regex=re.compile(pattern_def["regex"]),
                    description=pattern_def.get("description", pattern_def["name"]),
                    masked_format=pattern_def.get("masked_format", "{type}****{type}"),
                    requires_validation=pattern_def.get("requires_validation", False),
                    compliance_frameworks=pattern_def.get("compliance_frameworks", [])
                )
                patterns.append(pattern)
            except Exception as e:
                self.logger.error(f"Error adding custom pattern {pattern_def.get('name', 'unknown')}: {str(e)}")
        
        return patterns
    
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Scan a directory or file for sensitive data.
        
        Args:
            target: Path to directory or file to scan
            options: Additional scan options
            
        Returns:
            Scan result
        """
        if options is None:
            options = {}
        
        # Resolve the target path
        target_path = os.path.abspath(target)
        
        # Check if the target exists
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target path not found: {target_path}")
        
        # Set up scope
        scope = {
            "target_type": "file" if os.path.isfile(target_path) else "directory",
            "excluded_dirs": list(self.excluded_dirs),
            "excluded_files": list(self.excluded_files),
            "included_extensions": list(self.included_extensions) if self.included_extensions else [],
            "excluded_extensions": list(self.excluded_extensions) if self.excluded_extensions else [],
            "max_file_size": self.max_file_size,
            "recursive": options.get("recursive", True),
            "sensitive_data_types": [pattern.name for pattern in self.patterns]
        }
        
        # Start the scan
        scan_id = self.start_scan(target_path, scope)
        
        try:
            # Collect files to scan
            files_to_scan = self._collect_files(target_path, options)
            self.logger.info(f"Found {len(files_to_scan)} files to scan")
            
            # Scan files in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_file = {
                    executor.submit(self._scan_file, file_path): file_path
                    for file_path in files_to_scan
                }
                
                for future in concurrent.futures.as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        # Process result
                        future.result()
                    except Exception as e:
                        # Log error
                        self.logger.error(f"Error scanning file {file_path}: {str(e)}")
                        self.add_error({
                            "file": file_path,
                            "message": str(e),
                            "type": type(e).__name__
                        })
            
            # Complete the scan
            return self.end_scan()
        except Exception as e:
            # Log the error
            self.logger.error(f"Error scanning {target_path}: {str(e)}")
            
            # Add to errors
            self.add_error({
                "file": target_path,
                "message": str(e),
                "type": type(e).__name__
            })
            
            # End the scan
            return self.end_scan()
    
    def _collect_files(
        self,
        target_path: str,
        options: Dict[str, Any]
    ) -> List[str]:
        """
        Collect files to scan.
        
        Args:
            target_path: Target path
            options: Scan options
            
        Returns:
            List of file paths to scan
        """
        files_to_scan = []
        
        # Check if the target is a file
        if os.path.isfile(target_path):
            # Just scan this file if it matches our criteria
            if self._should_scan_file(target_path):
                files_to_scan.append(target_path)
            return files_to_scan
        
        # Target is a directory, so collect files recursively
        recursive = options.get("recursive", True)
        
        if recursive:
            # Walk through the directory tree
            for root, dirs, files in os.walk(target_path):
                # Remove excluded directories
                for excluded_dir in self.excluded_dirs:
                    if excluded_dir in dirs:
                        dirs.remove(excluded_dir)
                
                # Add files
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._should_scan_file(file_path):
                        files_to_scan.append(file_path)
        else:
            # Only scan files in the top directory
            for item in os.listdir(target_path):
                item_path = os.path.join(target_path, item)
                if os.path.isfile(item_path) and self._should_scan_file(item_path):
                    files_to_scan.append(item_path)
        
        return files_to_scan
    
    def _should_scan_file(self, file_path: str) -> bool:
        """
        Check if a file should be scanned.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if the file should be scanned, False otherwise
        """
        # Get file name and extension
        file_name = os.path.basename(file_path)
        _, file_ext = os.path.splitext(file_name.lower())
        
        # Check exclusions
        if file_name in self.excluded_files:
            return False
        
        if file_ext in self.excluded_extensions:
            return False
        
        # Check inclusions (if specified)
        if self.included_extensions and file_ext not in self.included_extensions:
            return False
        
        # Check file size
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size:
                self.logger.debug(f"Skipping large file: {file_path} ({file_size} bytes)")
                return False
            
            if file_size == 0:
                self.logger.debug(f"Skipping empty file: {file_path}")
                return False
        except OSError:
            self.logger.warning(f"Cannot access file: {file_path}")
            return False
        
        # Check if the file is a text file or other supported type
        if file_ext in self.TEXT_EXTENSIONS:
            return True
        
        # Check MIME type
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type and mime_type.startswith(('text/', 'application/json', 'application/xml')):
            return True
        
        # For document types, we need specific handling
        if file_ext in self.DOCUMENT_EXTENSIONS:
            # This is a placeholder - in a real implementation, we would check
            # if we have the necessary libraries to extract text from documents
            self.logger.debug(f"Document type not yet supported: {file_path}")
            return False
        
        return False
    
    def _scan_file(self, file_path: str) -> None:
        """
        Scan a file for sensitive data.
        
        Args:
            file_path: Path to the file
        """
        self.logger.debug(f"Scanning file: {file_path}")
        
        try:
            # Get file metadata
            file_stat = os.stat(file_path)
            file_created = datetime.datetime.fromtimestamp(file_stat.st_ctime)
            file_modified = datetime.datetime.fromtimestamp(file_stat.st_mtime)
            
            # Open file and scan line by line
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    # Skip lines that are too long
                    if len(line) > self.max_line_length:
                        continue
                    
                    # Scan the line for each pattern
                    for pattern in self.patterns:
                        for match in pattern.regex.finditer(line):
                            # Create finding
                            finding = self._create_finding(
                                file_path=file_path,
                                line_num=line_num,
                                match=match,
                                line=line,
                                pattern=pattern,
                                file_created=file_created,
                                file_modified=file_modified
                            )
                            
                            # Add the finding
                            self.add_finding(finding)
            
            # Increment scanned items
            self.increment_scanned_items()
            
        except UnicodeDecodeError:
            # File is not text-based
            self.logger.debug(f"File is not text-based: {file_path}")
            self.increment_scanned_items()
            
        except Exception as e:
            # Log error and continue
            self.logger.error(f"Error scanning file {file_path}: {str(e)}")
            self.add_error({
                "file": file_path,
                "message": str(e),
                "type": type(e).__name__
            })
            self.increment_scanned_items()
    
    def _create_finding(
        self,
        file_path: str,
        line_num: int,
        match: re.Match,
        line: str,
        pattern: DataPattern,
        file_created: datetime.datetime,
        file_modified: datetime.datetime
    ) -> SensitiveDataFinding:
        """
        Create a finding for sensitive data.
        
        Args:
            file_path: Path to the file
            line_num: Line number
            match: Regex match object
            line: The full line of text
            pattern: The matching pattern
            file_created: File creation time
            file_modified: File modification time
            
        Returns:
            SensitiveDataFinding object
        """
        # Get match context
        start, end = match.span()
        column = start + 1
        
        # Create context with match highlighted
        context_start = max(0, start - 20)
        context_end = min(len(line), end + 20)
        context = line[context_start:context_end].strip()
        
        # Create masked context
        masked_context = self._mask_sensitive_data(context, match, pattern)
        
        # Get owner (placeholder - in a real implementation, we might look up file ownership)
        try:
            owner = "unknown"  # Would use something like getpwuid(os.stat(file_path).st_uid).pw_name
        except:
            owner = "unknown"
        
        # Calculate risk level
        context_info = {
            "public_access": False,  # This would be determined by file permissions
            "file_type": os.path.splitext(file_path)[1],
            "in_version_control": ".git" in file_path.split(os.path.sep)
        }
        
        risk_level = self.calculate_risk_level(
            pattern.name,
            1.0,  # High confidence for regex matches
            context_info
        )
        
        # Create finding
        finding = SensitiveDataFinding(
            finding_id=f"finding-{uuid.uuid4()}",
            timestamp=datetime.datetime.now(),
            scanner_id=self.scanner_id,
            data_type=pattern.name,
            confidence=1.0,  # High confidence for regex matches
            source_type="file",
            location=file_path,
            line_number=line_num,
            column_number=column,
            context=context,
            masked_context=masked_context,
            owner=owner,
            created_date=file_created,
            modified_date=file_modified,
            risk_level=risk_level,
            risk_factors=context_info,
            compliance_frameworks=pattern.compliance_frameworks
        )
        
        return finding
    
    def _mask_sensitive_data(
        self,
        text: str,
        match: re.Match,
        pattern: DataPattern
    ) -> str:
        """
        Mask sensitive data in text.
        
        Args:
            text: Text to mask
            match: Regex match object
            pattern: Pattern that matched
            
        Returns:
            Text with sensitive data masked
        """
        sensitive_data = match.group(0)
        masked_data = pattern.masked_format
        
        # Replace placeholders in the mask format
        if "{type}" in masked_data:
            masked_data = masked_data.replace("{type}", pattern.name)
        
        if "{last4}" in masked_data and len(sensitive_data) >= 4:
            masked_data = masked_data.replace("{last4}", sensitive_data[-4:])
        
        if "{last_octet}" in masked_data and "." in sensitive_data:
            masked_data = masked_data.replace("{last_octet}", sensitive_data.split(".")[-1])
        
        if "{username_prefix}" in masked_data and "@" in sensitive_data:
            username = sensitive_data.split("@")[0]
            prefix = username[:min(3, len(username))]
            masked_data = masked_data.replace("{username_prefix}", prefix)
        
        if "{domain}" in masked_data and "@" in sensitive_data:
            domain = sensitive_data.split("@")[1]
            masked_data = masked_data.replace("{domain}", domain)
        
        # Replace the sensitive data with the mask
        start, end = match.span()
        relative_start = text.find(sensitive_data)
        if relative_start >= 0:
            masked_text = text[:relative_start] + masked_data + text[relative_start + len(sensitive_data):]
            return masked_text
        
        # Fallback if we couldn't find the exact match
        return text.replace(sensitive_data, masked_data) 