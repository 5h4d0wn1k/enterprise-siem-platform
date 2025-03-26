"""
Configuration loader for Enterprise SIEM Platform.
Loads and validates YAML configuration files.
"""

import os
import yaml
import logging
from typing import Dict, Any, List, Optional

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path (str, optional): Path to the configuration file. If None, uses default.
    
    Returns:
        dict: Loaded configuration
    
    Raises:
        FileNotFoundError: If the configuration file does not exist
        yaml.YAMLError: If the configuration file is not valid YAML
    """
    logger = logging.getLogger('siem.config')
    
    if config_path is None:
        # Get the directory of the current file
        current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(current_dir, 'config', 'config.yaml')
    
    # Check if the config file exists
    if not os.path.exists(config_path):
        logger.error(f"Configuration file not found: {config_path}")
        # Return a minimal default configuration
        return get_default_config()
    
    # Load the config file
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_path}")
            
            # Validate the configuration
            validate_config(config)
            
            return config
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file: {e}")
        return get_default_config()
    except Exception as e:
        logger.error(f"Error loading configuration file: {e}")
        return get_default_config()

def get_default_config() -> Dict[str, Any]:
    """
    Get a minimal default configuration.
    
    Returns:
        dict: Default configuration
    """
    return {
        'general': {
            'log_level': 'INFO',
            'log_file': 'data/logs/siem.log',
            'data_dir': 'data',
            'temp_dir': 'temp'
        },
        'collectors': {
            'windows_event': {'enable': False},
            'file': {'enable': False}
        },
        'analyzers': {
            'threshold': {'enable': False}
        },
        'alerters': {
            'console': {'enable': True},
            'email': {'enable': False}
        },
        'dashboard': {
            'enable': True,
            'host': '127.0.0.1',
            'port': 5000
        }
    }

def validate_config(config: Dict[str, Any]) -> None:
    """
    Validate the configuration structure.
    
    Args:
        config (dict): Configuration to validate
    
    Raises:
        ValueError: If the configuration is invalid
    """
    logger = logging.getLogger('siem.config')
    
    # Required top-level sections
    required_sections = ['general', 'collectors', 'analyzers', 'alerters', 'dashboard']
    
    # Check for required sections
    for section in required_sections:
        if section not in config:
            logger.warning(f"Missing required configuration section: {section}")
            # Create empty section to prevent errors
            config[section] = {}
    
    # Ensure general section has required fields
    if 'general' in config:
        general = config['general']
        
        # Set defaults if not provided
        if 'log_level' not in general:
            general['log_level'] = 'INFO'
            logger.info("Using default log level: INFO")
        
        if 'data_dir' not in general:
            general['data_dir'] = 'data'
            logger.info("Using default data directory: data")
        
        if 'temp_dir' not in general:
            general['temp_dir'] = 'temp'
            logger.info("Using default temp directory: temp")
        
        if 'log_file' not in general:
            general['log_file'] = os.path.join(general['data_dir'], 'logs', 'siem.log')
            logger.info(f"Using default log file: {general['log_file']}")
    
    # Ensure dashboard section exists
    if 'dashboard' not in config:
        config['dashboard'] = {
            'enable': True,
            'host': '127.0.0.1',
            'port': 5000
        }
        logger.info("Using default dashboard configuration")
    
    # Convert old configuration format if needed
    convert_old_config_format(config)

def convert_old_config_format(config: Dict[str, Any]) -> None:
    """
    Convert old configuration format to new format.
    
    Args:
        config (dict): Configuration to convert
    """
    logger = logging.getLogger('siem.config')
    
    # Convert general section
    if 'general' in config:
        general = config['general']
        if 'data_directory' in general and 'data_dir' not in general:
            general['data_dir'] = general.pop('data_directory')
            logger.info("Converted data_directory to data_dir")
        if 'temp_directory' in general and 'temp_dir' not in general:
            general['temp_dir'] = general.pop('temp_directory')
            logger.info("Converted temp_directory to temp_dir")
    
    # Convert collector format
    if 'collectors' in config:
        collectors = config['collectors']
        for collector_name, collector_config in collectors.items():
            if isinstance(collector_config, dict):
                if 'enabled' in collector_config and 'enable' not in collector_config:
                    collector_config['enable'] = collector_config.pop('enabled')
                    logger.info(f"Converted 'enabled' to 'enable' in {collector_name} collector")
    
    # Convert analyzer format
    if 'analyzers' in config:
        analyzers = config['analyzers']
        for analyzer_name, analyzer_config in analyzers.items():
            if isinstance(analyzer_config, dict):
                if 'enabled' in analyzer_config and 'enable' not in analyzer_config:
                    analyzer_config['enable'] = analyzer_config.pop('enabled')
                    logger.info(f"Converted 'enabled' to 'enable' in {analyzer_name} analyzer")
    
    # Convert alerter format from old 'alerting' section
    if 'alerting' in config:
        alerting = config.pop('alerting')
        if 'alerters' not in config:
            config['alerters'] = {}
        
        # Convert console alerter
        if 'console' in alerting:
            console = alerting['console']
            if isinstance(console, dict):
                if 'enabled' in console:
                    config['alerters']['console'] = {
                        'enable': console.pop('enabled')
                    }
                    # Copy other settings
                    for key, value in console.items():
                        config['alerters']['console'][key] = value
                    logger.info("Converted console alerter from alerting section")
        
        # Convert email alerter
        if 'email' in alerting:
            email = alerting['email']
            if isinstance(email, dict):
                if 'enabled' in email:
                    config['alerters']['email'] = {
                        'enable': email.pop('enabled')
                    }
                    # Copy other settings
                    for key, value in email.items():
                        config['alerters']['email'][key] = value
                    logger.info("Converted email alerter from alerting section")
        
        # Convert other alerters
        for alerter_name, alerter_config in alerting.items():
            if alerter_name not in ['console', 'email'] and isinstance(alerter_config, dict):
                if 'enabled' in alerter_config:
                    config['alerters'][alerter_name] = {
                        'enable': alerter_config.pop('enabled')
                    }
                    # Copy other settings
                    for key, value in alerter_config.items():
                        config['alerters'][alerter_name][key] = value
                    logger.info(f"Converted {alerter_name} alerter from alerting section")

def setup_logging(config: Dict[str, Any]) -> None:
    """
    Set up logging based on configuration.
    
    Args:
        config (dict): Configuration dictionary
    """
    # Get log level
    log_level_name = config.get('general', {}).get('log_level', 'INFO')
    log_level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    log_level = log_level_map.get(log_level_name, logging.INFO)
    
    # Get log file
    log_file = config.get('general', {}).get('log_file')
    
    # Configure logging
    handlers = [logging.StreamHandler()]
    
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers
    )
    
    logging.info(f"Logging initialized at {log_level_name} level")

def ensure_directories(config: Dict[str, Any]) -> None:
    """
    Ensure required directories exist.
    
    Args:
        config (dict): Configuration dictionary
    """
    # Add general directories
    general = config.get('general', {})
    data_dir = general.get('data_dir', 'data')
    temp_dir = general.get('temp_dir', 'temp')
    log_file = general.get('log_file')
    
    directories = [data_dir, temp_dir]
    
    # Add log directory if specified
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            directories.append(log_dir)
    
    # Create directories
    for directory in directories:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                logging.info(f"Created directory: {directory}")
            except Exception as e:
                logging.error(f"Failed to create directory {directory}: {str(e)}")

def get_enabled_collectors(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Get a list of enabled collector configurations.
    
    Args:
        config (dict): Full configuration
    
    Returns:
        list: List of enabled collector configurations
    """
    enabled_collectors = []
    
    if 'collectors' not in config:
        return enabled_collectors
    
    for collector_name, collector_config in config['collectors'].items():
        # Skip non-dictionary values
        if not isinstance(collector_config, dict):
            continue
            
        # Check if the collector is enabled
        if collector_config.get('enable', False):
            # Add the collector name to the config
            collector_config['name'] = collector_name
            enabled_collectors.append(collector_config)
    
    return enabled_collectors

def get_enabled_analyzers(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Get a list of enabled analyzer configurations.
    
    Args:
        config (dict): Full configuration
    
    Returns:
        list: List of enabled analyzer configurations
    """
    enabled_analyzers = []
    
    if 'analyzers' not in config:
        return enabled_analyzers
    
    for analyzer_name, analyzer_config in config['analyzers'].items():
        # Skip non-dictionary values
        if not isinstance(analyzer_config, dict):
            continue
            
        # Check if the analyzer is enabled
        if analyzer_config.get('enable', False):
            # Add the analyzer name to the config
            analyzer_config['name'] = analyzer_name
            enabled_analyzers.append(analyzer_config)
    
    return enabled_analyzers

def get_enabled_alerters(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Get a list of enabled alerter configurations.
    
    Args:
        config (dict): Full configuration
    
    Returns:
        list: List of enabled alerter configurations
    """
    enabled_alerters = []
    
    if 'alerters' not in config:
        return enabled_alerters
    
    for alerter_name, alerter_config in config['alerters'].items():
        # Skip non-dictionary values
        if not isinstance(alerter_config, dict):
            continue
            
        # Check if the alerter is enabled
        if alerter_config.get('enable', False):
            # Add the alerter name to the config
            alerter_config['name'] = alerter_name
            enabled_alerters.append(alerter_config)
    
    return enabled_alerters

def save_config(config: Dict[str, Any], config_path: str) -> None:
    """
    Save configuration to a YAML file.
    
    Args:
        config (dict): Configuration to save
        config_path (str): Path to save the configuration to
    
    Raises:
        IOError: If the configuration file cannot be written
    """
    logger = logging.getLogger('siem.config')
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
    
    # Save the config file
    try:
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
            logger.info(f"Configuration saved to {config_path}")
    except IOError as e:
        logger.error(f"Error saving configuration file: {e}")
        raise 