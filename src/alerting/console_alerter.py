"""
Console Alerter for Enterprise SIEM Platform.
"""
import logging
import datetime
import time
import colorama

# Initialize colorama
colorama.init()

class ConsoleAlerter:
    """
    Sends alerts to the console with colored output.
    """
    
    # ANSI color codes
    COLORS = {
        'low': colorama.Fore.BLUE,
        'medium': colorama.Fore.YELLOW,
        'high': colorama.Fore.RED,
        'critical': colorama.Fore.RED + colorama.Style.BRIGHT,
        'reset': colorama.Style.RESET_ALL
    }
    
    def __init__(self, config):
        """
        Initialize the Console Alerter.
        
        Args:
            config (dict): Configuration for the alerter
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.use_colors = config.get('colors', True)
    
    def format_alert(self, alert):
        """
        Format an alert for console output.
        
        Args:
            alert: The alert event
            
        Returns:
            str: Formatted alert string
        """
        timestamp = alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        severity = alert.severity.upper()
        
        # Apply colors if enabled
        if self.use_colors:
            color = self.COLORS.get(alert.severity, self.COLORS['reset'])
            reset = self.COLORS['reset']
            header = f"{color}[{timestamp}] [{severity}] ALERT: {reset}"
        else:
            header = f"[{timestamp}] [{severity}] ALERT: "
        
        # Format the message
        message = alert.message
        
        # Add details for threshold alerts
        if alert.event_type == 'threshold_alert' and 'raw_data' in alert.raw_data:
            raw_data = alert.raw_data
            rule_name = raw_data.get('rule_name', 'Unknown Rule')
            
            # Add matched events if available
            matched_events = raw_data.get('matched_events', [])
            if matched_events:
                message += "\n\nMatched Events:"
                for i, event_dict in enumerate(matched_events):
                    event_message = event_dict.get('message', '')
                    if len(event_message) > 100:
                        event_message = event_message[:97] + '...'
                    
                    message += f"\n  {i+1}. {event_message}"
        
        return header + message
    
    def send_alert(self, alert):
        """
        Send an alert to the console.
        
        Args:
            alert: The alert event
            
        Returns:
            bool: True if the alert was sent successfully, False otherwise
        """
        try:
            # Format the alert
            alert_str = self.format_alert(alert)
            
            # Print the alert
            print("\n" + alert_str + "\n")
            
            return True
        except Exception as e:
            self.logger.error(f"Error sending console alert: {str(e)}")
            return False
    
    def run_alerter(self, alert_queue):
        """
        Run the alerter continuously, processing alerts from the queue.
        
        Args:
            alert_queue: Queue to get alerts from
        """
        self.logger.info("Starting Console Alerter")
        
        while True:
            try:
                # Get an alert from the queue (if available)
                if not alert_queue.empty():
                    alert = alert_queue.get()
                    
                    # Send the alert
                    self.send_alert(alert)
                
                # Sleep briefly
                time.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Error in Console Alerter: {str(e)}")
                time.sleep(1)  # Sleep briefly before retrying 