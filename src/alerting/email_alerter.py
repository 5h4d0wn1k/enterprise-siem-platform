"""
Email Alerter for Enterprise SIEM Platform.
"""
import logging
import time
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class EmailAlerter:
    """
    Sends alerts via email.
    """
    
    def __init__(self, config):
        """
        Initialize the Email Alerter.
        
        Args:
            config (dict): Configuration for the alerter
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Email configuration
        self.server = config.get('server', 'localhost')
        self.port = config.get('port', 25)
        self.use_tls = config.get('use_tls', False)
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.from_address = config.get('from_address', 'siem@example.com')
        self.to_addresses = config.get('to_addresses', [])
        
        # Alert batching
        self.alert_buffer = []
        self.last_email_time = None
        self.batch_interval = config.get('batch_interval', 300)  # 5 minutes default
        self.max_batch_size = config.get('max_batch_size', 10)
    
    def format_html_alert(self, alert):
        """
        Format an alert as HTML.
        
        Args:
            alert: The alert event
            
        Returns:
            str: HTML formatted alert
        """
        timestamp = alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        severity = alert.severity.upper()
        
        # Determine severity color
        if alert.severity == 'critical':
            severity_color = '#FF0000'  # Red
        elif alert.severity == 'high':
            severity_color = '#FFA500'  # Orange
        elif alert.severity == 'medium':
            severity_color = '#FFFF00'  # Yellow
        else:
            severity_color = '#0000FF'  # Blue
        
        # Create HTML content
        html = f"""
        <div style="border: 1px solid #ddd; padding: 10px; margin-bottom: 10px;">
            <h3 style="color: {severity_color};">[{severity}] {alert.message}</h3>
            <p><strong>Time:</strong> {timestamp}</p>
            <p><strong>Source:</strong> {alert.source}</p>
            <p><strong>Event Type:</strong> {alert.event_type}</p>
        """
        
        # Add details for threshold alerts
        if alert.event_type == 'threshold_alert' and 'raw_data' in alert.raw_data:
            raw_data = alert.raw_data
            rule_name = raw_data.get('rule_name', 'Unknown Rule')
            threshold = raw_data.get('threshold', 0)
            timeframe = raw_data.get('timeframe', 0)
            event_count = raw_data.get('event_count', 0)
            
            html += f"""
            <div style="background-color: #f8f8f8; padding: 10px; margin-top: 10px;">
                <p><strong>Rule:</strong> {rule_name}</p>
                <p><strong>Threshold:</strong> {threshold} events in {timeframe} seconds</p>
                <p><strong>Events Detected:</strong> {event_count}</p>
            </div>
            """
            
            # Add matched events if available
            matched_events = raw_data.get('matched_events', [])
            if matched_events:
                html += f"""
                <div style="margin-top: 10px;">
                    <h4>Matched Events:</h4>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Time</th>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Source</th>
                            <th style="border: 1px solid #ddd; padding: 8px; text-align: left;">Message</th>
                        </tr>
                """
                
                for event_dict in matched_events:
                    event_time = event_dict.get('timestamp', '')
                    event_source = event_dict.get('source', '')
                    event_message = event_dict.get('message', '')
                    
                    # Truncate long messages
                    if len(event_message) > 100:
                        event_message = event_message[:97] + '...'
                    
                    html += f"""
                        <tr>
                            <td style="border: 1px solid #ddd; padding: 8px;">{event_time}</td>
                            <td style="border: 1px solid #ddd; padding: 8px;">{event_source}</td>
                            <td style="border: 1px solid #ddd; padding: 8px;">{event_message}</td>
                        </tr>
                    """
                
                html += """
                    </table>
                </div>
                """
        
        html += "</div>"
        return html
    
    def format_text_alert(self, alert):
        """
        Format an alert as plain text.
        
        Args:
            alert: The alert event
            
        Returns:
            str: Text formatted alert
        """
        timestamp = alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        severity = alert.severity.upper()
        
        text = f"""
[{severity}] {alert.message}
Time: {timestamp}
Source: {alert.source}
Event Type: {alert.event_type}
        """
        
        # Add details for threshold alerts
        if alert.event_type == 'threshold_alert' and 'raw_data' in alert.raw_data:
            raw_data = alert.raw_data
            rule_name = raw_data.get('rule_name', 'Unknown Rule')
            threshold = raw_data.get('threshold', 0)
            timeframe = raw_data.get('timeframe', 0)
            event_count = raw_data.get('event_count', 0)
            
            text += f"""
Rule: {rule_name}
Threshold: {threshold} events in {timeframe} seconds
Events Detected: {event_count}
            """
            
            # Add matched events if available
            matched_events = raw_data.get('matched_events', [])
            if matched_events:
                text += "\nMatched Events:\n"
                
                for i, event_dict in enumerate(matched_events):
                    event_time = event_dict.get('timestamp', '')
                    event_source = event_dict.get('source', '')
                    event_message = event_dict.get('message', '')
                    
                    # Truncate long messages
                    if len(event_message) > 100:
                        event_message = event_message[:97] + '...'
                    
                    text += f"{i+1}. [{event_time}] {event_source}: {event_message}\n"
        
        return text
    
    def send_email(self, subject, html_content, text_content):
        """
        Send an email with the given content.
        
        Args:
            subject (str): Email subject
            html_content (str): HTML content of the email
            text_content (str): Plain text content of the email
            
        Returns:
            bool: True if the email was sent successfully, False otherwise
        """
        if not self.to_addresses:
            self.logger.warning("No recipients specified for email alert")
            return False
        
        try:
            # Create a multipart message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_address
            msg['To'] = ', '.join(self.to_addresses)
            
            # Attach parts
            part1 = MIMEText(text_content, 'plain')
            part2 = MIMEText(html_content, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Connect to the SMTP server
            server = smtplib.SMTP(self.server, self.port)
            
            if self.use_tls:
                server.starttls()
            
            # Login if credentials were provided
            if self.username and self.password:
                server.login(self.username, self.password)
            
            # Send the email
            server.sendmail(self.from_address, self.to_addresses, msg.as_string())
            server.quit()
            
            self.logger.info(f"Email alert sent to {', '.join(self.to_addresses)}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending email alert: {str(e)}")
            return False
    
    def send_alert(self, alert):
        """
        Process a single alert.
        
        Args:
            alert: The alert event
            
        Returns:
            bool: True if the alert was processed successfully, False otherwise
        """
        try:
            # Add the alert to the buffer
            self.alert_buffer.append(alert)
            
            # Check if we should send a batch of alerts
            should_send = False
            
            # Check batch size
            if len(self.alert_buffer) >= self.max_batch_size:
                should_send = True
            
            # Check batch interval
            import datetime
            current_time = datetime.datetime.now()
            if self.last_email_time is not None:
                time_diff = (current_time - self.last_email_time).total_seconds()
                if time_diff >= self.batch_interval:
                    should_send = True
            
            # Send the batch if conditions are met
            if should_send and self.alert_buffer:
                return self.send_alert_batch()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error processing alert: {str(e)}")
            return False
    
    def send_alert_batch(self):
        """
        Send a batch of alerts.
        
        Returns:
            bool: True if the batch was sent successfully, False otherwise
        """
        if not self.alert_buffer:
            return True
        
        try:
            # Count alerts by severity
            severity_counts = {}
            for alert in self.alert_buffer:
                severity = alert.severity
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Create the subject line
            total_alerts = len(self.alert_buffer)
            if total_alerts == 1:
                subject = f"SIEM Alert: {self.alert_buffer[0].message}"
            else:
                subject = f"SIEM Alert Batch: {total_alerts} alerts"
                
                # Add severity counts
                severity_summary = []
                for severity in ['critical', 'high', 'medium', 'low']:
                    if severity in severity_counts:
                        severity_summary.append(f"{severity_counts[severity]} {severity}")
                
                if severity_summary:
                    subject += f" ({', '.join(severity_summary)})"
            
            # Create the email content
            html_content = """
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; }
                    h2 { color: #333; }
                </style>
            </head>
            <body>
                <h2>SIEM Alert Notification</h2>
                <p>The following security alerts were detected:</p>
            """
            
            text_content = "SIEM Alert Notification\n\n"
            text_content += "The following security alerts were detected:\n\n"
            
            # Add each alert
            for alert in self.alert_buffer:
                html_content += self.format_html_alert(alert)
                text_content += self.format_text_alert(alert) + "\n---\n"
            
            html_content += """
            </body>
            </html>
            """
            
            # Send the email
            result = self.send_email(subject, html_content, text_content)
            
            # Update the last email time and clear the buffer if successful
            if result:
                import datetime
                self.last_email_time = datetime.datetime.now()
                self.alert_buffer = []
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error sending alert batch: {str(e)}")
            return False
    
    def run_alerter(self, alert_queue):
        """
        Run the alerter continuously, processing alerts from the queue.
        
        Args:
            alert_queue: Queue to get alerts from
        """
        self.logger.info("Starting Email Alerter")
        
        while True:
            try:
                # Check if there are any buffered alerts that should be sent
                if self.alert_buffer:
                    import datetime
                    current_time = datetime.datetime.now()
                    
                    if self.last_email_time is None or (current_time - self.last_email_time).total_seconds() >= self.batch_interval:
                        self.send_alert_batch()
                
                # Get an alert from the queue (if available)
                if not alert_queue.empty():
                    alert = alert_queue.get()
                    
                    # Process the alert
                    self.send_alert(alert)
                
                # Sleep briefly
                time.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Error in Email Alerter: {str(e)}")
                time.sleep(1)  # Sleep briefly before retrying 