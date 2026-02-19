#!/usr/bin/env python3
"""
Alerts Module
Handles email notifications for security alerts
"""

import os
import ssl
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict

from config import SystemConfig

logger = logging.getLogger(__name__)


class EmailAlertSystem:
    """Handles sending email alerts"""
    
    def __init__(self):
        self.settings = SystemConfig.EMAIL_SETTINGS
    
    def send_alert(self, subject: str, body: str) -> bool:
        """Send email alert"""
        if not SystemConfig.ALERT_EMAIL:
            logger.info("Email alerts disabled")
            return False
        
        if not self.settings['sender_email'] or not self.settings['sender_password']:
            logger.warning("Email credentials not configured")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{SystemConfig.SYSTEM_NAME}] {subject}"
            msg['From'] = self.settings['sender_email']
            msg['To'] = ', '.join(self.settings['admin_emails'])
            
            # Plain text version
            text_part = MIMEText(body, 'plain')
            msg.attach(text_part)
            
            # HTML version
            html_body = f"""
            <html>
            <body>
                <h2>{SystemConfig.SYSTEM_NAME} Security Alert</h2>
                <pre>{body}</pre>
                <hr>
                <small>Sent at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
            </body>
            </html>
            """
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            # Send email
            context = ssl.create_default_context()
            with smtplib.SMTP(self.settings['smtp_server'], self.settings['smtp_port']) as server:
                server.ehlo()
                if self.settings.get('use_tls', True):
                    server.starttls(context=context)
                    server.ehlo()
                server.login(self.settings['sender_email'], self.settings['sender_password'])
                server.send_message(msg)
            
            logger.info(f"Alert sent: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def send_test_alert(self) -> bool:
        """Send test email"""
        subject = "Test Alert - Configuration Check"
        body = f"""
        This is a test email from {SystemConfig.SYSTEM_NAME}.
        
        System: {platform.node()}
        Platform: {platform.system()}
        Time: {datetime.now()}
        
        If you receive this, email alerts are working!
        """
        return self.send_alert(subject, body)
    
    def send_high_risk_alert(self, change_data: Dict) -> bool:
        """Send alert for high-risk change"""
        subject = f"HIGH RISK: {change_data['change_type']} - {os.path.basename(change_data['file_path'])}"
        
        body = f"""
        HIGH RISK FILE CHANGE DETECTED
        
        File: {change_data['file_path']}
        Change Type: {change_data['change_type']}
        Risk Score: {change_data.get('risk_score', 0):.1%}
        
        User: {change_data.get('user_name', 'Unknown')}
        Process: {change_data.get('process_name', 'Unknown')} (PID: {change_data.get('process_id', 'N/A')})
        
        Hash (SHA256): {change_data.get('new_hash', 'N/A')[:32]}...
        
        Recommended Action: Investigate immediately.
        """
        
        return self.send_alert(subject, body)