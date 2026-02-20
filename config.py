#!/usr/bin/env python3
"""
Configuration settings for Smart File Integrity & Forensic System
"""

import os
from datetime import timedelta

class SystemConfig:
    """System configuration settings"""
    
    # System information
    SYSTEM_NAME = "SmartFileGuard"
    VERSION = "2.1.0"
    
    # File monitoring settings
    MONITOR_PATHS = [
        '/etc',  # Linux system configs
        '/home',  # User files
        '/var/log',  # Log files
    ]
    
    # For Windows, you might want:
    # MONITOR_PATHS = [
    #     'C:\\Windows\\System32\\drivers\\etc',
    #     'C:\\Users',
    #     'C:\\ProgramData',
    # ]
    
    # Scan interval in seconds
    FILE_SCAN_INTERVAL = 3600  # 1 hour
    
    # Hash settings
    HASH_ALGORITHM = 'sha256'  # Can be 'md5', 'sha1', 'sha256', 'sha512'
    
    # Database settings
    DB_PATH = 'forensic_data.db'
    DB_BACKUP_INTERVAL = 86400  # 24 hours
    MAX_HISTORY_DAYS = 90  # Keep 90 days of history
    
    # Alert settings
    ALERT_EMAIL = None  # Set to your email for alerts, e.g., 'admin@example.com'
    ALERT_THRESHOLD = 0.7  # Risk score threshold for alerts (0.0 to 1.0)
    
    # Email configuration (if using email alerts)
    SMTP_SERVER = 'smtp.gmail.com'
    SMTP_PORT = 587
    SMTP_USERNAME = None  # Your email username
    SMTP_PASSWORD = None  # Your email password
    EMAIL_FROM = None  # From email address
    
    # Real-time monitoring
    REALTIME_BUFFER_SIZE = 100  # Number of events to keep in memory
    
    # Risk scoring
    DEFAULT_RISK_SCORE = 0.5
    HIGH_RISK_EXTENSIONS = ['.exe', '.dll', '.so', '.conf', '.key', '.pem']
    
    # Report settings
    REPORT_DIR = 'reports'
    MAX_REPORTS_TO_KEEP = 50  # Maximum number of reports to keep
    
    @classmethod
    def validate(cls):
        """Validate configuration settings"""
        if cls.HASH_ALGORITHM not in ['md5', 'sha1', 'sha256', 'sha512']:
            raise ValueError(f"Invalid hash algorithm: {cls.HASH_ALGORITHM}")
        
        if cls.ALERT_THRESHOLD < 0 or cls.ALERT_THRESHOLD > 1:
            raise ValueError(f"Alert threshold must be between 0 and 1: {cls.ALERT_THRESHOLD}")
        
        # Check if monitored paths exist
        for path in cls.MONITOR_PATHS:
            if not os.path.exists(path):
                print(f"Warning: Monitored path does not exist: {path}")
#!/usr/bin/env python3
"""
Configuration settings for Smart File Integrity & Forensic System
"""

import os
from datetime import timedelta

class SystemConfig:
    """System configuration settings"""
    
    # System information
    SYSTEM_NAME = "SmartFileGuard"
    VERSION = "2.1.0"
    
    # File monitoring settings
    MONITOR_PATHS = [
        '/etc',  # Linux system configs
        '/home',  # User files
        '/var/log',  # Log files
    ]
    
    # For Windows, you might want:
    # MONITOR_PATHS = [
    #     'C:\\Windows\\System32\\drivers\\etc',
    #     'C:\\Users',
    #     'C:\\ProgramData',
    # ]
    
    # Scan interval in seconds
    FILE_SCAN_INTERVAL = 3600  # 1 hour
    
    # Hash settings
    HASH_ALGORITHM = 'sha256'  # Can be 'md5', 'sha1', 'sha256', 'sha512'
    
    # Database settings - support both DB_PATH and DB_NAME for compatibility
    DB_PATH = 'forensic_data.db'
    DB_NAME = 'forensic_data.db'  # Alias for backward compatibility
    DB_BACKUP_INTERVAL = 86400  # 24 hours
    MAX_HISTORY_DAYS = 90  # Keep 90 days of history
    
    # Alert settings
    ALERT_EMAIL = None  # Set to your email for alerts, e.g., 'admin@example.com'
    ALERT_THRESHOLD = 0.7  # Risk score threshold for alerts (0.0 to 1.0)
    
    # Email configuration - Dictionary format expected by alerts.py
    EMAIL_SETTINGS = {
        'enabled': False,  # Set to True to enable email alerts
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'username': None,  # Your email username
        'password': None,  # Your email password
        'from_addr': None,  # From email address
        'to_addr': None,  # Recipient email address (same as ALERT_EMAIL)
        'use_tls': True
    }
    
    # Email configuration (legacy individual settings)
    SMTP_SERVER = 'smtp.gmail.com'
    SMTP_PORT = 587
    SMTP_USERNAME = None  # Your email username
    SMTP_PASSWORD = None  # Your email password
    EMAIL_FROM = None  # From email address
    
    # Real-time monitoring
    REALTIME_BUFFER_SIZE = 100  # Number of events to keep in memory
    
    # Risk scoring
    DEFAULT_RISK_SCORE = 0.5
    HIGH_RISK_EXTENSIONS = ['.exe', '.dll', '.so', '.conf', '.key', '.pem']
    
    # Report settings
    REPORT_DIR = 'reports'
    MAX_REPORTS_TO_KEEP = 50  # Maximum number of reports to keep
    
    @classmethod
    def validate(cls):
        """Validate configuration settings"""
        if cls.HASH_ALGORITHM not in ['md5', 'sha1', 'sha256', 'sha512']:
            raise ValueError(f"Invalid hash algorithm: {cls.HASH_ALGORITHM}")
        
        if cls.ALERT_THRESHOLD < 0 or cls.ALERT_THRESHOLD > 1:
            raise ValueError(f"Alert threshold must be between 0 and 1: {cls.ALERT_THRESHOLD}")
        
        # Update EMAIL_SETTINGS with ALERT_EMAIL if set
        if cls.ALERT_EMAIL and cls.EMAIL_SETTINGS['to_addr'] is None:
            cls.EMAIL_SETTINGS['to_addr'] = cls.ALERT_EMAIL
            cls.EMAIL_SETTINGS['enabled'] = True
        
        # Check if monitored paths exist
        for path in cls.MONITOR_PATHS:
            if not os.path.exists(path):
                print(f"Warning: Monitored path does not exist: {path}")