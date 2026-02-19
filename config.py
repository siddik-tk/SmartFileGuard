#!/usr/bin/env python3
"""
Configuration Module
Centralized configuration settings loaded from environment
"""

import os
import platform
import logging

logger = logging.getLogger(__name__)


class SystemConfig:
    """Central configuration management"""
    
    # System identity
    VERSION = "2.1.0"
    SYSTEM_NAME = "SmartFileGuard"
    
    # Database settings
    DB_NAME = "file_forensics.db"
    DB_BACKUP_COUNT = 7
    
    # Monitoring intervals
    FILE_SCAN_INTERVAL = 30  # seconds
    PROCESS_SCAN_INTERVAL = 60
    NETWORK_SCAN_INTERVAL = 120
    REPORT_INTERVAL = 3600
    
    # What to monitor
    MONITOR_PATHS = []
    EXCLUDE_PATTERNS = [
        '*.tmp', '*.log', '*.cache', '*.swp',
        '.git/*', '__pycache__/*', 'node_modules/*',
        '*.pyc', '.DS_Store', 'Thumbs.db'
    ]
    
    # Critical files
    CRITICAL_FILES = {
        '/etc/passwd', '/etc/shadow', '/etc/hosts',
        '/etc/sudoers', '/etc/crontab',
        '~/.ssh/authorized_keys', '~/.ssh/known_hosts',
    }
    
    # Risk thresholds
    RISK_LOW = 0.3
    RISK_MEDIUM = 0.6
    RISK_HIGH = 0.8
    
    # Email settings - from environment variables
    ALERT_EMAIL = True
    EMAIL_SETTINGS = {
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'sender_email': os.environ.get('SFG_EMAIL'),
        'sender_password': os.environ.get('SFG_EMAIL_PASS'),
        'admin_emails': ['admin@example.com'],
        'use_tls': True,
    }
    
    # Performance
    MAX_FILE_SIZE_MB = 50
    CACHE_SIZE = 10000
    
    # Real-time monitoring
    REALTIME_MONITORING = True
    REALTIME_EVENT_DELAY = 2.0

    @classmethod
    def auto_configure(cls):
        """Auto-configure based on operating system"""
        system = platform.system()
        
        if system == "Linux":
            cls.MONITOR_PATHS = ['/etc', '/usr/bin', '/var/log', os.path.expanduser('~')]
        elif system == "Windows":
            cls.MONITOR_PATHS = [
                os.environ.get('WINDIR', 'C:\\Windows') + '\\System32',
                os.path.expanduser('~\\Documents')
            ]
        elif system == "Darwin":  # macOS
            cls.MONITOR_PATHS = ['/etc', '/usr/bin', '/Applications', os.path.expanduser('~')]
        else:
            cls.MONITOR_PATHS = ['.']
        
        logger.info(f"Auto-configured for {system}")
        
        # Check email credentials
        if cls.ALERT_EMAIL and (not cls.EMAIL_SETTINGS['sender_email'] or 
                                not cls.EMAIL_SETTINGS['sender_password']):
            logger.warning("Email credentials not found in environment variables")
            cls.ALERT_EMAIL = False


# Auto-configure on import
SystemConfig.auto_configure()