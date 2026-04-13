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
    DB_NAME = "forensic_data.db"  # Match your DB_PATH
    DB_BACKUP_COUNT = 7
    
    # Monitoring intervals
    FILE_SCAN_INTERVAL = 30  # seconds
    PROCESS_SCAN_INTERVAL = 60
    NETWORK_SCAN_INTERVAL = 120
    REPORT_INTERVAL = 3600
    
    # What to monitor
    MONITOR_PATHS = []
    
    # 🔥 CRITICAL - EXCLUDE PATTERNS (this was missing!)
    EXCLUDE_PATTERNS = [
        '*.tmp', '*.log', '*.cache', '*.swp',
        '.git/*', '__pycache__/*', 'node_modules/*',
        '*.pyc', '.DS_Store', 'Thumbs.db',
        '*.bak', '*.old', '*.temp'
    ]
    
    # Critical files
    CRITICAL_FILES = {
        '/etc/passwd', '/etc/shadow', '/etc/hosts',
        '/etc/sudoers', '/etc/crontab',
        '~/.ssh/authorized_keys', '~/.ssh/known_hosts',
        'C:\\Windows\\System32\\config\\SAM',
        'C:\\Windows\\System32\\config\\SYSTEM',
    }
    
    # Risk thresholds
    RISK_LOW = 0.3
    RISK_MEDIUM = 0.6
    RISK_HIGH = 0.8
    
    # Email settings
    ALERT_EMAIL = True
    ALERT_THRESHOLD = 0.7
    EMAIL_SETTINGS = {
        'enabled': True,
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'sender_email': os.environ.get('SFG_EMAIL'),
        'sender_password': os.environ.get('SFG_EMAIL_PASS'),
        'admin_emails': ['siddik3tk@gmail.com'],
        'use_tls': True,
    }
    
    # Performance
    MAX_FILE_SIZE_MB = 50
    CACHE_SIZE = 10000
    
    # Real-time monitoring
    REALTIME_MONITORING = True
    REALTIME_EVENT_DELAY = 2.0

    RANSOMWARE_DETECTION = {
    'enabled': True,
    'rename_burst_threshold': 15,      # Files renamed in 10 seconds
    'modify_burst_threshold': 50,      # Files modified in 30 seconds
    'entropy_threshold': 7.0,          # Shannon entropy (0-8)
    'canary_check_interval': 60,       # Seconds between canary checks
    'quarantine_enabled': True,        # Auto-quarantine suspicious processes
    'alert_on_detection': True,        # Send email alerts
    }

    # Known safe processes (won't trigger ransomware alerts)
    SAFE_PROCESSES = [
        'explorer.exe', 'svchost.exe', 'System', 'TrustedInstaller.exe',
        'git.exe', 'python.exe', 'smartfileguard.exe', 'code.exe'
    ]

    # Ransomware note detection patterns
    RANSOM_NOTE_PATTERNS = [
        'README', 'DECRYPT', 'RECOVER', 'RESTORE', 'UNLOCK',
        'HOW_TO', 'HELP', 'INSTRUCTIONS', 'YOUR_FILES',
        'ransom', 'crypt', 'lock', 'pay', 'contact'
    ]
    
    # Report settings
    REPORT_DIR = 'reports'
    MAX_REPORTS_TO_KEEP = 50

    @classmethod
    def auto_configure(cls):
        """Auto-configure based on operating system"""
        system = platform.system()
        
        if system == "Linux":
            cls.MONITOR_PATHS = [
                '/etc/passwd',
                '/etc/sudoers', 
                '/etc/ssh/sshd_config',
                '/etc/crontab',
                '/etc/hosts', 
                '/var/log'
            ]
        elif system == "Windows":
            windir = os.environ.get('WINDIR', 'C:\\Windows')
            cls.MONITOR_PATHS = [
                windir + '\\System32\\drivers\\etc\\hosts',
            ]
        elif system == "Darwin":  # macOS
            cls.MONITOR_PATHS = [
                '/etc/passwd',
                '/etc/sudoers',
                '/etc/hosts', 
                '/etc/ssh/sshd_config',
                os.path.expanduser('~/.ssh/authorized_keys'),
                '/var/log'
            ]
        else:
            cls.MONITOR_PATHS = ['.']
        
        logger.info(f"Auto-configured for {system} with {len(cls.MONITOR_PATHS)} paths")
        
        # Check email credentials
        if cls.EMAIL_SETTINGS['sender_email'] and cls.EMAIL_SETTINGS['sender_password']:
            cls.ALERT_EMAIL = True
            cls.EMAIL_SETTINGS['enabled'] = True
        else:
            cls.ALERT_EMAIL = False
            cls.EMAIL_SETTINGS['enabled'] = False



# Auto-configure on import
SystemConfig.auto_configure()