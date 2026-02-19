#!/usr/bin/env python3
"""
Collectors Module
Handles audit data collection and user attribution
"""

import os
import sys
import platform
import logging
import uuid
import subprocess
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Optional imports
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class AuditDataCollector:
    """Collects user attribution data"""
    
    def __init__(self):
        self.system = platform.system()
        logger.info(f"Audit collector initialized for {self.system}")
    
    def collect_audit_data(self, file_path: str, event_type: str) -> Dict:
        """Collect audit data for a file event"""
        process_info = self._get_process_info()
        
        audit_data = {
            'timestamp': datetime.now(),
            'file_path': file_path,
            'event_type': event_type,
            'user': self._get_current_user(),
            'session_id': self._get_session_id(),
            'process_name': process_info.get('name', 'Unknown'),
            'process_id': process_info.get('pid', -1),
            'command_line': self._get_command_line(),
            'event_id': str(uuid.uuid4())
        }
        
        return audit_data
    
    def _get_current_user(self) -> str:
        """Get current user"""
        try:
            import getpass
            return getpass.getuser()
        except:
            return "Unknown"
    
    def _get_session_id(self) -> str:
        """Get session ID"""
        try:
            if self.system == "Linux":
                return os.environ.get('SSH_CONNECTION', 'local')
            return "Unknown"
        except:
            return "Unknown"
    
    def _get_process_info(self) -> Dict:
        """Get process information"""
        if not PSUTIL_AVAILABLE:
            return {'name': 'Unknown', 'pid': -1}
        
        try:
            proc = psutil.Process(os.getpid())
            return {
                'name': proc.name(),
                'pid': os.getpid(),
                'exe': proc.exe() if proc.exe() else 'Unknown'
            }
        except Exception:
            return {'name': 'Unknown', 'pid': -1}
    
    def _get_command_line(self) -> str:
        """Get command line"""
        return ' '.join(sys.argv)