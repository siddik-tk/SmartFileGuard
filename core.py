#!/usr/bin/env python3
"""
Core Module
Contains the main classes: FileSnapshot, ForensicDatabase, FileMonitor
"""

import os
import sys
import time
import hashlib
import sqlite3
import json
import logging
import platform
from datetime import datetime
from pathlib import Path
from enum import Enum
from typing import Dict, List, Optional, Any
import threading
import queue
from collections import deque 
import queue  

from config import SystemConfig

logger = logging.getLogger(__name__)

# Optional imports
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


class ChangeType(Enum):
    """Types of file changes"""
    CREATED = "CREATED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    MOVED = "MOVED"


class RiskLevel(Enum):
    """Risk assessment levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FileSnapshot:
    """Represents a snapshot of a file at a point in time"""
    
    def __init__(self, file_path: str, previous_hash: str = None):
        self.file_path = os.path.abspath(file_path)
        self.hash_sha256 = None
        self.hash_md5 = None
        self.size = 0
        self.permissions = None
        self.owner = None
        self.group = None
        self.last_modified = None
        self.created = None
        self.content_type = None
        self.risk_score = 0.0
        self.tags = []
        self.previous_snapshot_hash = previous_hash
        self.chain_hash = None
        
        self._collect_metadata()
        self._calculate_chain_hash()
    
    def _collect_metadata(self):
        """Collect all metadata about the file"""
        try:
            if not os.path.exists(self.file_path):
                return
            
            stat = os.stat(self.file_path)
            self.size = stat.st_size
            self.permissions = oct(stat.st_mode)[-3:]
            self.last_modified = datetime.fromtimestamp(stat.st_mtime)
            self.created = datetime.fromtimestamp(stat.st_ctime)
            
            self.hash_sha256 = self._calculate_hash('sha256')
            self.hash_md5 = self._calculate_hash('md5')
            
            self._get_ownership()
            self._detect_content_type()
            self._apply_tags()
            
        except Exception as e:
            logger.error(f"Error collecting metadata for {self.file_path}: {e}")
    
    def _calculate_hash(self, algorithm: str) -> Optional[str]:
        """Calculate file hash"""
        try:
            if self.size > SystemConfig.MAX_FILE_SIZE_MB * 1024 * 1024:
                return None
            
            hasher = hashlib.sha256() if algorithm == 'sha256' else hashlib.md5()
            
            with open(self.file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            
            return hasher.hexdigest()
        except Exception:
            return None
    
    def _calculate_chain_hash(self):
        """Calculate hash chain for tamper-proof evidence"""
        if not self.hash_sha256:
            return
        
        timestamp_str = self.last_modified.isoformat() if self.last_modified else datetime.now().isoformat()
        chain_data = f"{self.hash_sha256}{self.previous_snapshot_hash or ''}{timestamp_str}"
        self.chain_hash = hashlib.sha256(chain_data.encode()).hexdigest()
    
    def _get_ownership(self):
        """Get file owner and group"""
        try:
            if platform.system() == "Windows":
                self.owner = "Unknown"
                self.group = "Unknown"
            else:
                import pwd, grp
                stat = os.stat(self.file_path)
                self.owner = pwd.getpwuid(stat.st_uid).pw_name
                self.group = grp.getgrgid(stat.st_gid).gr_name
        except Exception:
            self.owner = "Unknown"
            self.group = "Unknown"
    
    def _detect_content_type(self):
        """Detect file content type"""
        try:
            import mimetypes
            mime_type, _ = mimetypes.guess_type(self.file_path)
            self.content_type = mime_type or "unknown"
        except Exception:
            self.content_type = "unknown"
    
    def _apply_tags(self):
        """Apply tags based on file properties"""
        for critical in SystemConfig.CRITICAL_FILES:
            if critical in self.file_path:
                self.tags.append('critical')
                self.risk_score = max(self.risk_score, 0.7)
                break
        
        if self.permissions and 'x' in self.permissions:
            self.tags.append('executable')
            self.risk_score = max(self.risk_score, 0.3)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage"""
        return {
            'path': self.file_path,
            'sha256': self.hash_sha256,
            'md5': self.hash_md5,
            'size': self.size,
            'permissions': self.permissions,
            'owner': self.owner,
            'group': self.group,
            'last_modified': self.last_modified.isoformat() if self.last_modified else None,
            'created': self.created.isoformat() if self.created else None,
            'content_type': self.content_type,
            'risk_score': self.risk_score,
            'tags': ','.join(self.tags),
            'previous_snapshot_hash': self.previous_snapshot_hash,
            'chain_hash': self.chain_hash
        }


class ForensicDatabase:
    """Manages all forensic data storage"""
    
    def __init__(self, db_path: str = SystemConfig.DB_NAME):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # File snapshots table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                snapshot_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                hash_sha256 TEXT,
                hash_md5 TEXT,
                file_size INTEGER,
                permissions TEXT,
                owner TEXT,
                group_name TEXT,
                last_modified DATETIME,
                created_time DATETIME,
                content_type TEXT,
                risk_score REAL DEFAULT 0.0,
                tags TEXT,
                previous_snapshot_hash TEXT,
                chain_hash TEXT UNIQUE,
                audit_user TEXT,
                audit_process TEXT,
                UNIQUE(file_path, snapshot_time)
            )
        ''')
        
        # Change events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS change_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                change_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                process_name TEXT,
                process_id INTEGER,
                user_name TEXT,
                command_line TEXT,
                risk_score REAL DEFAULT 0.0,
                risk_level TEXT,
                audit_user TEXT,
                audit_session_id TEXT,
                audit_event_id TEXT
            )
        ''')
        
        # Security alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                file_path TEXT,
                process_name TEXT,
                user_name TEXT,
                risk_score REAL,
                resolved BOOLEAN DEFAULT 0,
                email_sent BOOLEAN DEFAULT 0
            )
        ''')
        
        # Audit logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                user_name TEXT,
                session_id TEXT,
                process_name TEXT,
                command_line TEXT,
                target_path TEXT,
                event_id TEXT
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_path ON file_snapshots(file_path)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_chain_hash ON file_snapshots(chain_hash)')
        
        conn.commit()
        conn.close()
        
        logger.info(f"Database initialized: {self.db_path}")
    
    def save_snapshot(self, snapshot: FileSnapshot, audit_data: Dict = None):
        """Save a file snapshot to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        data = snapshot.to_dict()
        
        cursor.execute('''
            INSERT INTO file_snapshots 
            (file_path, hash_sha256, hash_md5, file_size, permissions, 
             owner, group_name, last_modified, created_time, content_type, 
             risk_score, tags, previous_snapshot_hash, chain_hash, 
             audit_user, audit_process)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['path'], data['sha256'], data['md5'], data['size'],
            data['permissions'], data['owner'], data['group'],
            data['last_modified'], data['created'], data['content_type'],
            data['risk_score'], data['tags'], data['previous_snapshot_hash'],
            data['chain_hash'],
            audit_data.get('user') if audit_data else None,
            audit_data.get('process_name') if audit_data else None
        ))
        
        conn.commit()
        conn.close()
    
    def log_change(self, change_data: Dict):
        """Log a file change event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO change_events 
            (change_type, file_path, old_hash, new_hash, process_name,
             process_id, user_name, command_line, risk_score, risk_level,
             audit_user, audit_session_id, audit_event_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            change_data['change_type'],
            change_data['file_path'],
            change_data.get('old_hash'),
            change_data.get('new_hash'),
            change_data.get('process_name'),
            change_data.get('process_id'),
            change_data.get('user_name'),
            change_data.get('command_line'),
            change_data.get('risk_score', 0.0),
            change_data.get('risk_level'),
            change_data.get('audit_user'),
            change_data.get('audit_session_id'),
            change_data.get('audit_event_id')
        ))
        
        change_id = cursor.lastrowid
        
        # If high risk, create alert
        if change_data.get('risk_score', 0.0) >= SystemConfig.RISK_HIGH:
            cursor.execute('''
                INSERT INTO security_alerts 
                (alert_type, description, severity, file_path, 
                 process_name, user_name, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                'SUSPICIOUS_FILE_CHANGE',
                f"{change_data['change_type']} of {os.path.basename(change_data['file_path'])}",
                'HIGH',
                change_data['file_path'],
                change_data.get('process_name'),
                change_data.get('user_name'),
                change_data.get('risk_score')
            ))
        
        conn.commit()
        conn.close()
        return change_id
    
    def get_recent_alerts(self, limit: int = 20) -> List[Dict]:
        """Get recent security alerts"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM security_alerts 
            WHERE resolved = 0
            ORDER BY alert_time DESC 
            LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_file_history(self, file_path: str) -> List[Dict]:
        """Get change history for a file"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM change_events 
            WHERE file_path = ? 
            ORDER BY event_time DESC 
            LIMIT 20
        ''', (file_path,))
        
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]


class FileMonitor:
    """Monitors file system for changes"""
    
    def __init__(self, database: ForensicDatabase):
        self.db = database
        self.file_cache = {}  # path -> hash
        self.running = False
    
    def _should_exclude(self, file_path: str) -> bool:
        """Check if file should be excluded"""
        import fnmatch
        for pattern in SystemConfig.EXCLUDE_PATTERNS:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        return False
    
    def scan_file(self, file_path: str, audit_data: Dict = None) -> Optional[FileSnapshot]:
        """Scan a single file"""
        if self._should_exclude(file_path):
            return None
        
        try:
            # Get previous hash for chaining
            previous_hash = self.file_cache.get(file_path)
            
            snapshot = FileSnapshot(file_path, previous_hash)
            
            if snapshot.hash_sha256:
                old_hash = self.file_cache.get(file_path)
                
                if old_hash != snapshot.hash_sha256:
                    change_type = ChangeType.CREATED if old_hash is None else ChangeType.MODIFIED
                    
                    change_event = {
                        'change_type': change_type.value,
                        'file_path': file_path,
                        'new_hash': snapshot.hash_sha256,
                        'old_hash': old_hash,
                        'risk_score': snapshot.risk_score,
                        'risk_level': self._get_risk_level(snapshot.risk_score),
                        'process_name': audit_data.get('process_name') if audit_data else None,
                        'user_name': audit_data.get('user') if audit_data else None,
                        'audit_user': audit_data.get('user') if audit_data else None,
                        'audit_session_id': audit_data.get('session_id') if audit_data else None,
                        'audit_event_id': audit_data.get('event_id') if audit_data else None
                    }
                    
                    self.db.log_change(change_event)
                    self.db.save_snapshot(snapshot, audit_data)
                    
                    # Update cache
                    self.file_cache[file_path] = snapshot.hash_sha256
                    
                    logger.info(f"Change detected: {change_type.value} - {file_path}")
                
                return snapshot
                
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
        
        return None
    
    def _get_risk_level(self, score: float) -> str:
        """Convert risk score to level"""
        if score >= SystemConfig.RISK_HIGH:
            return "HIGH"
        elif score >= SystemConfig.RISK_MEDIUM:
            return "MEDIUM"
        else:
            return "LOW"
    
    def scan_path(self, path: str, recursive: bool = True, audit_data: Dict = None):
        """Scan a directory path"""
        if not os.path.exists(path):
            logger.warning(f"Path does not exist: {path}")
            return
        
        if os.path.isfile(path):
            self.scan_file(path, audit_data)
            return
        
        for root, dirs, files in os.walk(path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not self._should_exclude(os.path.join(root, d))]
            
            for file in files:
                file_path = os.path.join(root, file)
                self.scan_file(file_path, audit_data)
            
            if not recursive:
                break
    
    def verify_hash_chains(self) -> Dict[str, int]:
        """Verify integrity of hash chains"""
        results = {'verified': 0, 'tampered': 0, 'errors': 0}
        
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT file_path, chain_hash, previous_snapshot_hash
                FROM file_snapshots 
                ORDER BY file_path, snapshot_time
            ''')
            
            rows = cursor.fetchall()
            current_file = None
            previous_hash = None
            
            for row in rows:
                file_path = row['file_path']
                current_hash = row['chain_hash']
                prev_hash = row['previous_snapshot_hash']
                
                if prev_hash:
                    if prev_hash == previous_hash:
                        results['verified'] += 1
                    else:
                        results['tampered'] += 1
                        logger.warning(f"Hash chain tampered for: {file_path}")
                
                if current_file != file_path:
                    current_file = file_path
                    previous_hash = current_hash
                else:
                    previous_hash = current_hash
                    
        except Exception as e:
            logger.error(f"Hash chain verification failed: {e}")
            results['errors'] += 1
        finally:
            conn.close()
        
        return results


# Real-time monitoring (if watchdog available)
if WATCHDOG_AVAILABLE:
    class RealTimeHandler(FileSystemEventHandler):
        """Handles real-time file system events"""
        
        def __init__(self, monitor: FileMonitor, audit_collector):
            self.monitor = monitor
            self.audit_collector = audit_collector
            self.event_queue = queue.Queue()
            self.processing = True
            self.thread = threading.Thread(target=self._process_events, daemon=True)
            self.thread.start()
        
        def on_created(self, event):
            if not event.is_directory:
                self.event_queue.put(('CREATED', event.src_path))
        
        def on_modified(self, event):
            if not event.is_directory:
                self.event_queue.put(('MODIFIED', event.src_path))
        
        def on_deleted(self, event):
            if not event.is_directory:
                self.event_queue.put(('DELETED', event.src_path))
        
        def _process_events(self):
            while self.processing:
                try:
                    event_type, file_path = self.event_queue.get(timeout=1.0)
                    
                    # Debounce
                    time.sleep(SystemConfig.REALTIME_EVENT_DELAY)
                    
                    # Collect audit data
                    audit_data = None
                    if self.audit_collector:
                        audit_data = self.audit_collector.collect_audit_data(file_path, event_type)
                    
                    # Scan the file
                    self.monitor.scan_file(file_path, audit_data)
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"Error processing event: {e}")
        
        def stop(self):
            self.processing = False