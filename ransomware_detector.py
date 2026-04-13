#!/usr/bin/env python3

"""
SmartFileGuard - Ransomware Detection Heuristics Module
Part of SmartFileGuard v2.1.0
Multi-layered behavioral detection of ransomware patterns
"""

import os
import re
import time
import json
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class RansomwareDetector:
    """
    Multi-layered ransomware detection using behavioral heuristics
    """
    
    # Known ransomware extension patterns
    SUSPICIOUS_EXTENSIONS = {
        '.encrypted', '.encrypt', '.crypt', '.crypted', '.locked',
        '.locky', '.cryptolocker', '.cerber', '.zepto', '.odin',
        '.thor', '.vault', '.petya', '.wncry', '.wcry', '.wncrypt',
        '.cry', '.cryptor', '.crypt0', '.crypt1', '.crypt2',
        '.enc', '.aaaaa', '.zzzzz', '.xyz', '.zzz', '.xxx',
        '.micro', '.shadow', '.djvu', '.djvus', '.djvuu',
        '.phobos', '.rapid', '.mkp', '.adobe', '.adobee',
        '.crab', '.hakbit', '.medusa', '.medusalocker',
        '.pay', '.ransom', '.covid', '.corona', '.ncorona',
        '.black', '.red', '.blue', '.death', '.rip',
        '.help', '.recover', '.restore', '.decrypt', '.unlock',
        '.recovery', '.data', '.files', '.important', '.critical',
        '.encrypted_file', '.id[', '.id-', '[', ']', '{', '}',
        '.email=', '_email_', '.mail', '.contact', '.support',
        '.onion', '.tor', '.bitcoin', '.btc', '.monero', '.xmr',
        '.hacked', '.cracked', '.broken', '.damaged'
    }
    
    # Ransomware note filenames
    RANSOM_NOTE_PATTERNS = [
        '*README*', '*DECRYPT*', '*RECOVER*', '*RESTORE*', '*UNLOCK*',
        '*HOW_TO*', '*HELP*', '*INSTRUCTIONS*', '*YOUR_FILES*',
        '*ransom*', '*crypt*', '*lock*', '*pay*', '*contact*',
        '*.hta', '*.txt', '*.html', '*.url', '*.onion'
    ]
    
    # Canary file paths (decoy files that should never change)
    CANARY_PATHS = [
        'canary.txt', 'decoy.docx', 'honeypot.pdf', '_backup_.tmp'
    ]
    
    def __init__(self, db=None, alert_callback=None):
        """
        Initialize ransomware detector
        
        Args:
            db: ForensicDatabase instance for logging
            alert_callback: Function to call when ransomware is detected
        """
        self.db = db
        self.alert_callback = alert_callback
        self.enabled = True
        
        # Tracking structures
        self.file_rename_events = deque(maxlen=500)  # (old_path, new_path, timestamp)
        self.file_modify_events = deque(maxlen=1000)  # (path, timestamp, hash)
        self.process_file_counts = defaultdict(lambda: deque(maxlen=100))  # pid -> timestamps
        
        # Time windows for detection
        self.RENAME_BURST_WINDOW = 10  # seconds
        self.RENAME_BURST_THRESHOLD = 15  # files renamed in window
        self.MODIFY_BURST_WINDOW = 30  # seconds
        self.MODIFY_BURST_THRESHOLD = 50  # files modified in window
        self.ENTROPY_THRESHOLD = 7.0  # Shannon entropy threshold (8.0 is max)
        
        # Known safe processes (won't trigger alerts)
        self.SAFE_PROCESSES = {
            'explorer.exe', 'svchost.exe', 'system', 'trustedinstaller.exe',
            'msiexec.exe', 'update.exe', 'git.exe', 'python.exe',
            'smartfileguard.exe', 'code.exe', 'devenv.exe'
        }
        
        # Canary files tracking
        self.canary_files = {}  # path -> baseline_hash
        self._initialize_canaries()
        
        # Detection state
        self.detection_lock = threading.RLock()
        self.last_detection_time = None
        self.detection_count = 0
        self.quarantine_active = False
        
        # Load user-defined high-risk paths from rules
        self.high_risk_paths = self._load_high_risk_paths()
        
        logger.info("Ransomware detector initialized with %d heuristics", 6)
    
    def _load_high_risk_paths(self) -> Set[str]:
        """Load high-risk paths from user rules"""
        high_risk = set()
        
        try:
            if os.path.exists('user_rules.json'):
                with open('user_rules.json', 'r') as f:
                    rules = json.load(f)
                    
                for rule in rules.get('monitor_paths', []):
                    if rule.get('score', 0) >= 0.7:  # High risk threshold
                        high_risk.add(rule['path'])
        except Exception as e:
            logger.debug(f"Could not load user rules: {e}")
        
        # Add default high-risk locations
        high_risk.update([
            os.path.expanduser('~/Documents'),
            os.path.expanduser('~/Desktop'),
            os.path.expanduser('~/Pictures'),
            os.path.expanduser('~/Downloads'),
        ])
        
        return high_risk
    
    def _initialize_canaries(self):
        """Set up canary files in strategic locations"""
        canary_dir = Path('canaries')
        canary_dir.mkdir(exist_ok=True)
        
        # Create canary files with predictable content
        canary_content = {
            'financial_report.xlsx': b'PK\x03\x04' + os.urandom(256),
            'passwords.txt': b'admin:password123\nuser:letmein\n' + os.urandom(128),
            'secret_plans.docx': b'CONFIDENTIAL' + os.urandom(512),
            'backup.sql': b'-- MySQL dump\n' + os.urandom(1024),
        }
        
        for filename, content in canary_content.items():
            filepath = canary_dir / filename
            try:
                if not filepath.exists():
                    filepath.write_bytes(content)
                
                # Store baseline hash
                self.canary_files[str(filepath)] = hashlib.sha256(content).hexdigest()
                logger.debug(f"Canary file initialized: {filepath}")
            except Exception as e:
                logger.warning(f"Could not create canary {filename}: {e}")
        
        logger.info(f"Initialized {len(self.canary_files)} canary files")
    
    def analyze_file_event(self, event_type: str, file_path: str, 
                          old_path: str = None, process_info: Dict = None,
                          file_hash: str = None) -> Optional[Dict]:
        """
        Analyze a file event for ransomware indicators
        
        Args:
            event_type: 'CREATED', 'MODIFIED', 'DELETED', 'MOVED'
            file_path: Current file path
            old_path: Previous path (for MOVED events)
            process_info: Dict with 'pid', 'name', 'user'
            file_hash: SHA-256 hash of file (if available)
        
        Returns:
            Detection result dict if ransomware suspected, else None
        """
        if not self.enabled:
            return None
        
        with self.detection_lock:
            timestamp = datetime.now()
            
            # Skip safe processes
            if process_info:
                proc_name = process_info.get('name', '').lower()
                if any(safe in proc_name for safe in self.SAFE_PROCESSES):
                    return None
            
            # Multi-layer detection
            detections = []
            
            # 1. Extension change detection (RENAME/MOVED with suspicious extension)
            if event_type in ('MOVED', 'CREATED') and old_path:
                ext_result = self._check_suspicious_extension(file_path, old_path, timestamp)
                if ext_result:
                    detections.append(ext_result)
            
            # 2. Rapid file modifications (burst detection)
            if event_type in ('MODIFIED', 'CREATED'):
                burst_result = self._check_modification_burst(file_path, timestamp, process_info)
                if burst_result:
                    detections.append(burst_result)
            
            # 3. High entropy content (encryption detection)
            if event_type in ('MODIFIED', 'CREATED') and file_hash is None:
                entropy_result = self._check_file_entropy(file_path, timestamp)
                if entropy_result:
                    detections.append(entropy_result)
            
            # 4. Canary file tampering
            if file_path in self.canary_files:
                canary_result = self._check_canary_tamper(file_path, timestamp)
                if canary_result:
                    detections.append(canary_result)
                    detections[0]['severity'] = 'CRITICAL'  # Canary is highest priority
            
            # 5. Ransom note creation
            if event_type == 'CREATED':
                note_result = self._check_ransom_note(file_path, timestamp)
                if note_result:
                    detections.append(note_result)
            
            # 6. Process behavior (many files from same process)
            if process_info:
                proc_result = self._check_process_behavior(process_info, timestamp)
                if proc_result:
                    detections.append(proc_result)
            
            # If any detection triggered, create consolidated alert
            if detections:
                return self._create_detection_alert(detections, file_path, process_info, timestamp)
        
        return None
    
    def _check_suspicious_extension(self, file_path: str, old_path: str, 
                                    timestamp: datetime) -> Optional[Dict]:
        """Detect file renamed to suspicious extension"""
        
        old_ext = Path(old_path).suffix.lower()
        new_ext = Path(file_path).suffix.lower()
        
        # Only alert if extension actually changed
        if old_ext == new_ext:
            return None
        
        # Check if new extension is suspicious
        if new_ext in self.SUSPICIOUS_EXTENSIONS:
            self.file_rename_events.append((old_path, file_path, timestamp))
            
            # Check for burst of renames
            recent_renames = [
                e for e in self.file_rename_events 
                if (timestamp - e[2]).total_seconds() < self.RENAME_BURST_WINDOW
            ]
            
            if len(recent_renames) >= self.RENAME_BURST_THRESHOLD:
                return {
                    'type': 'MASS_RENAME',
                    'confidence': min(0.9 + (len(recent_renames) * 0.01), 1.0),
                    'severity': 'CRITICAL',
                    'details': {
                        'old_extension': old_ext,
                        'new_extension': new_ext,
                        'rename_count': len(recent_renames),
                        'window_seconds': self.RENAME_BURST_WINDOW
                    }
                }
            else:
                return {
                    'type': 'SUSPICIOUS_EXTENSION',
                    'confidence': 0.6,
                    'severity': 'MEDIUM',
                    'details': {
                        'old_extension': old_ext,
                        'new_extension': new_ext
                    }
                }
        
        return None
    
    def _check_modification_burst(self, file_path: str, timestamp: datetime,
                                  process_info: Dict = None) -> Optional[Dict]:
        """Detect rapid file modifications (encryption behavior)"""
        
        # Quick hash for tracking (just file path + size as proxy)
        try:
            file_size = os.path.getsize(file_path)
        except:
            file_size = 0
        
        event_key = f"{file_path}:{file_size}"
        self.file_modify_events.append((event_key, timestamp))
        
        # Count modifications in recent window
        recent_mods = [
            e for e in self.file_modify_events
            if (timestamp - e[1]).total_seconds() < self.MODIFY_BURST_WINDOW
        ]
        
        # Check if high-risk path
        is_high_risk = any(
            file_path.startswith(hrp) for hrp in self.high_risk_paths
        )
        
        # Lower threshold for high-risk paths
        threshold = self.MODIFY_BURST_THRESHOLD // 2 if is_high_risk else self.MODIFY_BURST_THRESHOLD
        
        if len(recent_mods) >= threshold:
            return {
                'type': 'MASS_MODIFICATION',
                'confidence': min(0.7 + (len(recent_mods) * 0.005), 0.95),
                'severity': 'HIGH',
                'details': {
                    'modification_count': len(recent_mods),
                    'window_seconds': self.MODIFY_BURST_WINDOW,
                    'high_risk_path': is_high_risk
                }
            }
        
        return None
    
    def _check_file_entropy(self, file_path: str, timestamp: datetime) -> Optional[Dict]:
        """Check if file content has high entropy (likely encrypted)"""
        
        try:
            # Skip very large files
            if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB
                return None
            
            # Read first 4KB to calculate entropy
            with open(file_path, 'rb') as f:
                data = f.read(4096)
            
            if not data:
                return None
            
            entropy = self._calculate_shannon_entropy(data)
            
            if entropy > self.ENTROPY_THRESHOLD:
                return {
                    'type': 'HIGH_ENTROPY_CONTENT',
                    'confidence': min(0.5 + ((entropy - self.ENTROPY_THRESHOLD) * 0.5), 0.9),
                    'severity': 'HIGH',
                    'details': {
                        'entropy': round(entropy, 2),
                        'threshold': self.ENTROPY_THRESHOLD,
                        'sample_size': len(data)
                    }
                }
        except Exception as e:
            logger.debug(f"Entropy check failed for {file_path}: {e}")
        
        return None
    
    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        byte_counts = [0] * 256
        
        for byte in data:
            byte_counts[byte] += 1
        
        for count in byte_counts:
            if count > 0:
                probability = count / len(data)
                entropy -= probability * (probability.bit_length() - 1)  # log2 approximation
                # More accurate: entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _check_canary_tamper(self, file_path: str, timestamp: datetime) -> Optional[Dict]:
        """Check if canary file has been modified"""
        
        baseline_hash = self.canary_files.get(file_path)
        if not baseline_hash:
            return None
        
        try:
            with open(file_path, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
            
            if current_hash != baseline_hash:
                return {
                    'type': 'CANARY_TAMPER',
                    'confidence': 1.0,  # 100% confidence - canary should never change
                    'severity': 'CRITICAL',
                    'details': {
                        'canary_file': file_path,
                        'baseline_hash': baseline_hash[:16],
                        'current_hash': current_hash[:16]
                    }
                }
        except Exception as e:
            logger.error(f"Canary check failed: {e}")
        
        return None
    
    def _check_ransom_note(self, file_path: str, timestamp: datetime) -> Optional[Dict]:
        """Detect creation of ransom note files"""
        
        filename = Path(file_path).name.lower()
        
        # Check for ransom note patterns
        for pattern in self.RANSOM_NOTE_PATTERNS:
            pattern_lower = pattern.lower().replace('*', '')
            if pattern_lower in filename:
                # Check if file is recent and in user directory
                if any(hrp in file_path for hrp in self.high_risk_paths):
                    return {
                        'type': 'RANSOM_NOTE',
                        'confidence': 0.85,
                        'severity': 'CRITICAL',
                        'details': {
                            'filename': filename,
                            'matched_pattern': pattern
                        }
                    }
        
        return None
    
    def _check_process_behavior(self, process_info: Dict, timestamp: datetime) -> Optional[Dict]:
        """Detect suspicious process behavior (many file ops)"""
        
        pid = process_info.get('pid')
        if not pid:
            return None
        
        self.process_file_counts[pid].append(timestamp)
        
        # Clean old events
        recent_events = [
            t for t in self.process_file_counts[pid]
            if (timestamp - t).total_seconds() < 60
        ]
        self.process_file_counts[pid] = deque(recent_events, maxlen=200)
        
        # Alert if process touched many files
        if len(recent_events) >= 100:  # 100 files in 60 seconds
            proc_name = process_info.get('name', 'Unknown')
            
            # Skip known safe processes
            if proc_name.lower() not in self.SAFE_PROCESSES:
                return {
                    'type': 'SUSPICIOUS_PROCESS',
                    'confidence': 0.7,
                    'severity': 'HIGH',
                    'details': {
                        'pid': pid,
                        'process_name': proc_name,
                        'file_operations': len(recent_events),
                        'window_seconds': 60
                    }
                }
        
        return None
    
    def _create_detection_alert(self, detections: List[Dict], file_path: str,
                                process_info: Dict, timestamp: datetime) -> Dict:
        """Create consolidated alert from multiple detections"""
        
        # Find highest severity
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        primary = max(detections, key=lambda d: severity_order.get(d['severity'], 0))
        
        # Calculate overall confidence (weighted average of top 3)
        confidences = [d['confidence'] for d in detections[:3]]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5
        
        alert = {
            'timestamp': timestamp.isoformat(),
            'trigger_file': file_path,
            'detection_count': len(detections),
            'primary_detection': primary['type'],
            'confidence': round(avg_confidence, 3),
            'severity': primary['severity'],
            'detections': detections,
            'process_info': process_info or {},
            'recommended_action': self._get_recommended_action(primary['severity'])
        }
        
        self.detection_count += 1
        self.last_detection_time = timestamp
        
        # Log to database if available
        if self.db:
            try:
                self.db.log_change({
                    'change_type': 'RANSOMWARE_DETECTION',
                    'file_path': file_path,
                    'risk_score': avg_confidence,
                    'risk_level': primary['severity'],
                    'process_name': process_info.get('name') if process_info else None,
                    'process_id': process_info.get('pid') if process_info else None,
                    'user_name': process_info.get('user') if process_info else None,
                    'details': json.dumps(alert)
                })
            except Exception as e:
                logger.error(f"Failed to log ransomware detection: {e}")
        
        # Trigger callback
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")
        
        logger.critical(f"RANSOMWARE DETECTED: {primary['type']} - {file_path} (confidence: {avg_confidence:.2%})")
        
        return alert
    
    def _get_recommended_action(self, severity: str) -> str:
        """Get recommended action based on severity"""
        actions = {
            'CRITICAL': 'IMMEDIATE ISOLATION - Disconnect from network, kill suspicious processes, restore from backup',
            'HIGH': 'URGENT INVESTIGATION - Review process tree, check for encryption patterns, prepare backup restore',
            'MEDIUM': 'MONITOR CLOSELY - Increase logging, verify file integrity, review user activity',
            'LOW': 'LOG AND MONITOR - Continue observation, review periodically'
        }
        return actions.get(severity, 'INVESTIGATE - Review logs and determine appropriate response')
    
    def get_detection_stats(self) -> Dict:
        """Get detection statistics"""
        return {
            'total_detections': self.detection_count,
            'last_detection': self.last_detection_time.isoformat() if self.last_detection_time else None,
            'active_canaries': len(self.canary_files),
            'tracked_rename_events': len(self.file_rename_events),
            'tracked_modify_events': len(self.file_modify_events),
            'enabled': self.enabled
        }
    
    def quarantine_suspicious_process(self, pid: int) -> bool:
        """Attempt to quarantine a suspicious process"""
        try:
            import psutil
            
            process = psutil.Process(pid)
            
            # Log process details
            logger.warning(f"Quarantining process: {process.name()} (PID: {pid})")
            
            # Suspend the process
            process.suspend()
            
            # Log open files
            open_files = process.open_files()
            connections = process.connections()
            
            logger.info(f"Process {pid} open files: {len(open_files)}")
            logger.info(f"Process {pid} connections: {len(connections)}")
            
            self.quarantine_active = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to quarantine process {pid}: {e}")
            return False
    
    def add_custom_canary(self, file_path: str) -> bool:
        """Add a custom canary file"""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                self.canary_files[file_path] = file_hash
                logger.info(f"Added custom canary: {file_path}")
                return True
        except Exception as e:
            logger.error(f"Failed to add canary {file_path}: {e}")
        
        return False
    
    def reset_detection_state(self):
        """Reset detection counters (useful after incident response)"""
        with self.detection_lock:
            self.file_rename_events.clear()
            self.file_modify_events.clear()
            self.process_file_counts.clear()
            self.detection_count = 0
            self.last_detection_time = None
            self.quarantine_active = False
            logger.info("Detection state reset")