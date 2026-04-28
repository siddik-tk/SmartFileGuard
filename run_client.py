#!/usr/bin/env python3
"""
SmartFileGuard Client v2.1.0
"""
import os, sys, json, time, uuid, socket, hashlib, sqlite3, logging, platform, argparse, threading, secrets
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, redirect, render_template
from flask_cors import CORS
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def load_config():
    for fn in ['.env', 'network_config.json']:
        pf = Path(fn)
        if not pf.exists(): continue
        try:
            if fn.endswith('.json'):
                with open(pf) as f:
                    c = json.load(f)
                    for k, v in c.items():
                        ek = f'SFG_{k.upper()}'
                        if not os.environ.get(ek) and v:
                            os.environ[ek] = str(v)
            else:
                with open(pf) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            k, v = line.split('=', 1)
                            os.environ[k.strip()] = v.strip()
        except: pass
load_config()

missing = []
try: import requests
except ImportError: missing.append('requests')
if missing:
    import subprocess
    for p in missing: subprocess.run([sys.executable, '-m', 'pip', 'install', p], capture_output=True)
    import requests

from config import SystemConfig
from core import ForensicDatabase, FileMonitor
from collectors import AuditDataCollector
from ransomware_detector import RansomwareDetector
from reporting import ReportGenerator

# Configure logging - only to file, not to console
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - [CLIENT] - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler('smartfileguard_client.log')])
logger = logging.getLogger(__name__)

# Suppress Flask logs
cli = sys.modules.get('flask.cli')
if cli:
    cli.show_server_banner = lambda *x: None
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

class ClientAuth:
    def __init__(self, af='client_auth.json'):
        self.af = Path(af)
        self.sessions = {}
        self.session_timeout = 3600
        self._init()
    
    def _init(self):
        if not self.af.exists():
            salt = secrets.token_hex(16)
            pwd_hash = hashlib.sha256(f"client123{salt}".encode()).hexdigest()
            with open(self.af, 'w') as f:
                json.dump({'client': {'ph': pwd_hash, 'salt': salt, 'role': 'client'}}, f, indent=4)
            self.auth_data = {'client': {'ph': pwd_hash, 'salt': salt, 'role': 'client'}}
        else:
            with open(self.af) as f:
                self.auth_data = json.load(f)
    
    def verify_password(self, username, password):
        if username not in self.auth_data:
            return False
        return hashlib.sha256(f"{password}{self.auth_data[username]['salt']}".encode()).hexdigest() == self.auth_data[username]['ph']
    
    def create_session(self, username):
        now = datetime.now()
        token = secrets.token_hex(32)
        self.sessions[token] = {'u': username, 'c': now}
        return token
    
    def validate_session(self, token):
        if token in self.sessions:
            if (datetime.now() - self.sessions[token]['c']).total_seconds() < self.session_timeout:
                self.sessions[token]['c'] = datetime.now()
                return True
            del self.sessions[token]
        return False
    
    def logout(self, token):
        if token in self.sessions:
            del self.sessions[token]

client_auth = ClientAuth()

class SmartFileGuardClient:
    def __init__(self, silent=False):
        self.silent = silent
        self.node_name = os.environ.get('SFG_NODE_NAME', socket.gethostname())
        self.server_ip = os.environ.get('SFG_CENTRAL_SERVER', '10.41.55.22')
        self.api_key = os.environ.get('SFG_API_KEY', 'default-key')
        self.server_url = f"http://{self.server_ip}:5000"
        
        self.db = ForensicDatabase()
        self.audit_collector = AuditDataCollector()
        self.file_monitor = FileMonitor(self.db)
        self.report_gen = ReportGenerator(self.db)
        
        try:
            self.ransomware_detector = RansomwareDetector(
                db=self.db,
                alert_callback=self._on_ransomware_alert
            )
        except:
            self.ransomware_detector = None
        
        self.is_registered = False
        self.is_monitoring = False
        self.scan_count = 0
        self.start_time = time.time()
        self.file_cache = {}
        self.scan_thread = None
        
        self._register()
        self._start_heartbeat()
    
    def _on_ransomware_alert(self, alert):
        self._send_alert('RANSOMWARE_DETECTED', alert['primary_detection'], 
                        alert['severity'], alert['trigger_file'], risk=alert['confidence'])
    
    def _calculate_file_hash(self, file_path):
        try:
            if not os.path.exists(file_path):
                return ""
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:
                return f"LARGE_FILE_{file_size}"
            if file_size == 0:
                return hashlib.sha256(b"").hexdigest()
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return "ERROR"
    
    def _send_alert(self, alert_type, description, severity, file_path, user=None, process=None, risk=0.5, old_hash=None, new_hash=None):
        alert_data = {
            'alert_id': str(uuid.uuid4()),
            'node_name': self.node_name,
            'alert_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'alert_type': alert_type,
            'description': description,
            'severity': severity,
            'file_path': file_path,
            'process_name': process or 'SmartFileGuard',
            'user_name': user or os.environ.get('USER', os.environ.get('USERNAME', 'unknown')),
            'risk_score': risk,
            'hash_before': old_hash or '',
            'hash_after': new_hash or '',
            'details': json.dumps({})
        }
        
        try:
            conn = sqlite3.connect(self.db.db_path)
            c = conn.cursor()
            c.execute('''INSERT INTO security_alerts 
                (alert_type, description, severity, file_path, process_name, user_name, risk_score, alert_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (alert_type, description, severity, file_path, process_name, 
                 alert_data['user_name'], risk, alert_data['alert_time']))
            conn.commit()
            conn.close()
            logger.info(f"Alert saved: {alert_type}")
        except:
            pass
        
        if self.is_registered:
            try:
                requests.post(f"{self.server_url}/api/alert", json=alert_data,
                            headers={'X-API-Key': self.api_key}, timeout=10)
            except:
                pass
    
    def _send_file_event(self, file_path, change_type, user=None, process=None, risk=0.0, old_hash=None, new_hash=None):
        event_data = {
            'node_name': self.node_name,
            'event_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'file_path': file_path,
            'change_type': change_type,
            'user_name': user or 'system',
            'process_name': process or 'SmartFileGuard',
            'risk_score': risk,
            'hash_before': old_hash or '',
            'hash_after': new_hash or ''
        }
        
        try:
            conn = sqlite3.connect(self.db.db_path)
            c = conn.cursor()
            c.execute('''INSERT INTO change_events 
                (change_type, file_path, old_hash, new_hash, process_name, user_name, risk_score, event_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (change_type, file_path, old_hash or '', new_hash or '', 
                 process or 'SmartFileGuard', user or 'system', risk, event_data['event_time']))
            conn.commit()
            conn.close()
            logger.debug(f"File event saved: {change_type}")
        except:
            pass
        
        if self.is_registered:
            try:
                requests.post(f"{self.server_url}/api/file-event", json=event_data,
                            headers={'X-API-Key': self.api_key}, timeout=10)
            except:
                pass
    
    def _register(self):
        try:
            response = requests.get(f"{self.server_url}/api/health", timeout=5)
            if response.status_code == 200:
                reg_data = {
                    'node_name': self.node_name,
                    'node_group': 'clients',
                    'version': '2.1.0',
                    'os_info': f"{platform.system()} {platform.release()}"
                }
                response = requests.post(f"{self.server_url}/api/register", json=reg_data,
                                        headers={'X-API-Key': self.api_key}, timeout=10)
                if response.status_code == 200:
                    self.is_registered = True
                    if not self.silent:
                        print(f"✓ Registered with server: {self.server_url}")
                    return True
        except:
            pass
        return False
    
    def _start_heartbeat(self):
        def heartbeat_loop():
            while True:
                time.sleep(60)
                if self.is_registered:
                    self._send_heartbeat()
        threading.Thread(target=heartbeat_loop, daemon=True).start()
    
    def _send_heartbeat(self):
        try:
            conn = sqlite3.connect(self.db.db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM security_alerts")
            alert_count = c.fetchone()[0] or 0
            c.execute("SELECT COUNT(*) FROM change_events")
            event_count = c.fetchone()[0] or 0
            conn.close()
            
            requests.post(f"{self.server_url}/api/heartbeat", json={
                'node_name': self.node_name,
                'stats': {
                    'uptime': int(time.time() - self.start_time),
                    'scans': self.scan_count,
                    'tracked_files': len(self.file_cache),
                    'local_alerts': alert_count,
                    'local_events': event_count
                }
            }, headers={'X-API-Key': self.api_key}, timeout=5)
        except:
            pass
    
    def _get_risk_for_file(self, file_path):
        risk = 0.3
        critical_patterns = [
            '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/sudoers',
            '\\System32\\drivers\\etc\\hosts'
        ]
        for cp in critical_patterns:
            if cp.lower() in file_path.lower():
                risk = 0.9
                break
        return risk
    
    def _check_file(self, file_path, audit_data):
        try:
            current_hash = self._calculate_file_hash(file_path)
            if not current_hash or current_hash == 'ERROR':
                return
            
            old_hash = self.file_cache.get(file_path)
            risk = self._get_risk_for_file(file_path)
            
            if old_hash and old_hash != current_hash:
                self._send_file_event(file_path, 'MODIFIED', 
                                     user=audit_data.get('user'),
                                     process=audit_data.get('process_name'),
                                     risk=risk, old_hash=old_hash, new_hash=current_hash)
                
                if risk >= 0.7:
                    self._send_alert('FILE_MODIFIED', f'Modified: {os.path.basename(file_path)}',
                                    'HIGH' if risk >= 0.8 else 'MEDIUM', file_path,
                                    user=audit_data.get('user'), process=audit_data.get('process_name'),
                                    risk=risk, old_hash=old_hash, new_hash=current_hash)
            elif not old_hash:
                self._send_file_event(file_path, 'CREATED', risk=risk, new_hash=current_hash)
            
            self.file_cache[file_path] = current_hash
        except:
            pass
    
    def _scan(self):
        """Scan in background - no console output"""
        self.scan_count += 1
        
        audit_data = self.audit_collector.collect_audit_data('SCAN', 'BACKGROUND')
        
        paths_to_scan = []
        
        if platform.system() == "Linux":
            paths_to_scan = [
                '/etc/hosts', '/etc/passwd', '/etc/shadow',
                os.path.expanduser('~/Documents'),
                os.path.expanduser('~/Desktop')
            ]
        elif platform.system() == "Windows":
            paths_to_scan = [
                os.environ.get('WINDIR', 'C:\\Windows') + '\\System32\\drivers\\etc\\hosts',
                os.path.expanduser('~\\Documents'),
                os.path.expanduser('~\\Desktop')
            ]
        else:
            paths_to_scan = [
                '/etc/hosts', '/etc/passwd',
                os.path.expanduser('~/Documents')
            ]
        
        for path in paths_to_scan:
            if not os.path.exists(path):
                continue
            
            try:
                if os.path.isfile(path):
                    self._check_file(path, audit_data)
                else:
                    for root, dirs, files in os.walk(path):
                        dirs[:] = [d for d in dirs if not d.startswith('.')]
                        for file_name in files:
                            file_path = os.path.join(root, file_name)
                            self._check_file(file_path, audit_data)
            except:
                pass
        
        self._send_heartbeat()
    
    def run_single_scan(self):
        """Run a single scan in background"""
        if self.scan_thread and self.scan_thread.is_alive():
            # Scan already running, just return
            return "Scan in progress"
        
        # Run scan in background thread
        self.scan_thread = threading.Thread(target=self._scan, daemon=True)
        self.scan_thread.start()
        return "Scan started"
    
    def start_continuous_monitoring(self):
        """Start continuous monitoring - scans run in background"""
        if self.is_monitoring:
            if not self.silent:
                print("   Monitoring already running")
            return
        
        self.is_monitoring = True
        self._send_alert('MONITORING_STARTED', 'Continuous monitoring active', 'LOW', 'system')
        
        def continuous_loop():
            while self.is_monitoring:
                self._scan()
                time.sleep(SystemConfig.FILE_SCAN_INTERVAL)
        
        self.scan_thread = threading.Thread(target=continuous_loop, daemon=True)
        self.scan_thread.start()
        if not self.silent:
            print("   Continuous monitoring started (running in background)")
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.is_monitoring = False
        self._send_alert('MONITORING_STOPPED', 'Monitoring stopped', 'LOW', 'system')
        if not self.silent:
            print("   Monitoring stopped")
    
    def view_alerts(self):
        try:
            conn = sqlite3.connect(self.db.db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM security_alerts ORDER BY alert_time DESC LIMIT 20")
            rows = cur.fetchall()
            conn.close()
            if rows:
                print(f"\n{' Recent Alerts ':-^60}")
                for alert in rows:
                    print(f"\nTime: {alert['alert_time']}")
                    print(f"Type: {alert['alert_type']}")
                    print(f"Severity: {alert['severity']}")
                    print(f"File: {os.path.basename(alert['file_path'] or 'Unknown')}")
            else:
                print("\nNo recent alerts")
        except:
            print("\nNo alerts found")
    
    def check_file_history(self):
        file_path = input("Enter file path: ").strip()
        if file_path and os.path.exists(file_path):
            try:
                conn = sqlite3.connect(self.db.db_path)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute("SELECT * FROM change_events WHERE file_path = ? ORDER BY event_time DESC LIMIT 20", (file_path,))
                rows = cur.fetchall()
                conn.close()
                if rows:
                    print(f"\n{' File History ':-^60}")
                    for event in rows:
                        print(f"\nTime: {event['event_time']}")
                        print(f"Change: {event['change_type']}")
                        print(f"Risk: {event.get('risk_score', 0):.1%}")
                else:
                    print("No history found")
            except:
                print("Error reading history")
        else:
            print("File not found")
    
    def verify_hashes(self):
        print("\nVerifying hash chains...")
        results = self.file_monitor.verify_hash_chains()
        print(f"\nVerified: {results['verified']}")
        print(f"Tampered: {results['tampered']}")
        print(f"Errors: {results['errors']}")
    
    def test_alert(self):
        test_hash = hashlib.sha256(b"test_content").hexdigest()
        self._send_alert('TEST_ALERT', 'Manual test alert', 'LOW', 'test.txt', risk=0.3, new_hash=test_hash)
        print("  Test alert sent")
    
    def check_connection(self):
        try:
            r = requests.get(f"{self.server_url}/api/health", timeout=5)
            if r.status_code == 200:
                print(f"  ✓ Server {self.server_url} is online")
            else:
                print(f"  ✗ Server returned {r.status_code}")
        except:
            print(f"  ✗ Cannot connect to server")
    
    def system_status(self):
        runtime = datetime.now() - datetime.fromtimestamp(self.start_time)
        hours, remainder = divmod(runtime.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        try:
            conn = sqlite3.connect(self.db.db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM security_alerts")
            alert_count = c.fetchone()[0] or 0
            c.execute("SELECT COUNT(*) FROM change_events")
            event_count = c.fetchone()[0] or 0
            conn.close()
        except:
            alert_count = 0
            event_count = 0
        
        print(f"\n{' STATUS ':-^60}")
        print(f"Node: {self.node_name}")
        print(f"Server: {self.server_url}")
        print(f"Runtime: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
        print(f"Scans: {self.scan_count}")
        print(f"Tracked Files: {len(self.file_cache)}")
        print(f"Local Alerts: {alert_count}")
        print(f"Local Events: {event_count}")
        print(f"Monitoring: {'RUNNING' if self.is_monitoring else 'STOPPED'}")
        print('-' * 60)
    
    def add_custom_rule(self):
        print(f"\n{' ADD CUSTOM RULE ':-^60}")
        path = input("Enter file/folder path to monitor: ").strip()
        if not path:
            print("❌ No path provided")
            return
        abs_path = os.path.abspath(path)
        if not os.path.exists(abs_path):
            print(f"❌ Path does not exist: {abs_path}")
            return
        try:
            score_input = input("Enter risk score (0.0 to 1.0, default 0.5): ").strip()
            if score_input:
                score = float(score_input)
                if score < 0 or score > 1:
                    print("❌ Score must be between 0.0 and 1.0")
                    return
            else:
                score = 0.5
        except ValueError:
            print("❌ Invalid score")
            return
        recursive = False
        if os.path.isdir(abs_path):
            rec = input("Monitor folder recursively? (y/N): ").strip().lower()
            recursive = (rec == 'y')
        rules_file = 'user_rules.json'
        rules = {'monitor_paths': [], 'risk_scores': {}}
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r') as f:
                    rules = json.load(f)
            except:
                pass
        new_rule = {
            'path': abs_path,
            'score': score,
            'recursive': recursive,
            'type': 'folder' if os.path.isdir(abs_path) else 'file'
        }
        rules['monitor_paths'] = [r for r in rules['monitor_paths'] if r['path'] != abs_path]
        rules['monitor_paths'].append(new_rule)
        if os.path.isfile(abs_path):
            rules['risk_scores'][abs_path] = score
        with open(rules_file, 'w') as f:
            json.dump(rules, f, indent=4)
        print(f"\n✅ Added: {abs_path} (risk: {score})")
    
    def list_custom_rules(self):
        print(f"\n{' CUSTOM MONITORING RULES ':-^60}")
        rules_file = 'user_rules.json'
        if not os.path.exists(rules_file):
            print("No custom rules defined.")
            return
        try:
            with open(rules_file, 'r') as f:
                rules = json.load(f)
        except:
            print("❌ Error reading rules")
            return
        if not rules.get('monitor_paths'):
            print("No custom rules defined.")
            return
        for i, rule in enumerate(rules['monitor_paths'], 1):
            print(f"\n{i}. [{rule.get('type', 'unknown').upper()}] {rule['path']}")
            print(f"   Risk: {rule['score']}")
            if rule.get('recursive'):
                print(f"   Recursive: Yes")
        print(f"\nTotal: {len(rules['monitor_paths'])} rules")
    
    def remove_custom_rule(self):
        self.list_custom_rules()
        rules_file = 'user_rules.json'
        if not os.path.exists(rules_file):
            return
        try:
            with open(rules_file, 'r') as f:
                rules = json.load(f)
        except:
            print("❌ Error reading rules")
            return
        if not rules.get('monitor_paths'):
            return
        path = input("\nEnter path to remove: ").strip()
        if not path:
            return
        abs_path = os.path.abspath(path)
        old_count = len(rules['monitor_paths'])
        rules['monitor_paths'] = [r for r in rules['monitor_paths'] if r['path'] != abs_path]
        if abs_path in rules.get('risk_scores', {}):
            del rules['risk_scores'][abs_path]
        if len(rules['monitor_paths']) < old_count:
            with open(rules_file, 'w') as f:
                json.dump(rules, f, indent=4)
            print(f"✅ Removed: {abs_path}")
        else:
            print(f"❌ No rule found: {abs_path}")
    
    def generate_report_menu(self):
        while True:
            print(f"\n{' REPORT GENERATION ':-^60}")
            print("1. Generate Alerts Report")
            print("2. Generate File History Report")
            print("3. Generate System Status Report")
            print("4. Generate Hash Verification Report")
            print("5. View Reports")
            print("6. Delete Report")
            print("7. Back")
            print("-" * 60)
            choice = input("\nSelect option (1-7): ").strip()
            if choice == '1':
                fmt = input("Format (csv/json/pdf) [csv]: ").strip() or 'csv'
                result = self.report_gen.generate_report('alerts', fmt)
                print(f"✅ Report: {result['filepath']}")
            elif choice == '2':
                fmt = input("Format (csv/json/pdf) [csv]: ").strip() or 'csv'
                result = self.report_gen.generate_report('file_history', fmt)
                print(f"✅ Report: {result['filepath']}")
            elif choice == '3':
                fmt = input("Format (csv/json/pdf) [csv]: ").strip() or 'csv'
                result = self.report_gen.generate_report('system_status', fmt)
                print(f"✅ Report: {result['filepath']}")
            elif choice == '4':
                fmt = input("Format (csv/json/pdf) [csv]: ").strip() or 'csv'
                result = self.report_gen.generate_report('hash_verification', fmt)
                print(f"✅ Report: {result['filepath']}")
            elif choice == '5':
                reports = self.report_gen.list_reports()
                if reports:
                    for r in reports:
                        print(f"  {r['filename']} ({r['format']}) - {r['created'][:16]}")
                else:
                    print("  No reports")
            elif choice == '6':
                reports = self.report_gen.list_reports()
                if reports:
                    for i, r in enumerate(reports, 1):
                        print(f"  {i}. {r['filename']}")
                    try:
                        idx = int(input("Delete # (0=cancel): "))
                        if 1 <= idx <= len(reports):
                            self.report_gen.delete_report(reports[idx-1]['filename'])
                            print("✅ Deleted")
                    except:
                        pass
            elif choice == '7':
                break
    
    def ransomware_menu(self):
        if not self.ransomware_detector:
            print("\n❌ Ransomware detection not available")
            return
        while True:
            print(f"\n{' RANSOMWARE DETECTION ':-^60}")
            print("1. View Detection Status")
            print("2. Run Safe Detection Test")
            print("3. Back to Main Menu")
            print("-" * 60)
            choice = input("\nSelect option (1-3): ").strip()
            if choice == '1':
                stats = self.ransomware_detector.get_detection_stats()
                print(f"\n📊 Status:")
                print(f"   Detections: {stats['total_detections']}")
                print(f"   Canaries: {stats['active_canaries']}")
                print(f"   Active: {'🟢' if stats['enabled'] else '🔴'}")
            elif choice == '2':
                test_dir = Path('test_smartfileguard')
                test_dir.mkdir(exist_ok=True)
                print("Creating test files...")
                for i in range(10):
                    test_file = test_dir / f"test_doc_{i}.txt"
                    test_file.write_text(f"Test Document {i}")
                    suspicious_file = test_dir / f"test_doc_{i}.encrypted"
                    test_file.rename(suspicious_file)
                    time.sleep(0.1)
                print(f"✅ Test complete! Files in: {test_dir}")
            elif choice == '3':
                break
    
    def _update_stats_display(self):
        """Update the stats in the menu display"""
        try:
            conn = sqlite3.connect(self.db.db_path)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM security_alerts")
            alert_count = c.fetchone()[0] or 0
            c.execute("SELECT COUNT(*) FROM change_events")
            event_count = c.fetchone()[0] or 0
            conn.close()
            return alert_count, event_count
        except:
            return 0, 0
    
    def interactive_menu(self):
        while True:
            # Get fresh stats for display
            alert_count, event_count = self._update_stats_display()
            
            connected = False
            try:
                r = requests.get(f"{self.server_url}/api/health", timeout=3)
                connected = r.status_code == 200
            except:
                pass
            
            print(f"""
{'='*60}
         SmartFileGuard Client v2.1.0
{'='*60}
  Node:     {self.node_name}
  Server:   {self.server_url}
  Status:   {'✓ CONNECTED' if connected else '✗ OFFLINE'}
  Monitor:  {'RUNNING' if self.is_monitoring else 'STOPPED'}
  Files:    {len(self.file_cache)}
  Scans:    {self.scan_count}
  Alerts:   {alert_count}
  Events:   {event_count}
{'='*60}
  1.  Run single scan
  2.  Start continuous monitoring
  3.  Stop monitoring
  4.  View recent alerts
  5.  Check file history
  6.  Verify hash chains
  7.  Send test alert
  8.  System status
  9.  Add custom monitoring rule
  10. List custom rules
  11. Remove custom rule
  12. Generate Reports
  13. Ransomware Detection
  14. Exit
{'='*60}""")
            
            choice = input("\nSelect option (1-14): ").strip()
            
            if choice == '1':
                print("\n▶ Running single scan...")
                result = self.run_single_scan()
                print(f"  {result}")
                # Brief pause to let scan start
                time.sleep(0.5)
            elif choice == '2':
                print("\n▶ Starting continuous monitoring...")
                self.start_continuous_monitoring()
            elif choice == '3':
                print("\n▶ Stopping monitoring...")
                self.stop_monitoring()
            elif choice == '4':
                self.view_alerts()
            elif choice == '5':
                self.check_file_history()
            elif choice == '6':
                self.verify_hashes()
            elif choice == '7':
                print("\n▶ Sending test alert...")
                self.test_alert()
            elif choice == '8':
                self.system_status()
            elif choice == '9':
                self.add_custom_rule()
            elif choice == '10':
                self.list_custom_rules()
            elif choice == '11':
                self.remove_custom_rule()
            elif choice == '12':
                self.generate_report_menu()
            elif choice == '13':
                self.ransomware_menu()
            elif choice == '14':
                if self.is_monitoring:
                    self.stop_monitoring()
                print("\nGoodbye!")
                break
            else:
                print("  Invalid choice")
            
            # Don't wait for input after starting monitoring (option 2) or exit (14)
            if choice not in ['2', '14']:
                input("\nPress Enter...")


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app)
client_instance = None

def require_client_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Client-Token') or request.cookies.get('client_token')
        if not token or not client_auth.validate_session(token):
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return redirect('/client')

@app.route('/client')
def client_dashboard():
    return render_template('client_dashboard.html')

@app.route('/api/client/login', methods=['POST'])
def client_login():
    data = request.json
    if client_auth.verify_password(data.get('username', 'client'), data.get('password', '')):
        token = client_auth.create_session(data.get('username', 'client'))
        response = jsonify({'status': 'success', 'token': token})
        response.set_cookie('client_token', token, httponly=True, max_age=client_auth.session_timeout, samesite='Lax')
        return response
    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@app.route('/api/client/logout', methods=['POST'])
def client_logout():
    token = request.cookies.get('client_token')
    if token:
        client_auth.logout(token)
    response = jsonify({'status': 'logged_out'})
    response.delete_cookie('client_token')
    return response

@app.route('/api/client/status')
def client_status():
    token = request.cookies.get('client_token')
    return jsonify({'authenticated': bool(token and client_auth.validate_session(token))})

@app.route('/api/client/stats')
@require_client_auth
def client_stats():
    if client_instance:
        try:
            conn = sqlite3.connect(client_instance.db.db_path)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM security_alerts")
            total_alerts = cur.fetchone()[0] or 0
            cur.execute("SELECT COUNT(*) FROM change_events")
            total_changes = cur.fetchone()[0] or 0
            cur.execute("SELECT COUNT(DISTINCT file_path) FROM change_events")
            unique_files = cur.fetchone()[0] or 0
            cur.execute("SELECT COUNT(*) FROM security_alerts WHERE resolved=0")
            unresolved = cur.fetchone()[0] or 0
            conn.close()
            return jsonify({
                'total_alerts': total_alerts,
                'total_changes': total_changes,
                'unique_files': unique_files,
                'unresolved': unresolved
            })
        except:
            return jsonify({'total_alerts': 0, 'total_changes': 0, 'unique_files': 0, 'unresolved': 0})
    return jsonify({'total_alerts': 0, 'total_changes': 0, 'unique_files': 0, 'unresolved': 0})

@app.route('/api/client/alerts')
@require_client_auth
def client_alerts():
    if client_instance:
        try:
            conn = sqlite3.connect(client_instance.db.db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM security_alerts ORDER BY alert_time DESC LIMIT 200")
            rows = cur.fetchall()
            conn.close()
            return jsonify({'alerts': [dict(row) for row in rows]})
        except:
            return jsonify({'alerts': []})
    return jsonify({'alerts': []})

@app.route('/api/client/history')
@require_client_auth
def client_history():
    if client_instance:
        try:
            conn = sqlite3.connect(client_instance.db.db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM change_events ORDER BY event_time DESC LIMIT 200")
            rows = cur.fetchall()
            conn.close()
            return jsonify({'history': [dict(row) for row in rows]})
        except:
            return jsonify({'history': []})
    return jsonify({'history': []})

@app.route('/api/client/file-hash')
@require_client_auth
def client_file_hash():
    file_path = request.args.get('path', '')
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return jsonify({
            'path': file_path,
            'hash': sha256.hexdigest(),
            'size': os.path.getsize(file_path)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/client/reset', methods=['POST'])
@require_client_auth
def client_reset():
    if client_instance:
        try:
            if os.path.exists(client_instance.db.db_path):
                conn = sqlite3.connect(client_instance.db.db_path)
                cur = conn.cursor()
                for table in ['security_alerts', 'change_events', 'file_snapshots']:
                    try:
                        cur.execute(f"DELETE FROM {table}")
                    except:
                        pass
                conn.commit()
                conn.close()
            client_instance.file_cache.clear()
            client_instance.scan_count = 0
            return jsonify({'status': 'reset'})
        except:
            return jsonify({'error': 'Reset failed'}), 500
    return jsonify({'error': 'Client not initialized'}), 400

def start_client_dashboard(client, port=5001):
    global client_instance
    client_instance = client
    
    TEMPLATE_DIR = Path('templates')
    TEMPLATE_DIR.mkdir(exist_ok=True)
    
    def run():
        print(f"\n   Client Dashboard: http://localhost:{port}/client")
        print(f"   Login: client / client123")
        print(f"   (Dashboard accessible only on this machine)\n")
        app.run(host='127.0.0.1', port=port, debug=False, threaded=True, use_reloader=False)
    
    threading.Thread(target=run, daemon=True).start()
    time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description='SmartFileGuard Client')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon (no output)')
    parser.add_argument('--scan', action='store_true', help='Run single scan and exit')
    parser.add_argument('--server', help='Central server IP address')
    parser.add_argument('--api-key', help='API key for server')
    parser.add_argument('--port', type=int, default=5001, help='Dashboard port')
    parser.add_argument('--no-dashboard', action='store_true', help='Disable web dashboard')
    args = parser.parse_args()
    
    if args.server:
        os.environ['SFG_CENTRAL_SERVER'] = args.server
    if args.api_key:
        os.environ['SFG_API_KEY'] = args.api_key
    
    client = SmartFileGuardClient(silent=args.daemon)
    
    if not args.no_dashboard and not args.daemon:
        start_client_dashboard(client, args.port)
    
    if args.daemon:
        print(f"SmartFileGuard Client v2.1.0 - Daemon Mode")
        print(f"Node: {client.node_name}")
        print(f"Server: {client.server_url}")
        print(f"Log file: smartfileguard_client.log")
        print(f"\nPress Ctrl+C to stop...")
        client.start_continuous_monitoring()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            client.stop_monitoring()
            print("\nDaemon stopped.")
    elif args.scan:
        print("Starting scan...")
        client.run_single_scan()
        time.sleep(2)
        print("Scan complete.")
    else:
        client.interactive_menu()

if __name__ == "__main__":
    main()