#!/usr/bin/env python3
"""
SmartFileGuard Central Server v2.1.0
Admin portal accessible ONLY via localhost (127.0.0.1)
Session expires after 1 hour for security
"""
import os, sys, json, csv, sqlite3, logging, secrets, socket, hashlib, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, request, jsonify, redirect, send_file, render_template, abort
from flask_cors import CORS
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ---------- CONFIG ----------
def load_config():
    for f in ['.env', 'network_config.json']:
        pf = Path(f)
        if not pf.exists(): continue
        try:
            if f.endswith('.json'):
                with open(pf) as fh:
                    c = json.load(fh)
                    for k, v in c.items():
                        ek = f'SFG_{k.upper()}'
                        if not os.environ.get(ek) and v:
                            os.environ[ek] = str(v)
            else:
                with open(pf) as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            k, v = line.split('=', 1)
                            os.environ[k.strip()] = v.strip()
        except: pass
load_config()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [SERVER] - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler('central_server.log'), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# ---------- AUTH with 1-hour session timeout ----------
class AuthManager:
    def __init__(self, auth_file='admin_auth.json'):
        self.auth_file = Path(auth_file)
        self.sessions = {}
        self.session_timeout = 3600  # 1 hour in seconds
        self._setup_auth()

    def _setup_auth(self):
        need_create = not self.auth_file.exists() or self.auth_file.stat().st_size < 10
        if not need_create:
            try:
                with open(self.auth_file) as f:
                    data = json.load(f)
                for user in data:
                    if 'password_hash' in data[user] and 'ph' not in data[user]:
                        data[user]['ph'] = data[user].pop('password_hash')
                with open(self.auth_file, 'w') as f:
                    json.dump(data, f, indent=4)
                self.auth_data = data
                return
            except:
                need_create = True
        if need_create:
            salt = secrets.token_hex(16)
            password_hash = hashlib.sha256(f"admin123{salt}".encode()).hexdigest()
            self.auth_data = {'admin': {'ph': password_hash, 'salt': salt, 'role': 'admin'}}
            with open(self.auth_file, 'w') as f:
                json.dump(self.auth_data, f, indent=4)
            logger.info("Default admin account created (admin / admin123)")

    def verify_password(self, username, password):
        if username not in self.auth_data: return False
        return hashlib.sha256(f"{password}{self.auth_data[username]['salt']}".encode()).hexdigest() == self.auth_data[username]['ph']

    def verify_admin_password(self, password):
        """Verify admin password for sensitive operations"""
        return self.verify_password('admin', password)

    def change_password(self, username, old_pw, new_pw):
        if not self.verify_password(username, old_pw): return False, "Wrong password"
        if len(new_pw) < 6: return False, "Min 6 chars"
        salt = secrets.token_hex(16)
        self.auth_data[username]['ph'] = hashlib.sha256(f"{new_pw}{salt}".encode()).hexdigest()
        self.auth_data[username]['salt'] = salt
        with open(self.auth_file, 'w') as f: json.dump(self.auth_data, f, indent=4)
        self.sessions.clear()
        return True, "Password changed!"

    def create_session(self, username):
        now = datetime.now()
        # Clean expired sessions
        expired = [k for k,v in self.sessions.items() if (now - v['c']).total_seconds() > self.session_timeout]
        for k in expired:
            del self.sessions[k]
        token = secrets.token_hex(32)
        self.sessions[token] = {'u': username, 'c': now}
        return token

    def validate_session(self, token):
        if token in self.sessions:
            session_age = (datetime.now() - self.sessions[token]['c']).total_seconds()
            if session_age < self.session_timeout:
                # Refresh session on activity
                self.sessions[token]['c'] = datetime.now()
                return True
            del self.sessions[token]
        return False

    def logout(self, token):
        if token in self.sessions: del self.sessions[token]

auth = AuthManager()

# ---------- DATABASE ----------
class Database:
    def __init__(self, path='central_forensics.db'):
        self.path = path
        self._init()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        conn = sqlite3.connect(self.path, timeout=30)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_name TEXT UNIQUE,
            node_group TEXT DEFAULT 'default',
            ip_address TEXT,
            last_seen DATETIME,
            status TEXT DEFAULT 'active',
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            version TEXT,
            os_info TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            node_name TEXT,
            alert_time DATETIME,
            alert_type TEXT,
            description TEXT,
            severity TEXT DEFAULT 'MEDIUM',
            file_path TEXT,
            process_name TEXT,
            user_name TEXT,
            risk_score REAL DEFAULT 0.5,
            details TEXT,
            hash_before TEXT,
            hash_after TEXT,
            received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            resolved BOOLEAN DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS file_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_name TEXT,
            event_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_path TEXT,
            change_type TEXT,
            user_name TEXT,
            process_name TEXT,
            hash_before TEXT,
            hash_after TEXT,
            risk_score REAL DEFAULT 0.0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS heartbeats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_name TEXT,
            heartbeat_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT,
            stats TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS scan_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command TEXT,
            target_node TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_nodes_last ON nodes(last_seen)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(alert_time)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_file_history_time ON file_history(event_time)')
        conn.commit()
        conn.close()

    def register_node(self, node_name, node_group='default', ip='?', ver=None, os_info=None):
        conn = self._conn()
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO nodes (node_name, node_group, ip_address, last_seen, version, os_info, status)
                VALUES (?,?,?,?,?,?,'active') ON CONFLICT(node_name) DO UPDATE SET
                node_group=excluded.node_group, ip_address=excluded.ip_address,
                last_seen=excluded.last_seen, version=excluded.version, os_info=excluded.os_info, status='active' ''',
                (node_name, node_group, ip, datetime.now(), ver, os_info))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Register error: {e}")
            return False
        finally:
            conn.close()

    def heartbeat(self, node_name, stats=None):
        conn = self._conn()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO heartbeats (node_name, stats) VALUES (?,?)', 
                     (node_name, json.dumps(stats) if stats else '{}'))
            c.execute('UPDATE nodes SET last_seen=?, status=? WHERE node_name=?', 
                     (datetime.now(), 'active', node_name))
            conn.commit()
            return True
        except Exception as e:
            logger.error(f"Heartbeat error: {e}")
            return False
        finally:
            conn.close()

    def save_alert(self, data):
        conn = self._conn()
        c = conn.cursor()
        try:
            hash_before = data.get('hash_before', '')
            hash_after = data.get('hash_after', '')
            if not hash_before or not hash_after:
                details = data.get('details', '{}')
                if details and details != '{}':
                    try:
                        d = json.loads(details) if isinstance(details, str) else details
                        hash_before = hash_before or d.get('hash_before', d.get('old_hash', ''))
                        hash_after = hash_after or d.get('hash_after', d.get('new_hash', ''))
                    except:
                        pass
            
            c.execute('''INSERT INTO alerts (alert_id, node_name, alert_time, alert_type, description,
                severity, file_path, process_name, user_name, risk_score, details, hash_before, hash_after)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (data.get('alert_id', secrets.token_hex(8)), 
                 data.get('node_name', 'unknown'),
                 data.get('alert_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                 data.get('alert_type', 'UNKNOWN'),
                 data.get('description', ''),
                 data.get('severity', 'MEDIUM'),
                 data.get('file_path', ''),
                 data.get('process_name', ''),
                 data.get('user_name', ''),
                 data.get('risk_score', 0.5),
                 data.get('details', '{}'),
                 hash_before,
                 hash_after))
            conn.commit()
            return True
        except:
            return False
        finally:
            conn.close()

    def save_file_event(self, data):
        conn = self._conn()
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO file_history (node_name, event_time, file_path, change_type,
                user_name, process_name, hash_before, hash_after, risk_score)
                VALUES (?,?,?,?,?,?,?,?,?)''',
                (data.get('node_name', 'unknown'),
                 data.get('event_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                 data.get('file_path', ''),
                 data.get('change_type', 'UNKNOWN'),
                 data.get('user_name', ''),
                 data.get('process_name', ''),
                 data.get('hash_before', ''),
                 data.get('hash_after', ''),
                 data.get('risk_score', 0.0)))
            conn.commit()
            return True
        except:
            return False
        finally:
            conn.close()

    def get_nodes(self):
        conn = self._conn()
        c = conn.cursor()
        c.execute('SELECT * FROM nodes ORDER BY last_seen DESC')
        rows = c.fetchall()
        conn.close()
        nodes = []
        for r in rows:
            n = dict(r)
            if n.get('last_seen'):
                try:
                    ls = n['last_seen']
                    if isinstance(ls, str):
                        ls = datetime.strptime(ls[:19], '%Y-%m-%d %H:%M:%S')
                    diff = (datetime.now() - ls).total_seconds()
                    n['connection_status'] = 'connected' if diff < 120 else 'idle' if diff < 600 else 'disconnected'
                except:
                    n['connection_status'] = 'unknown'
            else:
                n['connection_status'] = 'never_connected'
            nodes.append(n)
        return nodes

    def get_alerts(self, limit=5000, start=None, end=None, node=None):
        conn = self._conn()
        c = conn.cursor()
        q = "SELECT * FROM alerts WHERE 1=1"
        p = []
        if start:
            q += " AND date(alert_time) >= ?"
            p.append(start)
        if end:
            q += " AND date(alert_time) <= ?"
            p.append(end)
        if node and node != 'all':
            q += " AND node_name = ?"
            p.append(node)
        q += " ORDER BY alert_time DESC LIMIT ?"
        p.append(limit)
        c.execute(q, p)
        rows = c.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_file_history(self, limit=5000, start=None, end=None, node=None):
        conn = self._conn()
        c = conn.cursor()
        q = "SELECT * FROM file_history WHERE 1=1"
        p = []
        if start:
            q += " AND date(event_time) >= ?"
            p.append(start)
        if end:
            q += " AND date(event_time) <= ?"
            p.append(end)
        if node and node != 'all':
            q += " AND node_name = ?"
            p.append(node)
        q += " ORDER BY event_time DESC LIMIT ?"
        p.append(limit)
        c.execute(q, p)
        rows = c.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_stats(self):
        conn = sqlite3.connect(self.path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM nodes WHERE status='active' AND last_seen > datetime('now','-2 minutes')")
        active = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM nodes")
        tn = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM alerts")
        ta = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM alerts WHERE alert_time > datetime('now','-1 day')")
        r24 = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM file_history")
        fe = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(DISTINCT file_path) FROM file_history WHERE file_path != ''")
        uf = c.fetchone()[0] or 0
        conn.close()
        return {
            'active_nodes': active,
            'total_nodes': tn,
            'total_alerts': ta,
            'recent_alerts_24h': r24,
            'total_file_events': fe,
            'unique_files_tracked': uf
        }

    def add_scan_command(self, cmd, target='all'):
        conn = self._conn()
        c = conn.cursor()
        c.execute("INSERT INTO scan_commands (command, target_node) VALUES (?,?)", (cmd, target))
        conn.commit()
        conn.close()

    def get_pending_commands(self, node_name):
        conn = self._conn()
        c = conn.cursor()
        c.execute("SELECT * FROM scan_commands WHERE (target_node=? OR target_node='all') AND status='pending'", (node_name,))
        rows = c.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def mark_command_done(self, cid):
        conn = self._conn()
        c = conn.cursor()
        c.execute("UPDATE scan_commands SET status='done' WHERE id=?", (cid,))
        conn.commit()
        conn.close()

    def clear_alerts(self):
        conn = sqlite3.connect(self.path)
        conn.cursor().execute("DELETE FROM alerts")
        conn.commit()
        conn.close()

    def reset_all_data(self):
        conn = sqlite3.connect(self.path)
        c = conn.cursor()
        for t in ['nodes', 'alerts', 'file_history', 'heartbeats', 'scan_commands']:
            c.execute(f"DELETE FROM {t}")
        conn.commit()
        conn.close()
        for f in Path('exports').glob('*'):
            f.unlink()

db = Database()

# ---------- EXPORTER ----------
class ReportExporter:
    def __init__(self):
        self.dir = Path('exports')
        self.dir.mkdir(exist_ok=True)

    def export_all(self, alerts, nodes, history, fmt):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fp = self.dir / f"report_{ts}.{fmt}"

        if fmt == 'json':
            with open(fp, 'w') as f:
                json.dump({
                    'export_time': datetime.now().isoformat(),
                    'alerts': alerts,
                    'nodes': nodes,
                    'file_history': history
                }, f, default=str, indent=2)

        elif fmt == 'csv':
            with open(fp, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(['=== ALERTS ==='])
                w.writerow(['Time', 'Node', 'Type', 'Severity', 'File', 'User', 'Risk', 'Hash Before', 'Hash After'])
                for a in alerts:
                    w.writerow([
                        str(a.get('alert_time', ''))[:19],
                        a.get('node_name', ''),
                        a.get('alert_type', ''),
                        a.get('severity', ''),
                        a.get('file_path', ''),
                        a.get('user_name', ''),
                        f"{a.get('risk_score', 0):.0%}" if a.get('risk_score') else 'N/A',
                        (a.get('hash_before', '')[:64]) or 'N/A',
                        (a.get('hash_after', '')[:64]) or 'N/A'
                    ])
                w.writerow([])
                w.writerow(['=== FILE HISTORY ==='])
                w.writerow(['Time', 'Node', 'File', 'Change', 'User', 'Risk', 'Hash Before', 'Hash After', 'Changed'])
                for h in history:
                    hb = h.get('hash_before', '')
                    ha = h.get('hash_after', '')
                    changed = 'YES' if hb and ha and hb != ha else 'NO' if hb and ha else 'N/A'
                    w.writerow([
                        str(h.get('event_time', ''))[:19],
                        h.get('node_name', ''),
                        h.get('file_path', ''),
                        h.get('change_type', ''),
                        h.get('user_name', ''),
                        f"{h.get('risk_score', 0):.0%}" if h.get('risk_score') else 'N/A',
                        hb[:64] if hb else 'N/A',
                        ha[:64] if ha else 'N/A',
                        changed
                    ])

        elif fmt == 'pdf':
            try:
                from fpdf import FPDF
                pdf = FPDF(orientation='L', unit='mm', format='A4')
                pdf.set_auto_page_break(auto=True, margin=15)
                pdf.add_page()
                pdf.set_fill_color(26, 54, 93)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font('Helvetica', 'B', 18)
                pdf.cell(0, 14, 'SmartFileGuard Security Report', new_x="LMARGIN", new_y="NEXT", align='C', fill=True)
                pdf.set_font('Helvetica', '', 9)
                pdf.cell(0, 8, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', new_x="LMARGIN", new_y="NEXT", align='C')
                pdf.ln(6)
                pdf.set_fill_color(45, 55, 72)
                pdf.set_font('Helvetica', 'B', 11)
                pdf.cell(0, 8, '  EXECUTIVE SUMMARY', new_x="LMARGIN", new_y="NEXT", fill=True)
                pdf.set_font('Helvetica', '', 9)
                pdf.set_text_color(45, 55, 72)
                pdf.cell(0, 6, f'  Alerts: {len(alerts)} | Nodes: {len(nodes)} | Events: {len(history)}', new_x="LMARGIN", new_y="NEXT")
                pdf.ln(6)
                if alerts:
                    pdf.set_fill_color(49, 130, 206)
                    pdf.set_text_color(255, 255, 255)
                    pdf.set_font('Helvetica', 'B', 10)
                    pdf.cell(0, 8, '  SECURITY ALERTS', new_x="LMARGIN", new_y="NEXT", fill=True)
                    pdf.ln(4)
                    w = [26, 25, 30, 15, 40, 20, 15, 45, 45]
                    pdf.set_fill_color(26, 54, 93)
                    pdf.set_font('Helvetica', 'B', 7)
                    headers = ['Time', 'Node', 'Type', 'Sev', 'File', 'User', 'Risk', 'Hash Before', 'Hash After']
                    for i, h in enumerate(headers):
                        pdf.cell(w[i], 7, h, border=1, align='C', fill=True)
                    pdf.ln()
                    pdf.set_font('Helvetica', '', 7)
                    for i, a in enumerate(alerts[:20]):
                        pdf.set_fill_color(245, 247, 250) if i % 2 == 0 else pdf.set_fill_color(255, 255, 255)
                        pdf.set_text_color(45, 55, 72)
                        row = [
                            str(a.get('alert_time', ''))[5:16],
                            str(a.get('node_name', ''))[:10],
                            str(a.get('alert_type', ''))[:13],
                            a.get('severity', '')[:4],
                            Path(str(a.get('file_path', ''))).name[:19],
                            str(a.get('user_name', ''))[:7],
                            f"{a.get('risk_score', 0):.0%}" if a.get('risk_score') else 'N/A',
                            (a.get('hash_before', '')[:40]) or 'N/A',
                            (a.get('hash_after', '')[:40]) or 'N/A'
                        ]
                        for j, v in enumerate(row):
                            pdf.cell(w[j], 6, str(v), border=1, fill=True)
                        pdf.ln()
                if history:
                    pdf.add_page()
                    pdf.set_fill_color(56, 161, 105)
                    pdf.set_text_color(255, 255, 255)
                    pdf.set_font('Helvetica', 'B', 10)
                    pdf.cell(0, 8, '  FILE HISTORY', new_x="LMARGIN", new_y="NEXT", fill=True)
                    pdf.ln(4)
                    w2 = [26, 20, 38, 12, 14, 12, 42, 42, 14]
                    h2 = ['Time', 'Node', 'File', 'Change', 'User', 'Risk', 'Hash Before', 'Hash After', 'Changed']
                    pdf.set_fill_color(26, 54, 93)
                    pdf.set_font('Helvetica', 'B', 7)
                    for i, h in enumerate(h2):
                        pdf.cell(w2[i], 7, h, border=1, align='C', fill=True)
                    pdf.ln()
                    pdf.set_font('Helvetica', '', 7)
                    for i, h in enumerate(history[:20]):
                        pdf.set_fill_color(245, 247, 250) if i % 2 == 0 else pdf.set_fill_color(255, 255, 255)
                        pdf.set_text_color(45, 55, 72)
                        hb = h.get('hash_before', '')
                        ha = h.get('hash_after', '')
                        changed = 'YES' if hb and ha and hb != ha else 'NO' if hb and ha else 'N/A'
                        row = [
                            str(h.get('event_time', ''))[5:16],
                            str(h.get('node_name', ''))[:9],
                            Path(str(h.get('file_path', ''))).name[:18],
                            h.get('change_type', '')[:6],
                            str(h.get('user_name', ''))[:6],
                            f"{h.get('risk_score', 0):.0%}" if h.get('risk_score') else 'N/A',
                            hb[:40] if hb else '-',
                            ha[:40] if ha else '-',
                            changed
                        ]
                        for j, v in enumerate(row):
                            pdf.cell(w2[j], 6, str(v), border=1, fill=True)
                        pdf.ln()
                pdf.output(str(fp))
            except ImportError:
                return self.export_all(alerts, nodes, history, 'csv')
        
        return {'filename': fp.name, 'filepath': str(fp), 'format': fmt, 'size': fp.stat().st_size}

    def list_exports(self):
        return [{'filename': f.name, 'format': f.suffix[1:], 'size': f.stat().st_size,
                'created': datetime.fromtimestamp(f.stat().st_ctime).isoformat()} 
                for f in sorted(self.dir.glob('*'), key=lambda x: x.stat().st_ctime, reverse=True)]

    def delete(self, fn):
        if (self.dir / fn).exists():
            (self.dir / fn).unlink()
            return True
        return False

exporter = ReportExporter()

# ---------- DECORATORS ----------
def require_api(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get('X-API-Key') != API_TOKEN:
            return jsonify({'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Admin-Token') or request.cookies.get('admin_token')
        if not token or not auth.validate_session(token):
            return jsonify({'error': 'Session expired'}), 401
        return f(*args, **kwargs)
    return decorated

def restrict_to_localhost(f):
    """Restrict page access to localhost (127.0.0.1) ONLY"""
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr
        # ONLY allow localhost
        if client_ip not in ['127.0.0.1', 'localhost', '::1']:
            logger.warning(f"BLOCKED: Admin portal access attempt from {client_ip}")
            return "Access Denied - Admin portal is only accessible from the server console (localhost)", 403
        return f(*args, **kwargs)
    return decorated

# ---------- FLASK APP ----------
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app, supports_credentials=True)
API_TOKEN = os.environ.get('SFG_API_KEY', secrets.token_hex(32))

# Get server IP for display only
SERVER_IP = None
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    SERVER_IP = s.getsockname()[0]
    s.close()
except:
    SERVER_IP = '127.0.0.1'

# ---------- API ROUTES (Accessible from clients with API key) ----------
@app.route('/api/health')
def health(): 
    return jsonify({'status': 'healthy', 'version': '2.1.0'})

@app.route('/api/register', methods=['POST'])
@require_api
def register():
    data = request.json
    db.register_node(data.get('node_name'), data.get('node_group', 'default'), 
                    request.remote_addr, data.get('version'), data.get('os_info'))
    return jsonify({'status': 'registered'})

@app.route('/api/alert', methods=['POST'])
@require_api
def alert():
    db.save_alert(request.json)
    return jsonify({'status': 'ok'})

@app.route('/api/file-event', methods=['POST'])
@require_api
def file_event():
    db.save_file_event(request.json)
    return jsonify({'status': 'ok'})

@app.route('/api/heartbeat', methods=['POST'])
@require_api
def heartbeat():
    data = request.json
    db.heartbeat(data.get('node_name'), data.get('stats'))
    return jsonify({'status': 'ok', 'commands': db.get_pending_commands(data.get('node_name'))})

@app.route('/api/command/<int:cid>/done', methods=['POST'])
@require_api
def cmd_done(cid):
    db.mark_command_done(cid)
    return jsonify({'status': 'ok'})

# ---------- PUBLIC READ-ONLY API (No auth needed for viewing data) ----------
@app.route('/api/nodes')
def nodes():
    return jsonify({'nodes': db.get_nodes()})

@app.route('/api/alerts')
def alerts():
    return jsonify({'alerts': db.get_alerts(500, 
                    request.args.get('start_date'), 
                    request.args.get('end_date'), 
                    request.args.get('node'))})

@app.route('/api/file-history')
def file_history():
    return jsonify({'file_history': db.get_file_history(1000,
                    request.args.get('start_date'),
                    request.args.get('end_date'),
                    request.args.get('node'))})

@app.route('/api/stats')
def stats():
    return jsonify(db.get_stats())

# ---------- AUTH ROUTES (Require admin login) ----------
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    if auth.verify_password(data.get('username', 'admin'), data.get('password', '')):
        token = auth.create_session(data.get('username', 'admin'))
        response = jsonify({'status': 'success', 'token': token})
        response.set_cookie('admin_token', token, httponly=True, max_age=3600, samesite='Lax')
        return response
    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    token = request.cookies.get('admin_token')
    if token:
        auth.logout(token)
    response = jsonify({'status': 'logged_out'})
    response.delete_cookie('admin_token')
    return response

@app.route('/api/auth/status')
def auth_status():
    token = request.cookies.get('admin_token')
    return jsonify({'authenticated': bool(token and auth.validate_session(token))})

@app.route('/api/auth/change-password', methods=['POST'])
@require_admin
def change_password():
    data = request.json
    ok, msg = auth.change_password(data.get('username', 'admin'), 
                                   data.get('old_password', ''), 
                                   data.get('new_password', ''))
    if ok:
        response = jsonify({'status': 'success', 'message': msg})
        response.delete_cookie('admin_token')
        return response
    return jsonify({'status': 'error', 'message': msg}), 400

@app.route('/api/auth/verify-password', methods=['POST'])
def verify_password():
    """Verify admin password for sensitive operations (like email config)"""
    data = request.json
    password = data.get('password', '')
    if auth.verify_password('admin', password):
        return jsonify({'verified': True})
    return jsonify({'verified': False}), 401

# ---------- EMAIL CONFIGURATION ROUTES ----------
@app.route('/api/email/status')
@require_admin
def email_status():
    config_file = Path('email_config.json')
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            return jsonify({
                'configured': config.get('configured', False),
                'sender_email': config.get('sender_email', ''),
                'admin_email': config.get('admin_email', ''),
                'smtp_server': config.get('smtp_server', 'smtp.gmail.com'),
                'smtp_port': config.get('smtp_port', 587)
            })
        except:
            pass
    return jsonify({
        'configured': False,
        'sender_email': '',
        'admin_email': '',
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587
    })

@app.route('/api/email/configure', methods=['POST'])
@require_admin
def configure_email():
    data = request.json
    sender_email = data.get('sender_email', '')
    sender_password = data.get('sender_password', '')
    admin_email = data.get('admin_email', '')
    smtp_server = data.get('smtp_server', 'smtp.gmail.com')
    smtp_port = data.get('smtp_port', 587)
    
    if not sender_email or not admin_email:
        return jsonify({'status': 'error', 'message': 'Sender email and admin email are required'}), 400
    
    # Test the email configuration only if password provided
    test_success = True
    test_error = None
    
    if sender_password:
        try:
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = admin_email
            msg['Subject'] = "SmartFileGuard - Configuration Test"
            body = f"""
            SmartFileGuard Test Email
            
            This is a test email from your SmartFileGuard server.
            
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            If you received this, email alerts are working correctly!
            """
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
            server.quit()
            logger.info(f"Test email sent successfully to {admin_email}")
        except Exception as e:
            test_success = False
            test_error = str(e)
            logger.error(f"Email test failed: {e}")
    
    # Save configuration (even if test failed, but user will be warned)
    config = {
        'configured': test_success,
        'sender_email': sender_email,
        'sender_password': sender_password,
        'admin_email': admin_email,
        'smtp_server': smtp_server,
        'smtp_port': smtp_port
    }
    with open('email_config.json', 'w') as f:
        json.dump(config, f, indent=4)
    
    if test_success:
        return jsonify({'status': 'success', 'message': 'Email configured and test sent successfully'})
    else:
        return jsonify({'status': 'warning', 'message': f'Configuration saved but test email failed: {test_error}'})

@app.route('/api/email/test', methods=['POST'])
@require_admin
def test_email():
    """Send a test email using saved configuration"""
    config_file = Path('email_config.json')
    if not config_file.exists():
        return jsonify({'status': 'error', 'message': 'Email not configured'}), 400
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        if not config.get('configured'):
            return jsonify({'status': 'error', 'message': 'Email not properly configured'}), 400
        
        msg = MIMEMultipart()
        msg['From'] = config['sender_email']
        msg['To'] = config['admin_email']
        msg['Subject'] = "SmartFileGuard - Test Email"
        body = f"""
        SmartFileGuard Test Email
        
        This is a test email from your SmartFileGuard server.
        
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        If you received this, email alerts are working correctly!
        """
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['sender_email'], config['sender_password'])
        server.send_message(msg)
        server.quit()
        
        return jsonify({'status': 'success', 'message': 'Test email sent successfully'})
    except Exception as e:
        logger.error(f"Test email failed: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

# ---------- ADMIN ROUTES (Require admin authentication) ----------
@app.route('/api/export', methods=['POST'])
@require_admin
def export_data():
    data = request.json or {}
    fmt = data.get('format', 'json')
    start = data.get('start_date')
    end = data.get('end_date')
    node = data.get('node')
    alerts = db.get_alerts(50000, start, end, node)
    history = db.get_file_history(50000, start, end, node)
    nodes = db.get_nodes()
    result = exporter.export_all(alerts, nodes, history, fmt)
    return jsonify({'status': 'success', 'result': result, 'count': len(alerts) + len(history)})

@app.route('/api/export/download/<filename>')
@require_admin
def download_export(filename):
    filepath = exporter.dir / filename
    if filepath.exists():
        return send_file(filepath, as_attachment=True)
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/exports')
@require_admin
def list_exports():
    return jsonify({'exports': exporter.list_exports()})

@app.route('/api/exports/<filename>', methods=['DELETE'])
@require_admin
def delete_export(filename):
    return jsonify({'status': 'deleted' if exporter.delete(filename) else 'error'})

@app.route('/api/scan/start-all', methods=['POST'])
@require_admin
def scan_start_all():
    db.add_scan_command('START_SCAN', 'all')
    return jsonify({'status': 'ok'})

@app.route('/api/scan/stop-all', methods=['POST'])
@require_admin
def scan_stop_all():
    db.add_scan_command('STOP_SCAN', 'all')
    return jsonify({'status': 'ok'})

@app.route('/api/scan/start/<node>', methods=['POST'])
@require_admin
def scan_start_node(node):
    db.add_scan_command('START_SCAN', node)
    return jsonify({'status': 'ok'})

@app.route('/api/scan/stop/<node>', methods=['POST'])
@require_admin
def scan_stop_node(node):
    db.add_scan_command('STOP_SCAN', node)
    return jsonify({'status': 'ok'})

@app.route('/api/alerts/clear', methods=['POST'])
@require_admin
def clear_alerts():
    db.clear_alerts()
    return jsonify({'status': 'cleared'})

@app.route('/api/system/reset', methods=['POST'])
@require_admin
def system_reset():
    db.reset_all_data()
    return jsonify({'status': 'reset'})

# ---------- FRONTEND ROUTES (Admin Portal - RESTRICTED TO LOCALHOST ONLY) ----------
@app.route('/')
@restrict_to_localhost
def index():
    return redirect('/dashboard')

@app.route('/dashboard')
@restrict_to_localhost
def dashboard():
    return render_template('server_dashboard.html')

@app.route('/favicon.ico')
@restrict_to_localhost
def favicon():
    return '', 204

def main():
    print(f"\n{'='*60}")
    print(f"SmartFileGuard Server v2.1.0")
    print(f"{'='*60}")
    print(f"")
    print(f"🔐 ADMIN PORTAL (Accessible ONLY from server console):")
    print(f"   http://localhost:5000")
    print(f"   http://127.0.0.1:5000")
    print(f"")
    print(f"⏰ Session Timeout: 1 hour (auto-logout for security)")
    print(f"")
    print(f"🌐 API ENDPOINTS (Accessible from clients with API key):")
    print(f"   http://{SERVER_IP}:5000/api/register")
    print(f"   http://{SERVER_IP}:5000/api/alert")
    print(f"   http://{SERVER_IP}:5000/api/heartbeat")
    print(f"")
    print(f"📋 Login: admin / admin123")
    print(f"")
    print(f"⚠️  NOTE: Admin dashboard is NOT accessible via network IP!")
    print(f"   Any attempt to access http://{SERVER_IP}:5000 from another machine")
    print(f"   will show 'Access Denied'")
    print(f"{'='*60}\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)

if __name__ == '__main__':
    main()