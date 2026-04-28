#!/usr/bin/env python3
"""
Authentication module for SmartFileGuard
Provides admin access control with password hashing
"""

import os
import json
import hashlib
import secrets
from pathlib import Path
from functools import wraps
from flask import request, jsonify, session, redirect, url_for
from datetime import datetime, timedelta

class AuthManager:
    """Manages admin authentication"""
    
    def __init__(self, auth_file='admin_auth.json'):
        self.auth_file = Path(auth_file)
        self.sessions = {}
        self._init_auth()
    
    def _init_auth(self):
        """Initialize or load admin credentials"""
        if not self.auth_file.exists():
            # Create default admin account
            default_password = 'admin123'  # Change this!
            salt = secrets.token_hex(16)
            password_hash = self._hash_password(default_password, salt)
            
            auth_data = {
                'admin': {
                    'password_hash': password_hash,
                    'salt': salt,
                    'created': datetime.now().isoformat(),
                    'role': 'admin'
                }
            }
            with open(self.auth_file, 'w') as f:
                json.dump(auth_data, f, indent=4)
            
            print(f"""
╔══════════════════════════════════════════════════════════════╗
║  🔐 DEFAULT ADMIN CREDENTIALS CREATED                        ║
╠══════════════════════════════════════════════════════════════╣
║  Username: admin                                             ║
║  Password: admin123                                          ║
║                                                              ║
║  ⚠️  CHANGE THIS PASSWORD IMMEDIATELY!                      ║
║  Use: python auth.py --change-password                       ║
╚══════════════════════════════════════════════════════════════╝
""")
        else:
            with open(self.auth_file) as f:
                self.auth_data = json.load(f)
    
    def _hash_password(self, password, salt):
        """Hash password with salt"""
        return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
    
    def verify_password(self, username, password):
        """Verify admin credentials"""
        try:
            with open(self.auth_file) as f:
                auth_data = json.load(f)
            
            if username in auth_data:
                user_data = auth_data[username]
                salt = user_data['salt']
                expected_hash = user_data['password_hash']
                actual_hash = self._hash_password(password, salt)
                return actual_hash == expected_hash
            
            return False
        except:
            return False
    
    def change_password(self, username, old_password, new_password):
        """Change admin password"""
        if not self.verify_password(username, old_password):
            return False, "Current password is incorrect"
        
        if len(new_password) < 6:
            return False, "Password must be at least 6 characters"
        
        try:
            with open(self.auth_file) as f:
                auth_data = json.load(f)
            
            salt = secrets.token_hex(16)
            password_hash = self._hash_password(new_password, salt)
            
            auth_data[username] = {
                'password_hash': password_hash,
                'salt': salt,
                'changed_at': datetime.now().isoformat(),
                'role': 'admin'
            }
            
            with open(self.auth_file, 'w') as f:
                json.dump(auth_data, f, indent=4)
            
            return True, "Password changed successfully"
        except Exception as e:
            return False, f"Error: {e}"
    
    def create_session(self, username):
        """Create a session token"""
        token = secrets.token_hex(32)
        self.sessions[token] = {
            'username': username,
            'created': datetime.now(),
            'expires': datetime.now() + timedelta(hours=8)
        }
        return token
    
    def validate_session(self, token):
        """Validate a session token"""
        if token in self.sessions:
            session_data = self.sessions[token]
            if datetime.now() < session_data['expires']:
                return True
            else:
                del self.sessions[token]
        return False
    
    def logout(self, token):
        """Destroy a session"""
        if token in self.sessions:
            del self.sessions[token]

# Initialize auth manager
auth = AuthManager()