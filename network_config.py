#!/usr/bin/env python3
"""
Network Configuration for LAN Deployment
"""

import os
import json
import socket
from pathlib import Path
from typing import Dict, Optional

class NetworkConfig:
    """Central network configuration for LAN deployment"""
    
    SERVER_HOST = os.environ.get('SFG_SERVER_HOST', '0.0.0.0')
    SERVER_PORT = int(os.environ.get('SFG_SERVER_PORT', 5000))
    
    CENTRAL_SERVER = os.environ.get('SFG_CENTRAL_SERVER', None)
    
    NODE_NAME = os.environ.get('SFG_NODE_NAME', socket.gethostname())
    NODE_GROUP = os.environ.get('SFG_NODE_GROUP', 'default')
    
    USE_CENTRAL_DB = os.environ.get('SFG_USE_CENTRAL_DB', 'false').lower() == 'true'
    
    PG_HOST = os.environ.get('SFG_PG_HOST', 'localhost')
    PG_PORT = int(os.environ.get('SFG_PG_PORT', 5432))
    PG_DATABASE = os.environ.get('SFG_PG_DATABASE', 'smartfileguard')
    PG_USER = os.environ.get('SFG_PG_USER', 'sfg_user')
    PG_PASSWORD = os.environ.get('SFG_PG_PASSWORD', '')
    
    API_KEY = os.environ.get('SFG_API_KEY', 'change-this-secret-key')
    
    FORWARD_ALERTS = os.environ.get('SFG_FORWARD_ALERTS', 'true').lower() == 'true'
    ALERT_RETRY_COUNT = 3
    ALERT_RETRY_DELAY = 5
    
    SYNC_INTERVAL = int(os.environ.get('SFG_SYNC_INTERVAL', 60))
    OFFLINE_BUFFER_SIZE = 1000
    
    @classmethod
    def get_server_url(cls) -> str:
        """Get central server URL"""
        if cls.CENTRAL_SERVER:
            return f"http://{cls.CENTRAL_SERVER}:{cls.SERVER_PORT}"
        return f"http://localhost:{cls.SERVER_PORT}"
    
    @classmethod
    def save_config(cls, filepath: str = 'network_config.json'):
        """Save current configuration to file"""
        config = {
            'server_host': cls.SERVER_HOST,
            'server_port': cls.SERVER_PORT,
            'central_server': cls.CENTRAL_SERVER,
            'node_name': cls.NODE_NAME,
            'node_group': cls.NODE_GROUP,
            'use_central_db': cls.USE_CENTRAL_DB,
            'forward_alerts': cls.FORWARD_ALERTS,
            'sync_interval': cls.SYNC_INTERVAL,
            'api_key': cls.API_KEY[:16] + '...'  # Don't save full key
        }
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=4)
        print(f"Configuration saved to {filepath}")
    
    @classmethod
    def load_config(cls, filepath: str = 'network_config.json'):
        """Load configuration from file"""
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                config = json.load(f)
                cls.SERVER_HOST = config.get('server_host', cls.SERVER_HOST)
                cls.SERVER_PORT = config.get('server_port', cls.SERVER_PORT)
                cls.CENTRAL_SERVER = config.get('central_server', cls.CENTRAL_SERVER)
                cls.NODE_NAME = config.get('node_name', cls.NODE_NAME)
                cls.NODE_GROUP = config.get('node_group', cls.NODE_GROUP)
                cls.USE_CENTRAL_DB = config.get('use_central_db', cls.USE_CENTRAL_DB)
                cls.FORWARD_ALERTS = config.get('forward_alerts', cls.FORWARD_ALERTS)
                cls.SYNC_INTERVAL = config.get('sync_interval', cls.SYNC_INTERVAL)
                # Don't overwrite API_KEY from config file if set via env
                if not os.environ.get('SFG_API_KEY'):
                    cls.API_KEY = config.get('api_key', cls.API_KEY)
                print(f"Configuration loaded from {filepath}")