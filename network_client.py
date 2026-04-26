#!/usr/bin/env python3
"""
Network Client for SmartFileGuard LAN Deployment
Fixed version with proper error handling
"""

import os
import sys
import json
import time
import uuid
import socket
import logging
import platform
import threading
from datetime import datetime
from typing import Dict, Optional
from queue import Queue
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_config import NetworkConfig

logger = logging.getLogger(__name__)


class NetworkClient:
    """Handles communication with central server"""
    
    def __init__(self):
        self.server_url = NetworkConfig.get_server_url()
        self.node_name = NetworkConfig.NODE_NAME
        self.node_group = NetworkConfig.NODE_GROUP
        self.api_key = NetworkConfig.API_KEY
        
        self.offline_queue = Queue(maxsize=NetworkConfig.OFFLINE_BUFFER_SIZE)
        self.is_online = False
        self.last_successful_connection = None
        
        self.session = self._create_session()
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()
        
        self._start_heartbeat()
        
        logger.info(f"Network client initialized for node: {self.node_name}")
        logger.info(f"Central server: {self.server_url}")
    
    def _create_session(self):
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({'X-API-Key': self.api_key})
        return session
    
    def _start_heartbeat(self):
        def send_heartbeat():
            while self.running:
                time.sleep(NetworkConfig.SYNC_INTERVAL)
                self.send_heartbeat()
        
        thread = threading.Thread(target=send_heartbeat, daemon=True)
        thread.start()
    
    def send_heartbeat(self):
        stats = {
            'tracked_files': 0,
            'uptime': time.time()
        }
        
        data = {
            'node_name': self.node_name,
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        }
        
        self._send_request('POST', '/api/heartbeat', data)
    
    def send_alert(self, alert_data: Dict) -> bool:
        alert_data['node_name'] = self.node_name
        alert_data['node_group'] = self.node_group
        alert_data['alert_id'] = str(uuid.uuid4())
        alert_data['alert_time'] = datetime.now().isoformat()
        
        return self._send_request('POST', '/api/alert', alert_data)
    
    def send_file_event(self, event_data: Dict) -> bool:
        event_data['node_name'] = self.node_name
        event_data['event_time'] = datetime.now().isoformat()
        
        return self._send_request('POST', '/api/file-event', event_data)
    
    def register_node(self, version: str = None, os_info: str = None) -> bool:
        data = {
            'node_name': self.node_name,
            'node_group': self.node_group,
            'version': version,
            'os_info': os_info or platform.platform()
        }
        
        return self._send_request('POST', '/api/register', data)
    
    def check_connection(self) -> bool:
        """Check if server is reachable"""
        try:
            response = self.session.get(f"{self.server_url}/api/health", timeout=5)
            if response.status_code == 200:
                self.is_online = True
                self.last_successful_connection = datetime.now()
                return True
        except:
            pass
        self.is_online = False
        return False
    
    def _send_request(self, method: str, endpoint: str, data: Dict = None) -> bool:
        url = f"{self.server_url}{endpoint}"
        
        try:
            response = self.session.request(method, url, json=data, timeout=10)
            
            if response.status_code == 200:
                if not self.is_online:
                    self.is_online = True
                    self.last_successful_connection = datetime.now()
                    logger.info("Connected to central server")
                return True
            elif response.status_code == 401:
                logger.error(f"Authentication failed. Check API key.")
                return False
            else:
                logger.warning(f"Server returned {response.status_code}")
                self._queue_offline(endpoint, data)
                return False
                
        except requests.exceptions.ConnectionError as e:
            if self.is_online:
                logger.warning(f"Connection lost: {e}")
                self.is_online = False
            self._queue_offline(endpoint, data)
            return False
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request error: {e}")
            self.is_online = False
            self._queue_offline(endpoint, data)
            return False
    
    def _queue_offline(self, endpoint: str, data: Dict):
        if self.offline_queue.qsize() < NetworkConfig.OFFLINE_BUFFER_SIZE:
            self.offline_queue.put({
                'endpoint': endpoint,
                'data': data,
                'timestamp': time.time()
            })
    
    def _process_queue(self):
        while self.running:
            try:
                item = self.offline_queue.get(timeout=5)
                
                if self.is_online:
                    url = f"{self.server_url}{item['endpoint']}"
                    try:
                        self.session.post(url, json=item['data'], timeout=10)
                        logger.debug(f"Sent queued request for {item['endpoint']}")
                    except Exception:
                        self.offline_queue.put(item)
                else:
                    self.offline_queue.put(item)
                    time.sleep(10)
                    
            except Exception:
                pass
    
    def stop(self):
        self.running = False
        logger.info("Network client stopped")


class AlertForwarder:
    """Integrates with existing alert system to forward to central server"""
    
    def __init__(self, network_client: NetworkClient):
        self.network_client = network_client
        self.enabled = NetworkConfig.FORWARD_ALERTS
    
    def forward_alert(self, change_data: Dict) -> bool:
        if not self.enabled:
            return False
        
        file_path = change_data.get('file_path', '')
        alert_data = {
            'alert_type': change_data.get('change_type', 'FILE_CHANGE'),
            'description': f"{change_data.get('change_type')} of {os.path.basename(file_path)}",
            'severity': change_data.get('risk_level', 'MEDIUM'),
            'file_path': file_path,
            'process_name': change_data.get('process_name'),
            'user_name': change_data.get('user_name'),
            'risk_score': change_data.get('risk_score', 0),
            'details': json.dumps(change_data.get('details', {}))
        }
        
        return self.network_client.send_alert(alert_data)
    
    def forward_file_event(self, event_data: Dict) -> bool:
        if not self.enabled:
            return False
        
        return self.network_client.send_file_event(event_data)