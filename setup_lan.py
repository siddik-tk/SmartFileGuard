#!/usr/bin/env python3
"""
Setup script for LAN deployment of SmartFileGuard
"""

import os
import sys
import json
import socket
import platform
import subprocess
import secrets
from pathlib import Path

def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def install_dependencies():
    """Install required dependencies"""
    print("\n" + "="*60)
    print("Installing dependencies...")
    print("="*60)
    
    # Install from requirements.txt if it exists
    req_file = Path('requirements.txt')
    if req_file.exists():
        print("   Found requirements.txt, installing all dependencies...")
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("   ✅ All dependencies installed!")
            return True
    
    # Fallback: install individually
    dependencies = ['watchdog', 'psutil', 'requests', 'flask', 'flask-cors', 'reportlab', 'pandas', 'openpyxl']
    
    for dep in dependencies:
        print(f"   Installing {dep}...")
        try:
            subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '--upgrade', dep],
                capture_output=True, text=True, timeout=120
            )
            print(f"   ✅ {dep}")
        except:
            print(f"   ⚠️  Could not install {dep}")
    
    return True

def setup_server():
    """Setup central server configuration"""
    print("\n" + "="*60)
    print("Setting up Central Server...")
    print("="*60)
    
    ip = get_local_ip()
    print(f"   Detected IP: {ip}")
    
    api_key = secrets.token_hex(32)
    
    config = {
        'server_host': '0.0.0.0',
        'server_port': 5000,
        'central_server': ip,
        'node_name': 'central-server',
        'node_group': 'servers',
        'use_central_db': False,
        'forward_alerts': False,
        'sync_interval': 60,
        'api_key': api_key
    }
    
    with open('network_config.json', 'w') as f:
        json.dump(config, f, indent=4)
    
    with open('.env', 'w') as f:
        f.write(f"SFG_API_KEY={api_key}\n")
        f.write(f"SFG_CENTRAL_SERVER={ip}\n")
        f.write(f"SFG_NODE_NAME=central-server\n")
    
    # Create server launcher
    with open('start_server.sh', 'w') as f:
        f.write('#!/bin/bash\n')
        f.write('echo "Starting SmartFileGuard Central Server..."\n')
        f.write(f'export SFG_API_KEY={api_key}\n')
        f.write(f'export SFG_CENTRAL_SERVER={ip}\n')
        f.write('python3 central_server.py\n')
    os.chmod('start_server.sh', 0o755)
    
    print(f"\n✅ Server configuration created!")
    print(f"   Server IP: {ip}")
    print(f"   API Key: {api_key}")
    
    return ip, api_key

def setup_client(server_ip, api_key, node_name=None):
    """Setup client configuration"""
    print("\n" + "="*60)
    print("Setting up Client...")
    print("="*60)
    
    if not node_name:
        node_name = socket.gethostname()
    
    config = {
        'server_host': '0.0.0.0',
        'server_port': 5000,
        'central_server': server_ip,
        'node_name': node_name,
        'node_group': 'clients',
        'use_central_db': False,
        'forward_alerts': True,
        'sync_interval': 60,
        'api_key': api_key
    }
    
    with open('network_config.json', 'w') as f:
        json.dump(config, f, indent=4)
    
    with open('.env', 'w') as f:
        f.write(f"SFG_API_KEY={api_key}\n")
        f.write(f"SFG_CENTRAL_SERVER={server_ip}\n")
        f.write(f"SFG_NODE_NAME={node_name}\n")
        f.write(f"SFG_FORWARD_ALERTS=true\n")
    
    os.environ['SFG_API_KEY'] = api_key
    os.environ['SFG_CENTRAL_SERVER'] = server_ip
    os.environ['SFG_NODE_NAME'] = node_name
    
    # Create client launcher
    with open('start_client.sh', 'w') as f:
        f.write('#!/bin/bash\n')
        f.write('echo "Starting SmartFileGuard Client..."\n')
        f.write(f'export SFG_API_KEY={api_key}\n')
        f.write(f'export SFG_CENTRAL_SERVER={server_ip}\n')
        f.write(f'export SFG_NODE_NAME={node_name}\n')
        f.write('echo "Node: $SFG_NODE_NAME"\n')
        f.write('echo "Server: $SFG_CENTRAL_SERVER"\n')
        f.write('python3 run_client.py\n')
    os.chmod('start_client.sh', 0o755)
    
    print(f"\n✅ Client configuration created!")
    print(f"   Node: {node_name}")
    print(f"   Server: {server_ip}:5000")

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║         SmartFileGuard LAN Deployment Setup v2.1.0           ║
╠══════════════════════════════════════════════════════════════╣
║  1. Setup Central Server                                     ║
║  2. Setup Client                                             ║
║  3. Install Dependencies Only                                ║
║  4. Full Setup (Server + Dependencies)                       ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    choice = input("\nChoice (1-4): ").strip()
    
    if choice == '1':
        install_dependencies()
        ip, api_key = setup_server()
        print(f"\n📋 Client Configuration:")
        print(f"   Server IP: {ip}")
        print(f"   API Key:  {api_key}")
    elif choice == '2':
        server_ip = input("Enter central server IP address: ").strip()
        api_key = input("Enter API key: ").strip()
        node_name = input("Enter node name (Enter for hostname): ").strip()
        if not server_ip or not api_key:
            print("❌ Server IP and API Key required")
            return
        install_dependencies()
        setup_client(server_ip, api_key, node_name if node_name else None)
    elif choice == '3':
        install_dependencies()
    elif choice == '4':
        install_dependencies()
        ip, api_key = setup_server()
        print(f"\n📋 Client Configuration:")
        print(f"   Server IP: {ip}")
        print(f"   API Key:  {api_key}")
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()