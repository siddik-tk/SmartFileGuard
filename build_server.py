#!/usr/bin/env python3
"""Build SmartFileGuard Server executable"""
import os, sys, shutil
from pathlib import Path

print("=" * 60)
print("Building SmartFileGuard Server Installer...")
print("=" * 60)

# Clean previous builds
for d in ['build', 'dist']:
    if Path(d).exists():
        shutil.rmtree(d)

# Build command
cmd = [
    'pyinstaller',
    '--onefile',
    '--name=SmartFileGuard_Server',
    '--console',
    '--add-data=central_server.py;.',
    '--add-data=auth.py;.',
    '--add-data=report_exporter.py;.',
    '--add-data=network_config.json;.',
    '--hidden-import=flask',
    '--hidden-import=flask_cors',
    '--hidden-import=sqlite3',
    '--hidden-import=json',
    '--hidden-import=logging',
    'central_server.py'
]

os.system(' '.join(cmd))

print("\n✅ Server EXE created: dist/SmartFileGuard_Server.exe")