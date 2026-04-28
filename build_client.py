#!/usr/bin/env python3
"""Build SmartFileGuard Client executable"""
import os, sys, shutil
from pathlib import Path

print("=" * 60)
print("Building SmartFileGuard Client Installer...")
print("=" * 60)

for d in ['build_client', 'dist_client']:
    if Path(d).exists():
        shutil.rmtree(d)

cmd = [
    'pyinstaller',
    '--onefile',
    '--name=SmartFileGuard_Client',
    '--console',
    '--distpath=dist_client',
    '--workpath=build_client',
    '--hidden-import=requests',
    '--hidden-import=watchdog',
    '--hidden-import=psutil',
    '--hidden-import=json',
    '--hidden-import=sqlite3',
    '--hidden-import=logging',
    '--hidden-import=threading',
    '--hidden-import=hashlib',
    '--hidden-import=uuid',
    'run_client.py'
]

os.system(' '.join(cmd))

print("\n✅ Client EXE created: dist_client/SmartFileGuard_Client.exe")