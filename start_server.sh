#!/bin/bash
echo "Starting SmartFileGuard Central Server..."
export SFG_API_KEY=0b6b8484793ea4c290ccf7cf4a381a3ca3e85c7865f84ff5bb786b01a873087d
export SFG_CENTRAL_SERVER=10.41.55.22
python3 central_server.py
