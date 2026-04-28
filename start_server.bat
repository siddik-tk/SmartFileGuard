@echo off
title SmartFileGuard Central Server
set SFG_API_KEY=e3f7234bbe9caf39282fe52c6fa634d456520f46a2f733bf58b68eaffc221fd8
set SFG_CENTRAL_SERVER=10.41.55.22
echo Starting SmartFileGuard Central Server...
echo.
python central_server.py
pause
