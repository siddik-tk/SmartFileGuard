#!/usr/bin/env python3
"""Generate self-signed SSL certificate for HTTPS"""
import os

print("Generating SSL certificate...")
os.system('openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"')
print("✅ SSL certificate generated!")
print("   cert.pem - Certificate")
print("   key.pem - Private key")
print("\nServer will now use HTTPS on port 5443")