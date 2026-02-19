# Smart File Integrity & Forensic System

A professional-grade file monitoring system that combines file integrity monitoring, git-like versioning, and forensic evidence collection.

## Features

- **Smart File Monitoring**: Tracks file changes with risk scoring
- **Tamper-Proof Evidence**: Hash chaining ensures evidence integrity
- **User Attribution**: Tracks who made changes and from which process
- **Real-Time Detection**: Instant alerts for suspicious changes
- **Email Alerts**: Configurable email notifications
- **Comprehensive Reporting**: File history and audit trails

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sfi-project.git
cd sfi-project

2. Install dependencies:

pip install -r requirements.txt

3. Configure environment variables (for email alerts):

export SFG_EMAIL="your_email@gmail.com"
export SFG_EMAIL_PASS="your_app_password"

Usage

1. Interactive Mode

python main.py

2. Command Line Options

# Run as daemon (continuous monitoring)
python main.py --daemon

# Run single scan
python main.py --scan

# Test email configuration
python main.py --test-email

# Verify hash chain integrity
python main.py --verify

3. Configuration
Edit config.py to customize:

- Monitoring paths
- Exclude patterns
- Risk thresholds
- Email settings
- Scan intervals