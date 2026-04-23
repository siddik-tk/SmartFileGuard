#!/usr/bin/env python3
"""
Git Manager Module for SmartFileGuard
Silent background Git operations for forensic preservation
"""

import os
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)


class GitManager:
    """Manages silent Git operations for forensic version control"""
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path).absolute()
        self.git_dir = self.repo_path / ".git"
        self.enabled = self._check_git_available()
        
        if self.enabled:
            self._ensure_repo_initialized()
            logger.info("Git Manager initialized - Auto-commit enabled")
        else:
            logger.warning("Git not available - version control disabled")
    
    def _check_git_available(self) -> bool:
        """Check if git is installed"""
        try:
            subprocess.run(["git", "--version"], capture_output=True, check=True)
            return True
        except:
            return False
    
    def _ensure_repo_initialized(self):
        """Initialize git repo silently"""
        if not self.git_dir.exists():
            try:
                subprocess.run(["git", "init"], capture_output=True, cwd=self.repo_path)
                
                # Create .gitignore
                gitignore = self.repo_path / ".gitignore"
                if not gitignore.exists():
                    gitignore.write_text("""
__pycache__/
*.pyc
*.log
forensic_data.db
db_backups/
reports/
*.tmp
""")
                subprocess.run(["git", "add", "."], capture_output=True, cwd=self.repo_path)
                subprocess.run(["git", "commit", "-m", "Initial commit - SmartFileGuard"], 
                              capture_output=True, cwd=self.repo_path)
                logger.info("Git repository initialized")
            except Exception as e:
                logger.error(f"Git init failed: {e}")
                self.enabled = False
    
    def commit_change(self, file_path: str, change_type: str, risk_score: float = 0.0) -> bool:
        """Silently commit a file change"""
        if not self.enabled:
            return False
        
        try:
            rel_path = Path(file_path).relative_to(self.repo_path)
        except ValueError:
            rel_path = Path(file_path)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Simple commit message
        if change_type == "RANSOMWARE_DETECTION":
            msg = f"🚨 RANSOMWARE: {rel_path}"
        elif change_type == "DELETED":
            msg = f"🗑️ Deleted: {rel_path}"
        elif change_type == "CREATED":
            msg = f"📄 Created: {rel_path}"
        else:
            risk = "HIGH" if risk_score >= 0.7 else "MED" if risk_score >= 0.4 else "LOW"
            msg = f"✏️ Modified [{risk}]: {rel_path}"
        
        try:
            subprocess.run(["git", "add", str(rel_path)], capture_output=True, cwd=self.repo_path)
            subprocess.run(["git", "commit", "-m", msg], capture_output=True, cwd=self.repo_path)
            logger.debug(f"Git commit: {rel_path}")
            return True
        except:
            return False
    
    def get_status(self) -> Dict:
        """Get simple Git status for viewing"""
        if not self.enabled:
            return {"enabled": False}
        
        try:
            # Count commits
            result = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                capture_output=True, text=True, cwd=self.repo_path
            )
            commit_count = result.stdout.strip() if result.returncode == 0 else "0"
            
            # Get last commit
            result = subprocess.run(
                ["git", "log", "-1", "--format=%s (%ar)"],
                capture_output=True, text=True, cwd=self.repo_path
            )
            last_commit = result.stdout.strip() if result.stdout else "No commits"
            
            return {
                "enabled": True,
                "initialized": self.git_dir.exists(),
                "total_commits": commit_count,
                "last_commit": last_commit,
                "repo_path": str(self.repo_path)
            }
        except:
            return {"enabled": True, "initialized": False}