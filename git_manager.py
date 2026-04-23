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
        try:
            result = subprocess.run(
                ["git", "--version"], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def _ensure_repo_initialized(self):
        if not self.git_dir.exists():
            try:
                subprocess.run(
                    ["git", "init"], 
                    capture_output=True, 
                    cwd=self.repo_path,
                    timeout=10
                )
                logger.info("Git repository initialized")
            except:
                self.enabled = False
                return
        
        try:
            subprocess.run(
                ["git", "config", "user.email", "smartfileguard@localhost"],
                capture_output=True,
                cwd=self.repo_path
            )
            subprocess.run(
                ["git", "config", "user.name", "SmartFileGuard"],
                capture_output=True,
                cwd=self.repo_path
            )
        except:
            pass
    
    def commit_change(self, file_path: str, change_type: str, risk_score: float = 0.0) -> bool:
        if not self.enabled:
            return False
        
        try:
            abs_path = Path(file_path).absolute()
            
            if change_type != "DELETED" and not abs_path.exists():
                return False
            
            try:
                rel_path = abs_path.relative_to(self.repo_path)
            except ValueError:
                return False
            
            # NO EMOJIS - Plain text only
            if change_type == "RANSOMWARE_DETECTION":
                msg = f"[RANSOMWARE] {rel_path}"
            elif change_type == "DELETED":
                msg = f"[DELETED] {rel_path}"
            elif change_type == "CREATED":
                msg = f"[CREATED] {rel_path}"
            elif change_type == "MODIFIED":
                risk = "HIGH" if risk_score >= 0.7 else "MED" if risk_score >= 0.4 else "LOW"
                msg = f"[MODIFIED {risk}] {rel_path}"
            else:
                msg = f"[{change_type}] {rel_path}"
            
            subprocess.run(
                ["git", "add", str(rel_path)],
                capture_output=True,
                cwd=self.repo_path,
                timeout=10
            )
            
            result = subprocess.run(
                ["git", "commit", "-m", msg],
                capture_output=True,
                text=True,
                cwd=self.repo_path,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"Git commit: {rel_path}")
                return True
            return False
                
        except Exception as e:
            logger.debug(f"Git commit error: {e}")
            return False
    
    def get_status(self) -> Dict:
        if not self.enabled:
            return {"enabled": False, "initialized": False}
        
        try:
            result = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                capture_output=True, 
                text=True, 
                cwd=self.repo_path,
                timeout=10
            )
            commit_count = result.stdout.strip() if result.returncode == 0 else "0"
            
            result = subprocess.run(
                ["git", "log", "-1", "--format=%s"],
                capture_output=True, 
                text=True, 
                cwd=self.repo_path,
                timeout=10
            )
            last_commit = result.stdout.strip() if result.stdout and result.returncode == 0 else "No commits"
            
            return {
                "enabled": True,
                "initialized": self.git_dir.exists(),
                "total_commits": commit_count,
                "last_commit": last_commit[:50] if last_commit else "No commits",
                "repo_path": str(self.repo_path)
            }
        except:
            return {"enabled": True, "initialized": self.git_dir.exists(), "error": True}