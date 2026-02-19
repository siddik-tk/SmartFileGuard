#!/usr/bin/env python3
"""
Smart File Integrity & Forensic System
Main entry point and CLI interface
"""

import os
import sys
import time
import logging
import platform
from datetime import datetime
from collections import deque

from config import SystemConfig
from core import ForensicDatabase, FileMonitor, RealTimeHandler
from collectors import AuditDataCollector
from alerts import EmailAlertSystem

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensic_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Check for watchdog
try:
    from watchdog.observers import Observer
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("watchdog not available - real-time monitoring disabled")


class SmartFileGuard:
    """Main system controller"""
    
    def __init__(self):
        logger.info(f"Starting {SystemConfig.SYSTEM_NAME} v{SystemConfig.VERSION}")
        
        # Create required directories
        os.makedirs('reports', exist_ok=True)
        os.makedirs('db_backups', exist_ok=True)
        
        # Initialize components
        self.db = ForensicDatabase()
        self.audit_collector = AuditDataCollector()
        self.file_monitor = FileMonitor(self.db)
        self.email_alert = EmailAlertSystem()
        
        # Real-time monitoring
        self.observer = None
        self.handler = None
        
        # Runtime state
        self.running = False
        self.scan_count = 0
        self.start_time = datetime.now()
        self.realtime_events = deque(maxlen=100)
        
        logger.info("System initialized successfully")
    
    def run_single_scan(self):
        """Run a single scan of all monitored paths"""
        logger.info("Running single scan...")
        self.scan_count += 1
        
        files_scanned = 0
        changes_detected = 0
        
        audit_data = self.audit_collector.collect_audit_data('SYSTEM_SCAN', 'SCAN')
        
        for path in SystemConfig.MONITOR_PATHS:
            if os.path.exists(path):
                logger.info(f"Scanning: {path}")
                
                # Count files before scan
                if os.path.isfile(path):
                    files_scanned += 1
                    self.file_monitor.scan_file(path, audit_data)
                else:
                    for root, _, files in os.walk(path):
                        files_scanned += len(files)
                        for file in files:
                            file_path = os.path.join(root, file)
                            self.file_monitor.scan_file(file_path, audit_data)
        
        logger.info(f"Scan complete: {files_scanned} files checked")
        return {"files_scanned": files_scanned, "changes_detected": changes_detected}
    
    def start_realtime_monitoring(self):
        """Start real-time file monitoring"""
        if not WATCHDOG_AVAILABLE:
            logger.warning("Cannot start real-time monitoring - watchdog not available")
            return False
        
        try:
            self.handler = RealTimeHandler(self.file_monitor, self.audit_collector)
            self.observer = Observer()
            
            for path in SystemConfig.MONITOR_PATHS:
                if os.path.exists(path):
                    self.observer.schedule(self.handler, path, recursive=True)
                    logger.info(f"Watching: {path}")
            
            self.observer.start()
            logger.info("Real-time monitoring started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start real-time monitoring: {e}")
            return False
    
    def stop_realtime_monitoring(self):
        """Stop real-time monitoring"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logger.info("Real-time monitoring stopped")
        
        if self.handler:
            self.handler.stop()
    
    def run_continuous(self):
        """Run continuous monitoring"""
        self.running = True
        
        print(f"\n{' CONTINUOUS MONITORING ':=^60}")
        print(f"Monitoring {len(SystemConfig.MONITOR_PATHS)} paths")
        print("Press Ctrl+C to stop\n")
        
        # Start real-time monitoring if available
        realtime_active = False
        if SystemConfig.REALTIME_MONITORING:
            realtime_active = self.start_realtime_monitoring()
        
        try:
            while self.running:
                scan_start = time.time()
                
                # Run periodic scan
                self.run_single_scan()
                
                # Show status
                self._display_status(realtime_active)
                
                # Sleep until next scan
                scan_duration = time.time() - scan_start
                sleep_time = max(1, SystemConfig.FILE_SCAN_INTERVAL - scan_duration)
                time.sleep(sleep_time)
                
        except KeyboardInterrupt:
            logger.info("Shutdown requested")
        finally:
            self.stop_realtime_monitoring()
            logger.info("System stopped")
    
    def _display_status(self, realtime_active: bool = False):
        """Display system status"""
        runtime = datetime.now() - self.start_time
        hours, remainder = divmod(runtime.total_seconds(), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        print(f"\n{' STATUS ':-^60}")
        print(f"Runtime: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
        print(f"Scans: {self.scan_count}")
        print(f"Tracked Files: {len(self.file_monitor.file_cache)}")
        print(f"Real-time: {'ACTIVE' if realtime_active else 'DISABLED'}")
        print(f"Email Alerts: {'ENABLED' if SystemConfig.ALERT_EMAIL else 'DISABLED'}")
        print('-' * 60)
    
    def interactive_menu(self):
        """Interactive menu interface"""
        while True:
            print(f"\n{' ' + SystemConfig.SYSTEM_NAME + ' v' + SystemConfig.VERSION + ' ':=^60}")
            print("1. Run single scan")
            print("2. Start continuous monitoring")
            print("3. View recent alerts")
            print("4. Check file history")
            print("5. Verify hash chains")
            print("6. Send test email")
            print("7. System status")
            print("8. Exit")
            print("=" * 60)
            
            choice = input("\nSelect option (1-8): ").strip()
            
            if choice == '1':
                self.run_single_scan()
                input("\nPress Enter to continue...")
                
            elif choice == '2':
                self.run_continuous()
                
            elif choice == '3':
                alerts = self.db.get_recent_alerts()
                if alerts:
                    print(f"\n{' Recent Alerts ':-^60}")
                    for alert in alerts:
                        print(f"\nTime: {alert['alert_time']}")
                        print(f"Type: {alert['alert_type']}")
                        print(f"Severity: {alert['severity']}")
                        print(f"File: {os.path.basename(alert['file_path'])}")
                        print(f"Email Sent: {'Yes' if alert.get('email_sent') else 'No'}")
                else:
                    print("\nNo recent alerts")
                input("\nPress Enter to continue...")
                
            elif choice == '4':
                file_path = input("Enter file path: ").strip()
                if file_path and os.path.exists(file_path):
                    history = self.db.get_file_history(file_path)
                    if history:
                        print(f"\n{' File History ':-^60}")
                        for event in history:
                            print(f"\nTime: {event['event_time']}")
                            print(f"Change: {event['change_type']}")
                            print(f"User: {event.get('user_name', 'Unknown')}")
                            print(f"Process: {event.get('process_name', 'Unknown')}")
                            print(f"Risk: {event.get('risk_score', 0):.1%}")
                    else:
                        print("No history found")
                else:
                    print("File not found")
                input("\nPress Enter to continue...")
                
            elif choice == '5':
                print("\nVerifying hash chains...")
                results = self.file_monitor.verify_hash_chains()
                print(f"\nVerified: {results['verified']}")
                print(f"Tampered: {results['tampered']}")
                print(f"Errors: {results['errors']}")
                input("\nPress Enter to continue...")
                
            elif choice == '6':
                print("\nSending test email...")
                success = self.email_alert.send_test_alert()
                if success:
                    print("✓ Test email sent")
                else:
                    print("✗ Failed to send email")
                input("\nPress Enter to continue...")
                
            elif choice == '7':
                self._display_status()
                input("\nPress Enter to continue...")
                
            elif choice == '8':
                print("\nGoodbye!")
                break
            
            else:
                print("Invalid choice")


def main():
    """Main entry point"""
    print(f"\n{' ' + SystemConfig.SYSTEM_NAME + ' v' + SystemConfig.VERSION + ' ':=^60}")
    print(f"Platform: {platform.system()} {platform.release()}")
    print("=" * 60)
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        system = SmartFileGuard()
        
        if sys.argv[1] == '--daemon':
            system.run_continuous()
        elif sys.argv[1] == '--scan':
            system.run_single_scan()
        elif sys.argv[1] == '--test-email':
            system.email_alert.send_test_alert()
        elif sys.argv[1] == '--verify':
            results = system.file_monitor.verify_hash_chains()
            print(f"Hash chain verification: {results}")
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: python main.py [--daemon|--scan|--test-email|--verify]")
    else:
        # Interactive mode
        system = SmartFileGuard()
        system.interactive_menu()


if __name__ == "__main__":
    main()