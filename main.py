#!/usr/bin/env python3
"""
Smart File Integrity & Forensic System
Main entry point and CLI interface
"""

import os
import sys
import time
import json
import logging
import platform
from datetime import datetime
from collections import deque
from banner import show_banner

from config import SystemConfig
from core import ForensicDatabase, FileMonitor, RealTimeHandler
from collectors import AuditDataCollector
from alerts import EmailAlertSystem
from reporting import ReportGenerator  # NEW IMPORT

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
        self.report_gen = ReportGenerator(self.db)  # NEW
        
        # Real-time monitoring
        self.observer = None
        self.handler = None
        
        # Runtime state
        self.running = False
        self.scan_count = 0
        self.start_time = datetime.now()
        self.realtime_events = deque(maxlen=100)
        
        logger.info("System initialized successfully")

    def add_custom_rule(self):
        """Add custom monitoring rule with risk score"""
        print(f"\n{' ADD CUSTOM RULE ':-^60}")
        
        # Get path
        path = input("Enter file/folder path to monitor: ").strip()
        if not path:
            print("❌ No path provided")
            return
        
        # Convert to absolute path
        abs_path = os.path.abspath(path)
        
        # Check if exists
        if not os.path.exists(abs_path):
            print(f"❌ Path does not exist: {abs_path}")
            return
        
        # Get risk score
        try:
            score_input = input("Enter risk score (0.0 to 1.0, default 0.5): ").strip()
            if score_input:
                score = float(score_input)
                if score < 0 or score > 1:
                    print("❌ Score must be between 0.0 and 1.0")
                    return
            else:
                score = 0.5
        except ValueError:
            print("❌ Invalid score")
            return
        
        # Recursive for folders
        recursive = False
        if os.path.isdir(abs_path):
            rec = input("Monitor folder recursively? (y/N): ").strip().lower()
            recursive = (rec == 'y')
        
        # Load existing rules
        rules_file = 'user_rules.json'
        rules = {'monitor_paths': [], 'risk_scores': {}}
        
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r') as f:
                    rules = json.load(f)
            except:
                pass
        
        # Add new rule
        new_rule = {
            'path': abs_path,
            'score': score,
            'recursive': recursive,
            'type': 'folder' if os.path.isdir(abs_path) else 'file'
        }
        
        # Remove if already exists
        rules['monitor_paths'] = [r for r in rules['monitor_paths'] 
                                if r['path'] != abs_path]
        
        rules['monitor_paths'].append(new_rule)
        
        # For files, also add to risk_scores
        if os.path.isfile(abs_path):
            rules['risk_scores'][abs_path] = score
        
        # Save rules
        with open(rules_file, 'w') as f:
            json.dump(rules, f, indent=4)
        
        path_type = "Folder" if os.path.isdir(abs_path) else "File"
        recursive_str = " (recursive)" if recursive else ""
        print(f"\n✅ Added {path_type}: {abs_path}")
        print(f"   Risk score: {score}{recursive_str}")
        print(f"   Rules saved to: {rules_file}")

    def list_custom_rules(self):
        """List all custom monitoring rules"""
        print(f"\n{' CUSTOM MONITORING RULES ':-^60}")
        
        rules_file = 'user_rules.json'
        if not os.path.exists(rules_file):
            print("No custom rules defined yet.")
            return
        
        try:
            with open(rules_file, 'r') as f:
                rules = json.load(f)
        except:
            print("❌ Error reading rules file")
            return
        
        if not rules.get('monitor_paths'):
            print("No custom rules defined.")
            return
        
        for i, rule in enumerate(rules['monitor_paths'], 1):
            path_type = rule.get('type', 'unknown')
            path = rule['path']
            score = rule['score']
            recursive = rule.get('recursive', False)
            
            print(f"\n{i}. [{path_type.upper()}] {path}")
            print(f"   Risk score: {score}")
            if recursive:
                print(f"   Recursive: Yes")
        
        print(f"\nTotal rules: {len(rules['monitor_paths'])}")

    def remove_custom_rule(self):
        """Remove a custom monitoring rule"""
        self.list_custom_rules()
        
        rules_file = 'user_rules.json'
        if not os.path.exists(rules_file):
            return
        
        try:
            with open(rules_file, 'r') as f:
                rules = json.load(f)
        except:
            print("❌ Error reading rules file")
            return
        
        if not rules.get('monitor_paths'):
            return
        
        path = input("\nEnter path to remove: ").strip()
        if not path:
            return
        
        abs_path = os.path.abspath(path)
        
        # Remove from monitor_paths
        old_count = len(rules['monitor_paths'])
        rules['monitor_paths'] = [r for r in rules['monitor_paths'] 
                                if r['path'] != abs_path]
        
        # Remove from risk_scores
        if abs_path in rules.get('risk_scores', {}):
            del rules['risk_scores'][abs_path]
        
        if len(rules['monitor_paths']) < old_count:
            with open(rules_file, 'w') as f:
                json.dump(rules, f, indent=4)
            print(f"✅ Removed rule for: {abs_path}")
        else:
            print(f"❌ No rule found for: {abs_path}")
    
    def run_single_scan(self):
        """Run a single scan of all monitored paths"""
        logger.info("Running single scan...")
        self.scan_count += 1
        
        files_scanned = 0
        changes_detected = 0
        
        audit_data = self.audit_collector.collect_audit_data('SYSTEM_SCAN', 'SCAN')
        
        # Scan system paths from config
        for path in SystemConfig.MONITOR_PATHS:
            if os.path.exists(path):
                logger.info(f"Scanning system path: {path}")
                if os.path.isfile(path):
                    files_scanned += 1
                    self.file_monitor.scan_file(path, audit_data)
                else:
                    for root, _, files in os.walk(path):
                        files_scanned += len(files)
                        for file in files:
                            file_path = os.path.join(root, file)
                            self.file_monitor.scan_file(file_path, audit_data)
        
        # Scan user-defined custom paths from rules
        rules = self.file_monitor.load_user_rules()
        for item in rules.get('monitor_paths', []):
            custom_path = item['path']
            if os.path.exists(custom_path):
                logger.info(f"Scanning custom path: {custom_path}")
                if os.path.isfile(custom_path):
                    files_scanned += 1
                    self.file_monitor.scan_file(custom_path, audit_data)
                else:
                    recursive = item.get('recursive', False)
                    for root, _, files in os.walk(custom_path):
                        files_scanned += len(files)
                        for file in files:
                            file_path = os.path.join(root, file)
                            self.file_monitor.scan_file(file_path, audit_data)
                        if not recursive:
                            break
        
        logger.info(f"Scan complete: {files_scanned} files checked")
        return {"files_scanned": files_scanned, "changes_detected": changes_detected}
    
    def start_realtime_monitoring(self):
        """Start real-time file monitoring"""
        if not WATCHDOG_AVAILABLE:
            logger.warning("Cannot start real-time monitoring - watchdog not available")
            return False
        
        try:
            from watchdog.observers import Observer
            
            self.handler = RealTimeHandler(self.file_monitor, self.audit_collector)
            self.observer = Observer()
            
            # Monitor system paths from config
            for path in SystemConfig.MONITOR_PATHS:
                if os.path.exists(path):
                    self.observer.schedule(self.handler, path, recursive=True)
                    logger.info(f"Watching system path: {path}")
            
            # Monitor user-defined custom paths
            rules = self.file_monitor.load_user_rules()
            for item in rules.get('monitor_paths', []):
                custom_path = item['path']
                if os.path.exists(custom_path):
                    recursive = item.get('recursive', False)
                    self.observer.schedule(self.handler, custom_path, recursive=recursive)
                    logger.info(f"Watching custom path: {custom_path} (recursive: {recursive})")
            
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
        print(f"System paths: {len(SystemConfig.MONITOR_PATHS)}")
        
        # Count custom paths
        rules = self.file_monitor.load_user_rules()
        custom_count = len(rules.get('monitor_paths', []))
        print(f"Custom paths: {custom_count}")
        print("Press Ctrl+C to stop\n")
        
        # Start real-time monitoring
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
    
    # ==================== NEW REPORTING METHODS ====================
    
    def generate_report_menu(self):
        """Interactive menu for generating reports"""
        while True:
            print(f"\n{' REPORT GENERATION ':-^60}")
            print("1. Generate Alerts Report")
            print("2. Generate File History Report")
            print("3. Generate System Status Report")
            print("4. Generate Hash Verification Report")
            print("5. View Generated Reports")
            print("6. Delete Report")
            print("7. Back to Main Menu")
            print("-" * 60)
            
            choice = input("\nSelect option (1-7): ").strip()
            
            if choice == '1':
                self._generate_alerts_report_interactive()
                input("\nPress Enter to continue...")
            elif choice == '2':
                self._generate_file_history_report_interactive()
                input("\nPress Enter to continue...")
            elif choice == '3':
                self._generate_system_status_report_interactive()
                input("\nPress Enter to continue...")
            elif choice == '4':
                self._generate_hash_verification_report_interactive()
                input("\nPress Enter to continue...")
            elif choice == '5':
                self._view_reports()
                input("\nPress Enter to continue...")
            elif choice == '6':
                self._delete_report()
                input("\nPress Enter to continue...")
            elif choice == '7':
                break
            else:
                print("Invalid choice")

    def _generate_alerts_report_interactive(self):
        """Interactive alerts report generation"""
        print(f"\n{' GENERATE ALERTS REPORT ':-^60}")
        
        # Get date filters
        use_date_filter = input("Filter by date? (y/N): ").strip().lower() == 'y'
        start_date = None
        end_date = None
        
        if use_date_filter:
            start_date = input("Start date (YYYY-MM-DD) [optional]: ").strip()
            end_date = input("End date (YYYY-MM-DD) [optional]: ").strip()
        
        # Get format
        print("\nSelect format:")
        print("1. CSV")
        print("2. JSON")
        print("3. PDF")
        format_choice = input("Choice (1-3): ").strip()
        
        format_map = {'1': 'csv', '2': 'json', '3': 'pdf'}
        if format_choice not in format_map:
            print("❌ Invalid format choice")
            return
        
        report_format = format_map[format_choice]
        
        # Generate report
        print("\nGenerating report...")
        try:
            result = self.report_gen.generate_report(
                report_type='alerts',
                format=report_format,
                start_date=start_date,
                end_date=end_date
            )
            
            print(f"\n✅ Report generated successfully!")
            print(f"   File: {result['filename']}")
            print(f"   Path: {result['filepath']}")
            print(f"   Records: {result['record_count']}")
        except Exception as e:
            print(f"❌ Error generating report: {e}")

    def _generate_file_history_report_interactive(self):
        """Interactive file history report generation"""
        print(f"\n{' GENERATE FILE HISTORY REPORT ':-^60}")
        
        # Get file path
        file_path = input("Enter specific file path (or press Enter for all files): ").strip()
        if file_path and not os.path.exists(file_path):
            print("❌ File not found")
            return
        
        # Get date filters
        use_date_filter = input("Filter by date? (y/N): ").strip().lower() == 'y'
        start_date = None
        end_date = None
        
        if use_date_filter:
            start_date = input("Start date (YYYY-MM-DD) [optional]: ").strip()
            end_date = input("End date (YYYY-MM-DD) [optional]: ").strip()
        
        # Get format
        print("\nSelect format:")
        print("1. CSV")
        print("2. JSON")
        print("3. PDF")
        format_choice = input("Choice (1-3): ").strip()
        
        format_map = {'1': 'csv', '2': 'json', '3': 'pdf'}
        if format_choice not in format_map:
            print("❌ Invalid format choice")
            return
        
        report_format = format_map[format_choice]
        
        # Generate report
        print("\nGenerating report...")
        try:
            result = self.report_gen.generate_report(
                report_type='file_history',
                format=report_format,
                start_date=start_date,
                end_date=end_date,
                file_path=file_path if file_path else None
            )
            
            print(f"\n✅ Report generated successfully!")
            print(f"   File: {result['filename']}")
            print(f"   Path: {result['filepath']}")
            print(f"   Records: {result['record_count']}")
        except Exception as e:
            print(f"❌ Error generating report: {e}")

    def _generate_system_status_report_interactive(self):
        """Interactive system status report generation"""
        print(f"\n{' GENERATE SYSTEM STATUS REPORT ':-^60}")
        
        # Get format
        print("\nSelect format:")
        print("1. CSV")
        print("2. JSON")
        print("3. PDF")
        format_choice = input("Choice (1-3): ").strip()
        
        format_map = {'1': 'csv', '2': 'json', '3': 'pdf'}
        if format_choice not in format_map:
            print("❌ Invalid format choice")
            return
        
        report_format = format_map[format_choice]
        
        # Generate report
        print("\nGenerating report...")
        try:
            result = self.report_gen.generate_report(
                report_type='system_status',
                format=report_format
            )
            
            print(f"\n✅ Report generated successfully!")
            print(f"   File: {result['filename']}")
            print(f"   Path: {result['filepath']}")
        except Exception as e:
            print(f"❌ Error generating report: {e}")

    def _generate_hash_verification_report_interactive(self):
        """Interactive hash verification report generation"""
        print(f"\n{' GENERATE HASH VERIFICATION REPORT ':-^60}")
        
        # Get format
        print("\nSelect format:")
        print("1. CSV")
        print("2. JSON")
        print("3. PDF")
        format_choice = input("Choice (1-3): ").strip()
        
        format_map = {'1': 'csv', '2': 'json', '3': 'pdf'}
        if format_choice not in format_map:
            print("❌ Invalid format choice")
            return
        
        report_format = format_map[format_choice]
        
        # Generate report
        print("\nGenerating report...")
        try:
            result = self.report_gen.generate_report(
                report_type='hash_verification',
                format=report_format
            )
            
            print(f"\n✅ Report generated successfully!")
            print(f"   File: {result['filename']}")
            print(f"   Path: {result['filepath']}")
        except Exception as e:
            print(f"❌ Error generating report: {e}")

    def _view_reports(self):
        """View all generated reports"""
        print(f"\n{' GENERATED REPORTS ':-^60}")
        
        reports = self.report_gen.list_reports()
        
        if not reports:
            print("No reports found.")
            return
        
        for i, report in enumerate(reports, 1):
            size_kb = report['size'] / 1024
            print(f"\n{i}. {report['filename']}")
            print(f"   Format: {report['format']}")
            print(f"   Size: {size_kb:.1f} KB")
            print(f"   Created: {report['created'][:19].replace('T', ' ')}")
        
        print(f"\nTotal reports: {len(reports)}")

    def _delete_report(self):
        """Delete a generated report"""
        reports = self.report_gen.list_reports()
        
        if not reports:
            print("No reports to delete.")
            return
        
        self._view_reports()
        
        try:
            choice = input("\nEnter report number to delete (or 0 to cancel): ").strip()
            if choice == '0':
                return
            
            idx = int(choice) - 1
            if 0 <= idx < len(reports):
                filename = reports[idx]['filename']
                if self.report_gen.delete_report(filename):
                    print(f"✅ Deleted: {filename}")
                else:
                    print(f"❌ Failed to delete: {filename}")
            else:
                print("❌ Invalid report number")
        except ValueError:
            print("❌ Invalid input")
    
    # ==================== MAIN MENU ====================
    
    def interactive_menu(self):
        """Main interactive menu"""
        while True:
            print(f"\n{' ' + SystemConfig.SYSTEM_NAME + ' v' + SystemConfig.VERSION + ' ':=^60}")
            print("1.  Run single scan")
            print("2.  Start continuous monitoring")
            print("3.  View recent alerts")
            print("4.  Check file history")
            print("5.  Verify hash chains")
            print("6.  Send test email")
            print("7.  System status")
            print("8.  Add custom monitoring rule (with risk score)")
            print("9.  List custom rules")
            print("10. Remove custom rule")
            print("11. Generate Reports")  # NEW OPTION
            print("12. Exit")
            print("=" * 60)
            
            choice = input("\nSelect option (1-12): ").strip()
            
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
                self.add_custom_rule()
                input("\nPress Enter to continue...")
                
            elif choice == '9':
                self.list_custom_rules()
                input("\nPress Enter to continue...")
                
            elif choice == '10':
                self.remove_custom_rule()
                input("\nPress Enter to continue...")
                
            elif choice == '11':  # NEW: Reports menu
                self.generate_report_menu()
                input("\nPress Enter to continue...")
                
            elif choice == '12':
                print("\nGoodbye!")
                break
            
            else:
                print("Invalid choice")


def main():
    """Main entry point"""

    show_banner()

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
        elif sys.argv[1] == '--report':
            if len(sys.argv) > 2:
                report_type = sys.argv[2] if len(sys.argv) > 2 else 'alerts'
                report_format = sys.argv[3] if len(sys.argv) > 3 else 'csv'
                
                print(f"Generating {report_type} report in {report_format} format...")
                try:
                    result = system.report_gen.generate_report(
                        report_type=report_type,
                        format=report_format
                    )
                    print(f"✅ Report generated: {result['filepath']}")
                except Exception as e:
                    print(f"❌ Error: {e}")
            else:
                print("Usage: python main.py --report [type] [format]")
                print("  type: alerts, file_history, system_status, hash_verification")
                print("  format: csv, json, pdf")
        elif sys.argv[1] == '--list-reports':
            reports = system.report_gen.list_reports()
            if reports:
                for report in reports:
                    print(f"{report['filename']} ({report['format']}) - {report['created'][:19]}")
            else:
                print("No reports found")
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: python main.py [--daemon|--scan|--test-email|--verify|--report|--list-reports]")
    else:
        # Interactive mode
        system = SmartFileGuard()
        system.interactive_menu()


if __name__ == "__main__":
    main()