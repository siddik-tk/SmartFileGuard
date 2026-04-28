#!/usr/bin/env python3
"""
Command-line client for generating reports from central server
"""

import os
import sys
import json
import argparse
import requests
from datetime import datetime
from pathlib import Path


class ReportClient:
    def __init__(self, server_url: str, api_key: str):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({'X-API-Key': api_key})
    
    def generate_alerts_report(self, format: str = 'csv', node: str = None,
                               severity: str = None, start_date: str = None,
                               end_date: str = None, output_dir: str = None) -> str:
        """Generate alerts report"""
        params = {'format': format, 'download': 'true'}
        if node and node != 'all':
            params['node'] = node
        if severity and severity != 'all':
            params['severity'] = severity
        if start_date:
            params['start_date'] = start_date
        if end_date:
            params['end_date'] = end_date
        
        response = self.session.get(f"{self.server_url}/api/report/alerts", params=params)
        
        if response.status_code == 200:
            return self._save_report(response, 'alerts', format, output_dir)
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    
    def generate_file_history_report(self, format: str = 'csv', node: str = None,
                                      file_path: str = None, start_date: str = None,
                                      end_date: str = None, output_dir: str = None) -> str:
        """Generate file history report"""
        params = {'format': format, 'download': 'true'}
        if node and node != 'all':
            params['node'] = node
        if file_path:
            params['file_path'] = file_path
        if start_date:
            params['start_date'] = start_date
        if end_date:
            params['end_date'] = end_date
        
        response = self.session.get(f"{self.server_url}/api/report/file-history", params=params)
        
        if response.status_code == 200:
            return self._save_report(response, 'file_history', format, output_dir)
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    
    def generate_summary_report(self, format: str = 'json', output_dir: str = None) -> str:
        """Generate summary report"""
        params = {'format': format, 'download': 'true'}
        
        response = self.session.get(f"{self.server_url}/api/report/summary", params=params)
        
        if response.status_code == 200:
            return self._save_report(response, 'summary', format, output_dir)
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    
    def list_reports(self) -> list:
        """List all generated reports"""
        response = self.session.get(f"{self.server_url}/api/report/list")
        
        if response.status_code == 200:
            return response.json().get('reports', [])
        else:
            print(f"Error: {response.status_code}")
            return []
    
    def download_report(self, filename: str, output_dir: str = None) -> str:
        """Download a specific report"""
        response = self.session.get(f"{self.server_url}/api/report/download/{filename}")
        
        if response.status_code == 200:
            return self._save_report(response, filename.split('.')[0], 
                                    filename.split('.')[-1], output_dir, filename)
        else:
            print(f"Error: {response.status_code}")
            return None
    
    def delete_report(self, filename: str) -> bool:
        """Delete a report"""
        response = self.session.delete(f"{self.server_url}/api/report/delete/{filename}")
        return response.status_code == 200
    
    def _save_report(self, response, report_type: str, format: str, 
                     output_dir: str = None, filename: str = None) -> str:
        """Save report to file"""
        if output_dir is None:
            output_dir = 'downloaded_reports'
        
        Path(output_dir).mkdir(exist_ok=True)
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{report_type}_{timestamp}.{format}"
        
        filepath = Path(output_dir) / filename
        
        with open(filepath, 'wb') as f:
            f.write(response.content)
        
        print(f"✅ Report saved to: {filepath}")
        return str(filepath)


def main():
    parser = argparse.ArgumentParser(description='SmartFileGuard Report CLI')
    parser.add_argument('--server', default='http://localhost:5000', 
                       help='Central server URL')
    parser.add_argument('--api-key', required=True, 
                       help='API key for authentication')
    parser.add_argument('--output-dir', default='reports',
                       help='Output directory for reports')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Alerts report
    alerts_parser = subparsers.add_parser('alerts', help='Generate alerts report')
    alerts_parser.add_argument('--format', choices=['csv', 'json', 'excel', 'html'], default='csv')
    alerts_parser.add_argument('--node', help='Filter by node name')
    alerts_parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
    alerts_parser.add_argument('--start-date', help='Start date (YYYY-MM-DD)')
    alerts_parser.add_argument('--end-date', help='End date (YYYY-MM-DD)')
    
    # File history report
    history_parser = subparsers.add_parser('history', help='Generate file history report')
    history_parser.add_argument('--format', choices=['csv', 'json', 'excel', 'html'], default='csv')
    history_parser.add_argument('--node', help='Filter by node name')
    history_parser.add_argument('--file', help='Filter by file path')
    history_parser.add_argument('--start-date', help='Start date (YYYY-MM-DD)')
    history_parser.add_argument('--end-date', help='End date (YYYY-MM-DD)')
    
    # Summary report
    summary_parser = subparsers.add_parser('summary', help='Generate summary report')
    summary_parser.add_argument('--format', choices=['json', 'csv'], default='json')
    
    # List reports
    subparsers.add_parser('list', help='List all reports')
    
    # Download report
    download_parser = subparsers.add_parser('download', help='Download a report')
    download_parser.add_argument('filename', help='Report filename')
    
    # Delete report
    delete_parser = subparsers.add_parser('delete', help='Delete a report')
    delete_parser.add_argument('filename', help='Report filename')
    
    args = parser.parse_args()
    
    client = ReportClient(args.server, args.api_key)
    
    if args.command == 'alerts':
        client.generate_alerts_report(
            format=args.format,
            node=args.node,
            severity=args.severity,
            start_date=args.start_date,
            end_date=args.end_date,
            output_dir=args.output_dir
        )
    
    elif args.command == 'history':
        client.generate_file_history_report(
            format=args.format,
            node=args.node,
            file_path=args.file,
            start_date=args.start_date,
            end_date=args.end_date,
            output_dir=args.output_dir
        )
    
    elif args.command == 'summary':
        client.generate_summary_report(
            format=args.format,
            output_dir=args.output_dir
        )
    
    elif args.command == 'list':
        reports = client.list_reports()
        print(f"\n{'='*80}")
        print(f"Generated Reports ({len(reports)})")
        print(f"{'='*80}")
        for report in reports:
            size = report.get('file_size', 0)
            size_str = f"{size // 1024} KB" if size else "-"
            print(f"  📄 {report['report_name']}")
            print(f"     Type: {report.get('report_type', '-')} | Format: {report.get('format', '-').upper()}")
            print(f"     Generated: {report.get('generated_at', '-')[:19]} | Size: {size_str}")
            print()
    
    elif args.command == 'download':
        client.download_report(args.filename, args.output_dir)
    
    elif args.command == 'delete':
        if client.delete_report(args.filename):
            print(f"✅ Deleted: {args.filename}")
        else:
            print(f"❌ Failed to delete: {args.filename}")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()