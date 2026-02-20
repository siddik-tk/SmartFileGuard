#!/usr/bin/env python3
"""
Reporting module for Smart File Integrity & Forensic System
Handles CSV, JSON, and well-structured PDF report generation
"""

import os
import csv
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    logging.warning("pandas not available - advanced CSV formatting disabled")

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, 
        Spacer, Image, PageBreak, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.lib.colors import Color, HexColor
    from reportlab.pdfgen import canvas
    from reportlab.graphics.shapes import Drawing, Line
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logging.warning("reportlab not available - PDF generation disabled")

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate well-structured reports in various formats"""
    
    def __init__(self, db):
        self.db = db
        self.report_dir = 'reports'
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Color scheme for PDF reports
        self.colors = {
            'primary': HexColor('#2E4053'),      # Dark blue-gray
            'secondary': HexColor('#2874A6'),    # Medium blue
            'accent': HexColor('#F39C12'),        # Orange
            'success': HexColor('#28B463'),       # Green
            'warning': HexColor('#F39C12'),       # Orange
            'danger': HexColor('#CB4335'),        # Red
            'light_bg': HexColor('#F8F9F9'),      # Light gray
            'header_bg': HexColor('#34495E'),     # Dark blue
            'border': HexColor('#D5D8DC'),        # Light gray
        }
        
    def generate_report(self, report_type: str, format: str, 
                       start_date: Optional[str] = None, 
                       end_date: Optional[str] = None,
                       file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a report based on type and format
        
        Args:
            report_type: 'alerts', 'file_history', 'system_status', 'hash_verification'
            format: 'csv', 'json', 'pdf'
            start_date: Optional start date filter (YYYY-MM-DD)
            end_date: Optional end date filter (YYYY-MM-DD)
            file_path: Optional specific file path for file_history report
        
        Returns:
            Dictionary with report metadata
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_type}_{timestamp}.{format}"
        filepath = os.path.join(self.report_dir, filename)
        
        # Collect data based on report type
        if report_type == 'alerts':
            data = self._collect_alerts_data(start_date, end_date)
        elif report_type == 'file_history':
            data = self._collect_file_history_data(file_path, start_date, end_date)
        elif report_type == 'system_status':
            data = self._collect_system_status_data()
        elif report_type == 'hash_verification':
            data = self._collect_hash_verification_data()
        else:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # Generate report in requested format
        if format == 'csv':
            result = self._generate_csv(data, filepath, report_type)
        elif format == 'json':
            result = self._generate_json(data, filepath, report_type)
        elif format == 'pdf':
            result = self._generate_structured_pdf(data, filepath, report_type)
        else:
            raise ValueError(f"Unknown format: {format}")
        
        return {
            'filename': filename,
            'filepath': filepath,
            'format': format,
            'report_type': report_type,
            'record_count': len(data.get('records', [])),
            'generated_at': datetime.now().isoformat()
        }
    
    def _collect_alerts_data(self, start_date: Optional[str] = None, 
                            end_date: Optional[str] = None) -> Dict[str, Any]:
        """Collect alerts data for reporting"""
        alerts = self.db.get_recent_alerts(limit=1000)
        
        # Filter by date if provided
        if start_date or end_date:
            filtered_alerts = []
            for alert in alerts:
                alert_date = alert['alert_time'].split()[0]
                if start_date and alert_date < start_date:
                    continue
                if end_date and alert_date > end_date:
                    continue
                filtered_alerts.append(alert)
            alerts = filtered_alerts
        
        # Calculate statistics
        severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        type_counts = {}
        hourly_distribution = {str(i).zfill(2): 0 for i in range(24)}
        
        for alert in alerts:
            severity = alert['severity']
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts[severity] = 1
                
            alert_type = alert['alert_type']
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
            
            # Hourly distribution
            try:
                hour = alert['alert_time'].split()[1].split(':')[0]
                hourly_distribution[hour] = hourly_distribution.get(hour, 0) + 1
            except:
                pass
        
        # Get top files with most alerts
        file_alerts = {}
        for alert in alerts:
            file_path = alert.get('file_path', 'Unknown')
            file_alerts[file_path] = file_alerts.get(file_path, 0) + 1
        
        top_files = sorted(file_alerts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'summary': {
                'total_alerts': len(alerts),
                'severity_breakdown': severity_counts,
                'type_breakdown': type_counts,
                'hourly_distribution': hourly_distribution,
                'top_files': top_files,
                'date_range': f"{start_date or 'ALL'} to {end_date or 'ALL'}"
            },
            'records': alerts
        }
    
    def _collect_file_history_data(self, file_path: Optional[str] = None,
                                  start_date: Optional[str] = None,
                                  end_date: Optional[str] = None) -> Dict[str, Any]:
        """Collect file history data for reporting"""
        if file_path:
            # Get history for specific file
            history = self.db.get_file_history(file_path)
            records = history
        else:
            # Get all file history
            records = []
            alerts = self.db.get_recent_alerts(limit=500)
            for alert in alerts:
                if alert.get('file_path'):
                    records.append({
                        'file_path': alert['file_path'],
                        'event_time': alert['alert_time'],
                        'change_type': alert['alert_type'],
                        'severity': alert['severity'],
                        'risk_score': alert.get('risk_score', 0),
                        'user': alert.get('user_name', 'Unknown'),
                        'details': alert.get('details', '')
                    })
        
        # Filter by date
        if start_date or end_date:
            filtered = []
            for record in records:
                record_date = record['event_time'].split()[0]
                if start_date and record_date < start_date:
                    continue
                if end_date and record_date > end_date:
                    continue
                filtered.append(record)
            records = filtered
        
        # Get unique files
        unique_files = set()
        file_stats = {}
        for record in records:
            file = record.get('file_path', 'Unknown')
            unique_files.add(file)
            
            if file not in file_stats:
                file_stats[file] = {
                    'total_events': 0,
                    'high_risk_events': 0,
                    'last_event': record['event_time']
                }
            
            file_stats[file]['total_events'] += 1
            if record.get('risk_score', 0) > 0.7:
                file_stats[file]['high_risk_events'] += 1
            file_stats[file]['last_event'] = max(
                file_stats[file]['last_event'], 
                record['event_time']
            )
        
        return {
            'summary': {
                'total_events': len(records),
                'unique_files': len(unique_files),
                'specific_file': file_path or 'ALL FILES',
                'date_range': f"{start_date or 'ALL'} to {end_date or 'ALL'}",
                'file_statistics': file_stats
            },
            'records': records
        }
    
    def _collect_system_status_data(self) -> Dict[str, Any]:
        """Collect system status data for reporting"""
        from config import SystemConfig
        
        # Get database stats
        db_stats = {}
        if hasattr(self.db, 'get_stats'):
            db_stats = self.db.get_stats()
        
        # Get file monitor stats
        file_count = 0
        if hasattr(self.db, 'get_all_tracked_files'):
            file_count = len(self.db.get_all_tracked_files())
        
        # Get recent alerts count
        recent_alerts = self.db.get_recent_alerts(limit=10)
        
        # System health metrics - with safe attribute access
        system_health = {
            'database_status': 'Healthy' if db_stats else 'Unknown',
            'monitoring_status': 'Active' if file_count > 0 else 'Inactive',
            'last_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_scans': getattr(self.db, 'scan_count', 0) if hasattr(self.db, 'scan_count') else 0
        }
        
        # Safely get configuration values with defaults
        hash_algorithm = getattr(SystemConfig, 'HASH_ALGORITHM', 'sha256')
        max_history_days = getattr(SystemConfig, 'MAX_HISTORY_DAYS', 30)
        alert_email = getattr(SystemConfig, 'ALERT_EMAIL', None)
        monitored_paths = getattr(SystemConfig, 'MONITOR_PATHS', [])
        system_name = getattr(SystemConfig, 'SYSTEM_NAME', 'SmartFileGuard')
        version = getattr(SystemConfig, 'VERSION', '1.0.0')
        scan_interval = getattr(SystemConfig, 'FILE_SCAN_INTERVAL', 3600)
        
        return {
            'summary': {
                'system_name': system_name,
                'version': version,
                'tracked_files': file_count,
                'total_alerts': db_stats.get('total_alerts', 0),
                'database_size': db_stats.get('db_size', 'Unknown'),
                'monitoring_paths': len(monitored_paths),
                'email_alerts': 'ENABLED' if alert_email else 'DISABLED',
                'system_health': system_health
            },
            'recent_alerts': recent_alerts,
            'configuration': {
                'scan_interval': f"{scan_interval} seconds",
                'hash_algorithm': hash_algorithm,
                'alert_email': alert_email or 'Not configured',
                'monitored_paths': monitored_paths,
                'max_history_days': max_history_days
            }
        }
    
    def _collect_hash_verification_data(self) -> Dict[str, Any]:
        """Collect hash verification data for reporting"""
        from core import FileMonitor
        
        # Create temporary file monitor to verify chains
        file_monitor = FileMonitor(self.db)
        verification_results = file_monitor.verify_hash_chains()
        
        # Get details of tampered files
        tampered_files = []
        if hasattr(self.db, 'get_tampered_files'):
            tampered_files = self.db.get_tampered_files()
        
        # Calculate integrity score
        total_files = verification_results['verified'] + verification_results['tampered']
        integrity_score = (verification_results['verified'] / total_files * 100) if total_files > 0 else 100
        
        return {
            'summary': {
                'verified': verification_results['verified'],
                'tampered': verification_results['tampered'],
                'errors': verification_results['errors'],
                'total_files': total_files,
                'integrity_score': round(integrity_score, 2),
                'verification_status': 'PASSED' if verification_results['tampered'] == 0 else 'FAILED'
            },
            'tampered_files': tampered_files,
            'verification_time': datetime.now().isoformat(),
            'recommendations': self._generate_recommendations(verification_results)
        }
    
    def _generate_recommendations(self, verification_results: Dict) -> List[str]:
        """Generate recommendations based on verification results"""
        recommendations = []
        
        if verification_results['tampered'] > 0:
            recommendations.append("⚠️ IMMEDIATE ACTION REQUIRED: Tampered files detected")
            recommendations.append("   - Review all tampered files listed in this report")
            recommendations.append("   - Check system logs for unauthorized access")
            recommendations.append("   - Restore files from verified backups")
            recommendations.append("   - Run full system antivirus scan")
        
        if verification_results['errors'] > 0:
            recommendations.append("📋 Maintenance Required: Some files could not be verified")
            recommendations.append("   - Check file permissions for affected paths")
            recommendations.append("   - Verify disk integrity for storage locations")
        
        if verification_results['verified'] == 0:
            recommendations.append("🆕 New System: No files have been verified yet")
            recommendations.append("   - Run initial baseline scan")
            recommendations.append("   - Configure monitoring rules for critical paths")
        else:
            recommendations.append("✅ Regular Maintenance:")
            recommendations.append("   - Schedule regular integrity scans")
            recommendations.append("   - Keep backup copies of critical files")
            recommendations.append("   - Monitor for unusual file access patterns")
        
        return recommendations
    
    def _generate_csv(self, data: Dict[str, Any], filepath: str, 
                     report_type: str) -> bool:
        """Generate CSV report"""
        try:
            records = data.get('records', [])
            
            if not records:
                if report_type == 'alerts':
                    fieldnames = ['alert_time', 'alert_type', 'severity', 'file_path', 'details']
                elif report_type == 'file_history':
                    fieldnames = ['event_time', 'file_path', 'change_type', 'severity', 'risk_score', 'user', 'details']
                else:
                    fieldnames = ['No data available']
            else:
                fieldnames = records[0].keys()
            
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                # Write summary as comments
                csvfile.write(f"# Report Type: {report_type.upper()}\n")
                csvfile.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                for key, value in data.get('summary', {}).items():
                    if key not in ['hourly_distribution', 'top_files', 'file_statistics']:
                        csvfile.write(f"# {key}: {value}\n")
                csvfile.write("#" + "="*80 + "\n")
                
                # Write data
                writer.writeheader()
                writer.writerows(records)
            
            logger.info(f"CSV report generated: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            return False
    
    def _generate_json(self, data: Dict[str, Any], filepath: str, 
                      report_type: str) -> bool:
        """Generate JSON report"""
        try:
            report_data = {
                'report_type': report_type,
                'generated_at': datetime.now().isoformat(),
                'generator': 'SmartFileGuard',
                'version': '2.1.0',
                'summary': data.get('summary', {}),
                'data': data.get('records', [])
            }
            
            with open(filepath, 'w', encoding='utf-8') as jsonfile:
                json.dump(report_data, jsonfile, indent=2, default=str)
            
            logger.info(f"JSON report generated: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return False
    
    def _generate_structured_pdf(self, data: Dict[str, Any], filepath: str, 
                                report_type: str) -> bool:
        """Generate a well-structured PDF report"""
        if not REPORTLAB_AVAILABLE:
            logger.error("ReportLab not available - cannot generate PDF")
            return False
        
        try:
            # Create PDF document with proper formatting
            doc = SimpleDocTemplate(
                filepath,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72,
                title=f"SmartFileGuard {report_type.title()} Report",
                author="SmartFileGuard System"
            )
            
            story = []
            
            # Add report header
            story.extend(self._create_report_header(report_type))
            
            # Add executive summary
            story.extend(self._create_executive_summary(data, report_type))
            story.append(PageBreak())
            
            # Add detailed sections based on report type
            if report_type == 'alerts':
                story.extend(self._create_alerts_section(data))
            elif report_type == 'file_history':
                story.extend(self._create_file_history_section(data))
            elif report_type == 'system_status':
                story.extend(self._create_system_status_section(data))
            elif report_type == 'hash_verification':
                story.extend(self._create_hash_verification_section(data))
            
            # Add recommendations if available
            if 'recommendations' in data:
                story.extend(self._create_recommendations_section(data['recommendations']))
            
            # Add footer with page numbers
            story.append(Spacer(1, 0.5*inch))
            
            # Build PDF
            doc.build(story, onFirstPage=self._add_page_number, 
                     onLaterPages=self._add_page_number)
            
            logger.info(f"Structured PDF report generated: {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _create_report_header(self, report_type: str) -> List:
        """Create report header with title and metadata"""
        elements = []
        from config import SystemConfig
        
        system_name = getattr(SystemConfig, 'SYSTEM_NAME', 'SmartFileGuard')
        
        # Main title
        title_style = ParagraphStyle(
            name='ReportTitle',
            parent=getSampleStyleSheet()['Heading1'],
            fontSize=24,
            textColor=self.colors['primary'],
            alignment=TA_CENTER,
            spaceAfter=30,
            fontName='Helvetica-Bold'
        )
        
        title = Paragraph(
            f"{system_name}",
            title_style
        )
        elements.append(title)
        
        # Report type subtitle
        subtitle_style = ParagraphStyle(
            name='SectionHeader',
            parent=getSampleStyleSheet()['Heading2'],
            fontSize=16,
            textColor=self.colors['secondary'],
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        )
        
        subtitle = Paragraph(
            f"{report_type.replace('_', ' ').title()} Report",
            subtitle_style
        )
        elements.append(subtitle)
        
        # Date and time
        date_str = datetime.now().strftime("%B %d, %Y at %H:%M:%S")
        date_info = Paragraph(
            f"Generated: {date_str}",
            getSampleStyleSheet()['Normal']
        )
        elements.append(date_info)
        
        # Horizontal line
        elements.append(self._create_horizontal_line())
        elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_executive_summary(self, data: Dict, report_type: str) -> List:
        """Create executive summary section"""
        elements = []
        
        # Section header
        section_style = ParagraphStyle(
            name='SectionHeader',
            parent=getSampleStyleSheet()['Heading2'],
            fontSize=16,
            textColor=self.colors['secondary'],
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        )
        
        elements.append(Paragraph("Executive Summary", section_style))
        
        # Summary data
        summary = data.get('summary', {})
        
        # Create summary table
        summary_data = []
        
        if report_type == 'alerts':
            severity_breakdown = summary.get('severity_breakdown', {})
            summary_data.extend([
                ["Total Alerts", str(summary.get('total_alerts', 0))],
                ["Critical Alerts", str(severity_breakdown.get('CRITICAL', 0))],
                ["High Alerts", str(severity_breakdown.get('HIGH', 0))],
                ["Medium Alerts", str(severity_breakdown.get('MEDIUM', 0))],
                ["Low Alerts", str(severity_breakdown.get('LOW', 0))],
                ["Unique Alert Types", str(len(summary.get('type_breakdown', {})))],
            ])
        elif report_type == 'file_history':
            summary_data.extend([
                ["Total Events", str(summary.get('total_events', 0))],
                ["Unique Files", str(summary.get('unique_files', 0))],
                ["Specific File", summary.get('specific_file', 'ALL')],
                ["Date Range", summary.get('date_range', 'ALL')],
            ])
        elif report_type == 'system_status':
            system_health = summary.get('system_health', {})
            summary_data.extend([
                ["Tracked Files", str(summary.get('tracked_files', 0))],
                ["Total Alerts", str(summary.get('total_alerts', 0))],
                ["Monitoring Paths", str(summary.get('monitoring_paths', 0))],
                ["Email Alerts", summary.get('email_alerts', 'DISABLED')],
                ["System Health", system_health.get('monitoring_status', 'Unknown')],
            ])
        elif report_type == 'hash_verification':
            integrity_score = summary.get('integrity_score', 0)
            
            summary_data.extend([
                ["Integrity Score", f"{integrity_score}%"],
                ["Verified Files", str(summary.get('verified', 0))],
                ["Tampered Files", str(summary.get('tampered', 0))],
                ["Verification Status", summary.get('verification_status', 'UNKNOWN')],
            ])
        
        if summary_data:
            # Create table
            table = Table(summary_data, colWidths=[2.5*inch, 2.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), self.colors['light_bg']),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
            ]))
            
            elements.append(table)
        else:
            elements.append(Paragraph("No summary data available", getSampleStyleSheet()['Normal']))
        
        elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_alerts_section(self, data: Dict) -> List:
        """Create detailed alerts section"""
        elements = []
        
        # Section header
        section_style = ParagraphStyle(
            name='SectionHeader',
            parent=getSampleStyleSheet()['Heading2'],
            fontSize=16,
            textColor=self.colors['secondary'],
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        )
        
        elements.append(Paragraph("Alert Details", section_style))
        
        # Severity breakdown
        sub_style = ParagraphStyle(
            name='SubSectionHeader',
            parent=getSampleStyleSheet()['Heading3'],
            fontSize=14,
            textColor=self.colors['primary'],
            spaceAfter=8,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )
        
        elements.append(Paragraph("Severity Distribution", sub_style))
        
        severity_data = [["Severity", "Count"]]
        severity_counts = data['summary'].get('severity_breakdown', {})
        for severity, count in severity_counts.items():
            severity_data.append([severity, str(count)])
        
        if len(severity_data) > 1:
            severity_table = Table(severity_data, colWidths=[2*inch, 1*inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.colors['secondary']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_bg']),
                ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
            ]))
            
            elements.append(severity_table)
            elements.append(Spacer(1, 0.2*inch))
        
        # Alert type breakdown
        elements.append(Paragraph("Alert Type Distribution", sub_style))
        
        type_data = [["Alert Type", "Count"]]
        type_counts = data['summary'].get('type_breakdown', {})
        for alert_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            type_data.append([alert_type, str(count)])
        
        if len(type_data) > 1:
            type_table = Table(type_data, colWidths=[2.5*inch, 1*inch])
            type_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.colors['secondary']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_bg']),
                ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
            ]))
            
            elements.append(type_table)
            elements.append(Spacer(1, 0.2*inch))
        
        # Top files with alerts
        elements.append(Paragraph("Top Files with Alerts", sub_style))
        
        top_files = data['summary'].get('top_files', [])
        if top_files:
            file_data = [["File Path", "Alert Count"]]
            for file_path, count in top_files:
                # Truncate long file paths
                short_path = file_path if len(file_path) < 40 else "..." + file_path[-37:]
                file_data.append([short_path, str(count)])
            
            file_table = Table(file_data, colWidths=[3.5*inch, 1*inch])
            file_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.colors['secondary']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_bg']),
                ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
            ]))
            
            elements.append(file_table)
        else:
            elements.append(Paragraph("No file alert data available", getSampleStyleSheet()['Normal']))
        
        return elements
    
    def _create_file_history_section(self, data: Dict) -> List:
        """Create detailed file history section"""
        elements = []
        
        # Section header
        section_style = ParagraphStyle(
            name='SectionHeader',
            parent=getSampleStyleSheet()['Heading2'],
            fontSize=16,
            textColor=self.colors['secondary'],
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        )
        
        elements.append(Paragraph("File Activity Details", section_style))
        
        # File statistics
        sub_style = ParagraphStyle(
            name='SubSectionHeader',
            parent=getSampleStyleSheet()['Heading3'],
            fontSize=14,
            textColor=self.colors['primary'],
            spaceAfter=8,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )
        
        file_stats = data['summary'].get('file_statistics', {})
        
        if file_stats:
            elements.append(Paragraph("File Activity Summary", sub_style))
            
            stats_data = [["File", "Total Events", "High Risk", "Last Event"]]
            
            for file_path, stats in list(file_stats.items())[:15]:  # Show top 15 files
                short_path = file_path if len(file_path) < 35 else "..." + file_path[-32:]
                stats_data.append([
                    short_path,
                    str(stats['total_events']),
                    str(stats['high_risk_events']),
                    stats['last_event'][:16]  # Show only date and hour
                ])
            
            if len(stats_data) > 1:
                stats_table = Table(stats_data, colWidths=[2.2*inch, 0.8*inch, 0.8*inch, 1.2*inch])
                stats_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.colors['secondary']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (2, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_bg']),
                    ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
                ]))
                
                elements.append(stats_table)
                elements.append(Spacer(1, 0.2*inch))
        
        # Recent file events
        elements.append(Paragraph("Recent File Events", sub_style))
        
        records = data.get('records', [])[:20]  # Show last 20 events
        
        if records:
            event_data = [["Time", "File", "Change Type", "Risk"]]
            
            for record in records[:15]:  # Show only 15 events in PDF
                file_path = record.get('file_path', 'Unknown')
                short_path = os.path.basename(file_path) if file_path else 'Unknown'
                if len(short_path) > 20:
                    short_path = short_path[:17] + "..."
                
                risk_score = record.get('risk_score', 0)
                risk_str = f"{risk_score:.0%}" if isinstance(risk_score, (int, float)) else str(risk_score)
                
                event_data.append([
                    record.get('event_time', '')[:16],
                    short_path,
                    record.get('change_type', '')[:15],
                    risk_str
                ])
            
            if len(event_data) > 1:
                event_table = Table(event_data, colWidths=[1.2*inch, 1.8*inch, 1.2*inch, 0.8*inch])
                event_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.colors['secondary']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('ALIGN', (3, 0), (3, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_bg']),
                    ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
                ]))
                
                elements.append(event_table)
                
                if len(records) > 15:
                    elements.append(Paragraph(
                        f"* Showing last 15 of {len(records)} events", 
                        getSampleStyleSheet()['Italic']
                    ))
        else:
            elements.append(Paragraph("No file events found", getSampleStyleSheet()['Normal']))
        
        return elements
    
    def _create_system_status_section(self, data: Dict) -> List:
        """Create detailed system status section"""
        elements = []
        
        # Section header
        section_style = ParagraphStyle(
            name='SectionHeader',
            parent=getSampleStyleSheet()['Heading2'],
            fontSize=16,
            textColor=self.colors['secondary'],
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        )
        
        elements.append(Paragraph("System Status Details", section_style))
        
        # System health
        sub_style = ParagraphStyle(
            name='SubSectionHeader',
            parent=getSampleStyleSheet()['Heading3'],
            fontSize=14,
            textColor=self.colors['primary'],
            spaceAfter=8,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )
        
        elements.append(Paragraph("System Health", sub_style))
        
        # Safely get health data with defaults
        summary = data.get('summary', {})
        health = summary.get('system_health', {})
        
        health_data = [
            ["Component", "Status"],
            ["Database", health.get('database_status', 'Unknown')],
            ["Monitoring", health.get('monitoring_status', 'Unknown')],
            ["Last Scan", health.get('last_scan', 'Unknown')],
            ["Total Scans", str(health.get('total_scans', 0))]
        ]
        
        health_table = Table(health_data, colWidths=[2*inch, 3*inch])
        health_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['secondary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_bg']),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
        ]))
        
        elements.append(health_table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Configuration details
        elements.append(Paragraph("System Configuration", sub_style))
        
        config = data.get('configuration', {})
        config_data = []
        for key, value in config.items():
            if key != 'monitored_paths':
                # Format key for display
                display_key = key.replace('_', ' ').title()
                config_data.append([display_key, str(value)])
        
        # Add monitored paths
        if 'monitored_paths' in config:
            paths = config['monitored_paths']
            if paths:
                paths_str = "\n".join(str(p) for p in paths[:5])  # Show first 5 paths
                if len(paths) > 5:
                    paths_str += f"\n... and {len(paths) - 5} more"
            else:
                paths_str = "No paths configured"
            config_data.append(['Monitored Paths', paths_str])
        
        if config_data:
            config_table = Table(config_data, colWidths=[2*inch, 3*inch])
            config_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), self.colors['light_bg']),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('VALIGN', (0, -1), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
            ]))
            
            elements.append(config_table)
        else:
            elements.append(Paragraph("No configuration data available", getSampleStyleSheet()['Normal']))
        
        elements.append(Spacer(1, 0.2*inch))
        
        # Recent alerts
        elements.append(Paragraph("Recent Alerts", sub_style))
        
        recent_alerts = data.get('recent_alerts', [])
        if recent_alerts:
            alert_data = [["Time", "Type", "Severity", "File"]]
            
            for alert in recent_alerts[:10]:
                file_path = alert.get('file_path', 'Unknown')
                short_path = os.path.basename(file_path) if file_path else 'Unknown'
                if len(short_path) > 20:
                    short_path = short_path[:17] + "..."
                
                alert_data.append([
                    alert.get('alert_time', '')[:16],
                    alert.get('alert_type', '')[:15],
                    alert.get('severity', ''),
                    short_path
                ])
            
            if len(alert_data) > 1:
                alert_table = Table(alert_data, colWidths=[1.2*inch, 1.2*inch, 0.8*inch, 1.8*inch])
                alert_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.colors['secondary']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_bg']),
                    ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
                ]))
                
                elements.append(alert_table)
        else:
            elements.append(Paragraph("No recent alerts", getSampleStyleSheet()['Normal']))
        
        return elements
    
    def _create_hash_verification_section(self, data: Dict) -> List:
        """Create detailed hash verification section"""
        elements = []
        
        # Section header
        section_style = ParagraphStyle(
            name='SectionHeader',
            parent=getSampleStyleSheet()['Heading2'],
            fontSize=16,
            textColor=self.colors['secondary'],
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        )
        
        elements.append(Paragraph("Hash Verification Details", section_style))
        
        # Integrity score
        integrity_score = data['summary'].get('integrity_score', 0)
        
        sub_style = ParagraphStyle(
            name='SubSectionHeader',
            parent=getSampleStyleSheet()['Heading3'],
            fontSize=14,
            textColor=self.colors['primary'],
            spaceAfter=8,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )
        
        elements.append(Paragraph(f"Integrity Score: {integrity_score}%", sub_style))
        
        # Verification results
        results_data = [
            ["Metric", "Value"],
            ["Verified Files", str(data['summary'].get('verified', 0))],
            ["Tampered Files", str(data['summary'].get('tampered', 0))],
            ["Errors", str(data['summary'].get('errors', 0))],
            ["Total Files", str(data['summary'].get('total_files', 0))],
            ["Status", data['summary'].get('verification_status', 'UNKNOWN')]
        ]
        
        results_table = Table(results_data, colWidths=[2*inch, 3*inch])
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['secondary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_bg']),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
        ]))
        
        elements.append(results_table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Tampered files list
        tampered_files = data.get('tampered_files', [])
        if tampered_files:
            elements.append(Paragraph("Tampered Files", sub_style))
            
            tamper_data = [["File Path", "Detection Time"]]
            
            for file_info in tampered_files[:20]:
                file_path = file_info.get('file_path', 'Unknown')
                if len(file_path) > 50:
                    file_path = "..." + file_path[-47:]
                
                tamper_data.append([
                    file_path,
                    file_info.get('detection_time', 'Unknown')[:16]
                ])
            
            if len(tamper_data) > 1:
                tamper_table = Table(tamper_data, colWidths=[3.5*inch, 1.5*inch])
                tamper_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), self.colors['danger']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_bg']),
                    ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
                ]))
                
                elements.append(tamper_table)
        else:
            elements.append(Paragraph("No tampered files detected", getSampleStyleSheet()['Normal']))
        
        return elements
    
    def _create_recommendations_section(self, recommendations: List[str]) -> List:
        """Create recommendations section"""
        elements = []
        
        # Section header
        section_style = ParagraphStyle(
            name='SectionHeader',
            parent=getSampleStyleSheet()['Heading2'],
            fontSize=16,
            textColor=self.colors['secondary'],
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        )
        
        elements.append(Paragraph("Recommendations", section_style))
        
        for rec in recommendations:
            # Format recommendation with bullet point
            p = Paragraph(f"• {rec}", getSampleStyleSheet()['Normal'])
            elements.append(p)
            elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _create_horizontal_line(self):
        """Create a horizontal line for PDF"""
        d = Drawing(500, 1)
        d.add(Line(0, 0, 500, 0, strokeColor=self.colors['border'], strokeWidth=1))
        return d
    
    def _add_page_number(self, canvas_obj, doc):
        """Add page number to PDF"""
        page_num = canvas_obj.getPageNumber()
        text = f"Page {page_num}"
        canvas_obj.setFont('Helvetica', 8)
        canvas_obj.setFillColor(colors.gray)
        canvas_obj.drawRightString(doc.pagesize[0] - 72, 30, text)
        
        # Add footer line
        canvas_obj.setStrokeColor(self.colors['border'])
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(72, 40, doc.pagesize[0] - 72, 40)
    
    def list_reports(self) -> List[Dict[str, Any]]:
        """List all generated reports"""
        reports = []
        report_dir = Path(self.report_dir)
        
        for file in report_dir.glob("*.*"):
            if file.suffix.lower() in ['.csv', '.json', '.pdf']:
                stat = file.stat()
                reports.append({
                    'filename': file.name,
                    'format': file.suffix[1:].upper(),
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'path': str(file)
                })
        
        return sorted(reports, key=lambda x: x['created'], reverse=True)
    
    def delete_report(self, filename: str) -> bool:
        """Delete a specific report"""
        filepath = os.path.join(self.report_dir, filename)
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                logger.info(f"Deleted report: {filename}")
                return True
        except Exception as e:
            logger.error(f"Failed to delete report {filename}: {e}")
        return False