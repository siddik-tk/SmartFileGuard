#!/usr/bin/env python3
"""
Report Exporter for SmartFileGuard
Exports alerts, file history, and system reports in JSON, CSV, PDF formats
"""

import os
import json
import csv
import io
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)

# Try importing pandas for Excel
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

# Try importing reportlab for PDF
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.enums import TA_CENTER
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class ReportExporter:
    """Handles exporting reports in various formats"""
    
    def __init__(self, export_dir='exports'):
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(exist_ok=True)
    
    def export_all_data(self, alerts: List[Dict], nodes: List[Dict], 
                       file_history: List[Dict], format: str = 'json') -> Dict:
        """Export all data in specified format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"smartfileguard_full_report_{timestamp}"
        
        if format == 'json':
            return self._export_json(alerts, nodes, file_history, filename)
        elif format == 'csv':
            return self._export_csv(alerts, nodes, file_history, timestamp)
        elif format == 'pdf':
            return self._export_pdf(alerts, nodes, file_history, filename)
        elif format == 'excel':
            return self._export_excel(alerts, nodes, file_history, filename)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _export_json(self, alerts, nodes, file_history, filename):
        """Export as JSON"""
        filepath = self.export_dir / f"{filename}.json"
        
        data = {
            'export_time': datetime.now().isoformat(),
            'summary': {
                'total_alerts': len(alerts),
                'total_nodes': len(nodes),
                'total_file_events': len(file_history),
                'active_nodes': len([n for n in nodes if n.get('connection_status') == 'connected'])
            },
            'nodes': nodes,
            'alerts': alerts,
            'file_history': file_history
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        return {
            'filename': filepath.name,
            'filepath': str(filepath),
            'format': 'json',
            'size': filepath.stat().st_size
        }
    
    def _export_csv(self, alerts, nodes, file_history, timestamp):
        """Export as CSV files in a zip-like structure"""
        results = []
        
        # Alerts CSV
        alerts_file = self.export_dir / f"alerts_{timestamp}.csv"
        if alerts:
            with open(alerts_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
                writer.writeheader()
                writer.writerows(alerts)
            results.append({
                'filename': alerts_file.name,
                'filepath': str(alerts_file),
                'format': 'csv',
                'type': 'alerts',
                'records': len(alerts),
                'size': alerts_file.stat().st_size
            })
        
        # Nodes CSV
        nodes_file = self.export_dir / f"nodes_{timestamp}.csv"
        if nodes:
            with open(nodes_file, 'w', newline='', encoding='utf-8') as f:
                if nodes:
                    writer = csv.DictWriter(f, fieldnames=['node_name', 'node_group', 'ip_address', 
                                                           'connection_status', 'last_seen', 'version'])
                    writer.writeheader()
                    for node in nodes:
                        writer.writerow({
                            'node_name': node.get('node_name'),
                            'node_group': node.get('node_group'),
                            'ip_address': node.get('ip_address'),
                            'connection_status': node.get('connection_status'),
                            'last_seen': node.get('last_seen'),
                            'version': node.get('version')
                        })
            results.append({
                'filename': nodes_file.name,
                'filepath': str(nodes_file),
                'format': 'csv',
                'type': 'nodes',
                'records': len(nodes),
                'size': nodes_file.stat().st_size
            })
        
        # File history CSV
        history_file = self.export_dir / f"file_history_{timestamp}.csv"
        if file_history:
            with open(history_file, 'w', newline='', encoding='utf-8') as f:
                if file_history:
                    writer = csv.DictWriter(f, fieldnames=file_history[0].keys())
                    writer.writeheader()
                    writer.writerows(file_history)
            results.append({
                'filename': history_file.name,
                'filepath': str(history_file),
                'format': 'csv',
                'type': 'file_history',
                'records': len(file_history),
                'size': history_file.stat().st_size
            })
        
        return results[0] if results else {'filename': 'empty', 'format': 'csv'}
    
    def _export_pdf(self, alerts, nodes, file_history, filename):
        """Export as PDF"""
        if not REPORTLAB_AVAILABLE:
            return self._export_json(alerts, nodes, file_history, filename)
        
        filepath = self.export_dir / f"{filename}.pdf"
        
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=30,
            leftMargin=30,
            topMargin=30,
            bottomMargin=30
        )
        
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=20,
            textColor=colors.HexColor('#00ff88'),
            alignment=TA_CENTER,
            spaceAfter=20
        )
        story.append(Paragraph("SmartFileGuard Report", title_style))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Summary
        story.append(Paragraph("Summary", styles['Heading2']))
        summary_data = [
            ['Total Alerts', str(len(alerts))],
            ['Total Nodes', str(len(nodes))],
            ['Active Nodes', str(len([n for n in nodes if n.get('connection_status') == 'connected']))],
            ['File Events', str(len(file_history))]
        ]
        t = Table(summary_data, colWidths=[200, 200])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#1a2733')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#e0e0e0')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#2a3a47')),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
        story.append(Spacer(1, 20))
        
        # Alerts table (first 50)
        if alerts:
            story.append(Paragraph("Recent Alerts", styles['Heading2']))
            alert_data = [['Time', 'Node', 'Type', 'Severity', 'File']]
            for a in alerts[:50]:
                alert_data.append([
                    str(a.get('alert_time', ''))[:16],
                    a.get('node_name', '')[:15],
                    str(a.get('alert_type', ''))[:20],
                    a.get('severity', ''),
                    str(a.get('file_path', '')).split('\\')[-1][:25]
                ])
            
            t = Table(alert_data, colWidths=[90, 80, 100, 60, 120])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16202a')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00ff88')),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#2a3a47')),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(t)
        
        doc.build(story)
        
        return {
            'filename': filepath.name,
            'filepath': str(filepath),
            'format': 'pdf',
            'size': filepath.stat().st_size
        }
    
    def _export_excel(self, alerts, nodes, file_history, filename):
        """Export as Excel"""
        if not PANDAS_AVAILABLE:
            return self._export_csv(alerts, nodes, file_history, 
                                   datetime.now().strftime("%Y%m%d_%H%M%S"))
        
        filepath = self.export_dir / f"{filename}.xlsx"
        
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            if alerts:
                pd.DataFrame(alerts).to_excel(writer, sheet_name='Alerts', index=False)
            if nodes:
                pd.DataFrame(nodes).to_excel(writer, sheet_name='Nodes', index=False)
            if file_history:
                pd.DataFrame(file_history).to_excel(writer, sheet_name='File History', index=False)
        
        return {
            'filename': filepath.name,
            'filepath': str(filepath),
            'format': 'excel',
            'size': filepath.stat().st_size
        }
    
    def get_exports(self) -> List[Dict]:
        """List all exported files"""
        exports = []
        for file in self.export_dir.glob('*'):
            if file.suffix in ['.json', '.csv', '.pdf', '.xlsx']:
                exports.append({
                    'filename': file.name,
                    'format': file.suffix[1:],
                    'size': file.stat().st_size,
                    'created': datetime.fromtimestamp(file.stat().st_ctime).isoformat()
                })
        return sorted(exports, key=lambda x: x['created'], reverse=True)
    
    def delete_export(self, filename):
        """Delete an export file"""
        filepath = self.export_dir / filename
        if filepath.exists():
            filepath.unlink()
            return True
        return False