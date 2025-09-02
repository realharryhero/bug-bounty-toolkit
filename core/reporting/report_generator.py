"""
Report Generator - Creates comprehensive security reports in multiple formats
"""

import json
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)

class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

@dataclass
class Finding:
    """Represents a security finding."""
    title: str
    severity: Severity
    confidence: float
    description: str
    target: str
    vulnerability_type: str
    payload: Optional[str] = None
    evidence: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = None
    cwe_ids: Optional[List[str]] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.references is None:
            self.references = []
        if self.cwe_ids is None:
            self.cwe_ids = []

@dataclass
class ScanResults:
    """Container for scan results."""
    scan_type: str
    target: str
    start_time: str
    end_time: str
    duration: float
    findings: List[Finding]
    statistics: Dict[str, Any]
    metadata: Dict[str, Any]

class ReportGenerator:
    """Generates security reports in multiple formats."""
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Create templates directory
        self.templates_dir = Path("templates")
        self.templates_dir.mkdir(exist_ok=True)
        
        self._create_default_templates()
    
    def _create_default_templates(self):
        """Create default report templates if they don't exist."""
        html_template_path = self.templates_dir / "report.html"
        
        if not html_template_path.exists():
            html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { background-color: #f4f4f4; padding: 15px; border-radius: 5px; margin-bottom: 30px; }
        .finding { border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #dc3545; }
        .high { border-left: 5px solid #fd7e14; }
        .medium { border-left: 5px solid #ffc107; }
        .low { border-left: 5px solid #28a745; }
        .info { border-left: 5px solid #17a2b8; }
        .severity { font-weight: bold; text-transform: uppercase; }
        .payload { background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; margin: 10px 0; }
        .metadata { font-size: 0.9em; color: #666; }
        .statistics { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { text-align: center; padding: 15px; background-color: #e9ecef; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> {{target}}</p>
        <p><strong>Scan Type:</strong> {{scan_type}}</p>
        <p><strong>Date:</strong> {{start_time}} - {{end_time}}</p>
        <p><strong>Duration:</strong> {{duration}} seconds</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="statistics">
            <div class="stat-box">
                <h3>{{total_findings}}</h3>
                <p>Total Findings</p>
            </div>
            <div class="stat-box">
                <h3>{{critical_count}}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-box">
                <h3>{{high_count}}</h3>
                <p>High</p>
            </div>
            <div class="stat-box">
                <h3>{{medium_count}}</h3>
                <p>Medium</p>
            </div>
            <div class="stat-box">
                <h3>{{low_count}}</h3>
                <p>Low</p>
            </div>
        </div>
    </div>
    
    <div class="findings">
        <h2>Detailed Findings</h2>
        {{findings_html}}
    </div>
    
    <div class="metadata">
        <h2>Scan Metadata</h2>
        <pre>{{metadata_json}}</pre>
    </div>
</body>
</html>'''
            
            with open(html_template_path, 'w') as f:
                f.write(html_template)
    
    def generate_report(self, results: ScanResults, format: str = "html") -> str:
        """
        Generate a security report in the specified format.
        
        Args:
            results: Scan results to include in the report
            format: Report format (html, json, pdf)
            
        Returns:
            Path to the generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == "html":
            return self._generate_html_report(results, timestamp)
        elif format == "json":
            return self._generate_json_report(results, timestamp)
        elif format == "pdf":
            return self._generate_pdf_report(results, timestamp)
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def _generate_html_report(self, results: ScanResults, timestamp: str) -> str:
        """Generate HTML report."""
        template_path = self.templates_dir / "report.html"
        
        with open(template_path, 'r') as f:
            template = f.read()
        
        # Calculate statistics
        severity_counts = self._calculate_severity_counts(results.findings)
        
        # Generate findings HTML
        findings_html = ""
        for finding in results.findings:
            severity_class = finding.severity.value.lower()
            findings_html += f'''
            <div class="finding {severity_class}">
                <h3>{finding.title}</h3>
                <p><span class="severity">{finding.severity.value}</span> - Confidence: {finding.confidence:.2f}</p>
                <p><strong>Description:</strong> {finding.description}</p>
                <p><strong>Target:</strong> {finding.target}</p>
                <p><strong>Vulnerability Type:</strong> {finding.vulnerability_type}</p>
                {f'<div class="payload"><strong>Payload:</strong><br><code>{finding.payload}</code></div>' if finding.payload else ''}
                {f'<p><strong>Evidence:</strong> {finding.evidence}</p>' if finding.evidence else ''}
                {f'<p><strong>Impact:</strong> {finding.impact}</p>' if finding.impact else ''}
                {f'<p><strong>Remediation:</strong> {finding.remediation}</p>' if finding.remediation else ''}
                <p class="metadata">Found at: {finding.timestamp}</p>
            </div>
            '''
        
        # Replace template variables
        report_html = template.replace("{{target}}", results.target)
        report_html = report_html.replace("{{scan_type}}", results.scan_type)
        report_html = report_html.replace("{{start_time}}", results.start_time)
        report_html = report_html.replace("{{end_time}}", results.end_time)
        report_html = report_html.replace("{{duration}}", str(results.duration))
        report_html = report_html.replace("{{total_findings}}", str(len(results.findings)))
        report_html = report_html.replace("{{critical_count}}", str(severity_counts.get("Critical", 0)))
        report_html = report_html.replace("{{high_count}}", str(severity_counts.get("High", 0)))
        report_html = report_html.replace("{{medium_count}}", str(severity_counts.get("Medium", 0)))
        report_html = report_html.replace("{{low_count}}", str(severity_counts.get("Low", 0)))
        report_html = report_html.replace("{{findings_html}}", findings_html)
        report_html = report_html.replace("{{metadata_json}}", json.dumps(results.metadata, indent=2))
        
        # Save report
        report_path = self.output_dir / f"security_report_{timestamp}.html"
        with open(report_path, 'w') as f:
            f.write(report_html)
        
        logger.info(f"HTML report generated: {report_path}")
        return str(report_path)
    
    def _generate_json_report(self, results: ScanResults, timestamp: str) -> str:
        """Generate JSON report."""
        report_data = {
            "scan_info": {
                "scan_type": results.scan_type,
                "target": results.target,
                "start_time": results.start_time,
                "end_time": results.end_time,
                "duration": results.duration
            },
            "statistics": results.statistics,
            "findings": [asdict(finding) for finding in results.findings],
            "metadata": results.metadata,
            "generated_at": datetime.now().isoformat()
        }
        
        report_path = self.output_dir / f"security_report_{timestamp}.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"JSON report generated: {report_path}")
        return str(report_path)
    
    def _generate_pdf_report(self, results: ScanResults, timestamp: str) -> str:
        """Generate PDF report (requires additional dependencies)."""
        try:
            # This would require libraries like weasyprint or reportlab
            # For now, generate HTML and provide conversion instructions
            html_path = self._generate_html_report(results, timestamp)
            
            logger.warning("PDF generation requires additional dependencies.")
            logger.info(f"HTML report generated instead: {html_path}")
            logger.info("To convert to PDF, use: wkhtmltopdf or weasyprint")
            
            return html_path
            
        except Exception as e:
            logger.error(f"PDF generation failed: {str(e)}")
            # Fallback to HTML
            return self._generate_html_report(results, timestamp)
    
    def _calculate_severity_counts(self, findings: List[Finding]) -> Dict[str, int]:
        """Calculate count of findings by severity."""
        counts = {}
        for finding in findings:
            severity = finding.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def create_finding(self, title: str, severity: Severity, confidence: float,
                      description: str, target: str, vulnerability_type: str,
                      **kwargs) -> Finding:
        """
        Create a new finding with proper validation.
        
        Args:
            title: Finding title
            severity: Severity level
            confidence: Confidence score (0.0 to 1.0)
            description: Detailed description
            target: Target URL/endpoint
            vulnerability_type: Type of vulnerability
            **kwargs: Additional finding attributes
            
        Returns:
            New Finding instance
        """
        # Validate confidence score
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")
        
        return Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            description=description,
            target=target,
            vulnerability_type=vulnerability_type,
            **kwargs
        )
    
    def create_scan_results(self, scan_type: str, target: str, 
                           start_time: datetime, end_time: datetime,
                           findings: List[Finding],
                           **metadata) -> ScanResults:
        """
        Create scan results with calculated statistics.
        
        Args:
            scan_type: Type of scan performed
            target: Target that was scanned
            start_time: Scan start time
            end_time: Scan end time
            findings: List of findings
            **metadata: Additional metadata
            
        Returns:
            ScanResults instance
        """
        duration = (end_time - start_time).total_seconds()
        
        # Calculate statistics
        statistics = {
            "total_findings": len(findings),
            "severity_breakdown": self._calculate_severity_counts(findings),
            "average_confidence": sum(f.confidence for f in findings) / len(findings) if findings else 0.0,
            "vulnerability_types": list(set(f.vulnerability_type for f in findings))
        }
        
        return ScanResults(
            scan_type=scan_type,
            target=target,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration=duration,
            findings=findings,
            statistics=statistics,
            metadata=metadata
        )