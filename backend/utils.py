from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from datetime import datetime
import os
import json

def generate_pdf_report(scan, scan_results, report_type='detailed'):
    """Generate PDF report from scan results"""
    
    # Create report directory if not exists
    reports_dir = '../static/reports'
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"scan_report_{scan.id}_{timestamp}.pdf"
    filepath = os.path.join(reports_dir, filename)
    
    # Create PDF document
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1  # Center
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.HexColor('#2a4365')
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading3'],
        fontSize=14,
        spaceAfter=8,
        textColor=colors.HexColor('#3182ce')
    )
    
    # Story holds the content
    story = []
    
    # Title
    story.append(Paragraph("AutoScanZ Vulnerability Assessment Report", title_style))
    story.append(Spacer(1, 20))
    
    # Report metadata
    meta_data = [
        ["Report ID:", f"SCAN-{scan.id}"],
        ["Target URL:", scan.target_url],
        ["Scan Type:", scan.scan_type],
        ["Scan Date:", scan.start_time.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.start_time else 'N/A'],
        ["Generated:", datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')],
        ["Status:", scan.status],
        ["Vulnerabilities Found:", str(scan.vulnerabilities_found)]
    ]
    
    meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f7fafc')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    
    story.append(meta_table)
    story.append(Spacer(1, 30))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    
    summary_text = f"""
    This report presents the findings of a security vulnerability scan conducted on {scan.target_url}. 
    The scan identified {scan.vulnerabilities_found} security issues, including {scan.critical_count} critical,
    {scan.high_count} high, {scan.medium_count} medium, and {scan.low_count} low severity vulnerabilities.
    """
    
    story.append(Paragraph(summary_text, styles["Normal"]))
    story.append(Spacer(1, 20))
    
    # Risk Summary Table
    story.append(Paragraph("Risk Summary", subheading_style))
    
    risk_data = [
        ["Severity", "Count", "Risk Level"],
        ["Critical", str(scan.critical_count), "Very High"],
        ["High", str(scan.high_count), "High"],
        ["Medium", str(scan.medium_count), "Medium"],
        ["Low", str(scan.low_count), "Low"],
        ["Total", str(scan.vulnerabilities_found), "-"]
    ]
    
    risk_table = Table(risk_data, colWidths=[1.5*inch, 1*inch, 1.5*inch])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2a4365')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#e53e3e')),  # Critical
        ('BACKGROUND', (0, 2), (0, 2), colors.HexColor('#dd6b20')),  # High
        ('BACKGROUND', (0, 3), (0, 3), colors.HexColor('#d69e2e')),  # Medium
        ('BACKGROUND', (0, 4), (0, 4), colors.HexColor('#38b2ac')),  # Low
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ALIGN', (1, 1), (1, -1), 'CENTER'),
    ]))
    
    story.append(risk_table)
    story.append(Spacer(1, 30))
    
    # Detailed Findings (if detailed report)
    if report_type == 'detailed' and scan_results:
        story.append(Paragraph("Detailed Findings", heading_style))
        
        # Parse vulnerabilities from results
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities[:10]):  # Limit to first 10 for PDF
                story.append(Paragraph(f"Finding {i+1}: {vuln.get('title', 'Unknown')}", subheading_style))
                
                vuln_data = [
                    ["Severity:", vuln.get('severity', 'Unknown').upper()],
                    ["Type:", vuln.get('type', 'Unknown')],
                    ["CVE ID:", vuln.get('cve_id', 'N/A')],
                ]
                
                vuln_table = Table(vuln_data, colWidths=[1*inch, 4*inch])
                vuln_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 10))
                
                # Description
                desc_style = ParagraphStyle(
                    'VulnDesc',
                    parent=styles['Normal'],
                    fontSize=10,
                    spaceAfter=6,
                    leftIndent=20
                )
                
                story.append(Paragraph(f"<b>Description:</b> {vuln.get('description', 'No description')}", desc_style))
                story.append(Paragraph(f"<b>Remediation:</b> {vuln.get('remediation', 'No remediation provided')}", desc_style))
                story.append(Spacer(1, 20))
        else:
            story.append(Paragraph("No vulnerabilities found.", styles["Normal"]))
    
    # Recommendations
    story.append(Paragraph("Recommendations", heading_style))
    
    rec_text = """
    1. Address critical and high severity vulnerabilities immediately
    2. Implement regular security scanning schedule
    3. Keep all software components updated
    4. Implement proper input validation and output encoding
    5. Configure security headers appropriately
    6. Use HTTPS with strong TLS configuration
    7. Implement proper access controls
    8. Regularly backup and test recovery procedures
    """
    
    story.append(Paragraph(rec_text, styles["Normal"]))
    story.append(Spacer(1, 20))
    
    # Footer note
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.grey,
        alignment=1
    )
    
    story.append(Paragraph("Generated by AutoScanZ - Automated Vulnerability Scanner", footer_style))
    story.append(Paragraph("Confidential - For authorized use only", footer_style))
    
    # Build PDF
    doc.build(story)
    
    return filepath