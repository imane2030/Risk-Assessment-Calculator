from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from datetime import datetime
import os

def generate_pdf_report(data: dict) -> str:
    """
    Generate PDF risk assessment report.
    
    Args:
        data: Dictionary containing risk assessment results
    
    Returns:
        Path to generated PDF file
    """
    # Create output directory if it doesn't exist
    os.makedirs('reports', exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'reports/risk_assessment_{timestamp}.pdf'
    
    # Create PDF document
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=1  # Center
    )
    
    elements.append(Paragraph("Cybersecurity Risk Assessment Report", title_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y')}", styles['Normal']))
    elements.append(Spacer(1, 0.3*inch))
    
    # Executive Summary
    elements.append(Paragraph("Executive Summary", styles['Heading2']))
    
    results = data.get('results', {})
    ale = results.get('annual_loss_expectancy', 0)
    risk_level = results.get('risk_level', 'Unknown')
    
    summary_text = f"""
    This risk assessment quantifies cybersecurity risk using the FAIR (Factor Analysis of Information Risk) methodology.
    The analysis estimates an <b>Annual Loss Expectancy (ALE) of ${ale:,.2f}</b> with a risk level of <b>{risk_level}</b>.
    """
    
    elements.append(Paragraph(summary_text, styles['BodyText']))
    elements.append(Spacer(1, 0.2*inch))
    
    # Risk Parameters Table
    elements.append(Paragraph("Risk Assessment Parameters", styles['Heading2']))
    
    params_data = [
        ['Parameter', 'Value'],
        ['Asset Value', f"${results.get('asset_value', 0):,.2f}"],
        ['Threat Event Frequency (per year)', results.get('threat_event_frequency', 0)],
        ['Vulnerability (probability)', f"{results.get('vulnerability', 0):.2%}"],
        ['Loss Magnitude (per event)', f"${results.get('loss_magnitude', 0):,.2f}"]
    ]
    
    params_table = Table(params_data, colWidths=[3*inch, 2*inch])
    params_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(params_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Risk Calculation Results
    elements.append(Paragraph("Risk Calculation Results", styles
