from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from fair_calculator import FAIRCalculator
from report_generator import generate_pdf_report
import json

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return send_file('templates/index.html')

@app.route('/api/calculate', methods=['POST'])
def calculate_risk():
    """Calculate risk using FAIR methodology."""
    try:
        data = request.get_json()
        
        # Extract input parameters
        asset_value = float(data.get('asset_value', 0))
        threat_event_frequency = float(data.get('threat_event_frequency', 0))
        vulnerability = float(data.get('vulnerability', 0))
        loss_magnitude = float(data.get('loss_magnitude', 0))
        
        # Validate inputs
        if asset_value <= 0:
            return jsonify({'error': 'Asset value must be greater than 0'}), 400
        
        # Initialize FAIR calculator
        calculator = FAIRCalculator(
            asset_value=asset_value,
            threat_event_frequency=threat_event_frequency,
            vulnerability=vulnerability,
            loss_magnitude=loss_magnitude
        )
        
        # Calculate risk metrics
        results = calculator.calculate()
        
        return jsonify({
            'success': True,
            'results': results
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/monte-carlo', methods=['POST'])
def run_monte_carlo():
    """Run Monte Carlo simulation for risk analysis."""
    try:
        data = request.get_json()
        
        asset_value = float(data.get('asset_value', 0))
        tef_min = float(data.get('tef_min', 1))
        tef_max = float(data.get('tef_max', 10))
        vuln_min = float(data.get('vuln_min', 0.1))
        vuln_max = float(data.get('vuln_max', 0.9))
        loss_min = float(data.get('loss_min', 10000))
        loss_max = float(data.get('loss_max', 100000))
        iterations = int(data.get('iterations', 10000))
        
        calculator = FAIRCalculator(
            asset_value=asset_value,
            threat_event_frequency=(tef_min + tef_max) / 2,
            vulnerability=(vuln_min + vuln_max) / 2,
            loss_magnitude=(loss_min + loss_max) / 2
        )
        
        simulation_results = calculator.monte_carlo_simulation(
            tef_range=(tef_min, tef_max),
            vuln_range=(vuln_min, vuln_max),
            loss_range=(loss_min, loss_max),
            iterations=iterations
        )
        
        return jsonify({
            'success': True,
            'simulation': simulation_results
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/generate-report', methods=['POST'])
def generate_report():
    """Generate PDF report."""
    try:
        data = request.get_json()
        
        pdf_path = generate_pdf_report(data)
        
        return send_file(
            pdf_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name='risk_assessment_report.pdf'
        )
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
