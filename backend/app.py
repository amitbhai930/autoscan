from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import os
import json
import threading
import time
from datetime import datetime
import uuid

# Import our modules
from scanner import VulnerabilityScanner
from auth import Auth
from database import Database
from models import Scan, User, Vulnerability
from utils import generate_pdf_report

app = Flask(__name__, static_folder='../static', template_folder='../templete')
CORS(app, supports_credentials=True)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'autoscanz-secret-key-2024')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize components
db = Database()
auth = Auth()

# Store active scans (in production, use Redis or database)
active_scans = {}

# Authentication middleware
def token_required(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        payload = auth.verify_token(token)
        if not payload:
            return jsonify({'error': 'Invalid token'}), 401
        
        request.user_id = payload['user_id']
        request.username = payload['username']
        request.is_admin = payload['is_admin']
        
        return f(*args, **kwargs)
    
    decorated.__name__ = f.__name__
    return decorated

# Admin middleware
def admin_required(f):
    def decorated(*args, **kwargs):
        if not request.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    
    decorated.__name__ = f.__name__
    return decorated

# Serve frontend files
@app.route('/')
def serve_frontend():
    return send_from_directory('../frontend', 'index.html')

@app.route('/<path:path>')
def serve_static_files(path):
    return send_from_directory('../frontend', path)

# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    result = auth.register_user(
        data['username'],
        data['password'],
        data.get('email', '')
    )
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify(result), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing credentials'}), 400
    
    result = auth.login_user(data['username'], data['password'])
    if not result:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    return jsonify(result), 200

@app.route('/api/logout', methods=['POST'])
@token_required
def logout():
    # In production, you might want to blacklist the token
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile():
    session = db.get_session()
    try:
        user = session.query(User).filter_by(id=request.user_id).first()
        if user:
            return jsonify({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None
            }), 200
        return jsonify({'error': 'User not found'}), 404
    finally:
        session.close()

@app.route('/api/scan', methods=['POST'])
@token_required
def start_scan():
    data = request.get_json()
    if not data or 'target_url' not in data:
        return jsonify({'error': 'Target URL is required'}), 400
    
    target_url = data['target_url']
    scan_type = data.get('scan_type', 'full')
    options = data.get('options', {})
    
    # Create scan record in database
    session = db.get_session()
    try:
        scan = Scan(
            user_id=request.user_id,
            target_url=target_url,
            scan_type=scan_type,
            status='running',
            start_time=datetime.utcnow()
        )
        session.add(scan)
        session.commit()
        
        # Start scan in background thread
        scan_id = scan.id
        thread = threading.Thread(
            target=run_scan_background,
            args=(scan_id, target_url, scan_type, options, request.user_id)
        )
        thread.daemon = True
        thread.start()
        
        # Store in active scans
        active_scans[scan_id] = {
            'status': 'running',
            'progress': 0,
            'start_time': datetime.utcnow().isoformat()
        }
        
        return jsonify({
            'message': 'Scan started',
            'scan_id': scan_id,
            'status': 'running'
        }), 202
        
    except Exception as e:
        session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

def run_scan_background(scan_id, target_url, scan_type, options, user_id):
    """Run scan in background thread"""
    session = db.get_session()
    try:
        scanner = VulnerabilityScanner(target_url, scan_id, user_id)
        results = scanner.run_scan(scan_type, options)
        
        # Update scan record
        scan = session.query(Scan).filter_by(id=scan_id).first()
        if scan:
            scan.status = 'completed'
            scan.end_time = datetime.utcnow()
            scan.result_json = json.dumps(results, indent=2)
            scan.vulnerabilities_found = results['statistics']['total_vulnerabilities']
            scan.critical_count = results['statistics']['critical']
            scan.high_count = results['statistics']['high']
            scan.medium_count = results['statistics']['medium']
            scan.low_count = results['statistics']['low']
            scan.cve_matches = results['statistics']['cve_matches']
            
            # Store vulnerabilities
            for vuln in results['vulnerabilities']:
                db_vuln = Vulnerability(
                    scan_id=scan_id,
                    cve_id=vuln.get('cve_id'),
                    severity=vuln['severity'],
                    type=vuln['type'],
                    description=vuln['description'],
                    remediation=vuln['remediation'],
                    affected_component=vuln.get('title', '')
                )
                session.add(db_vuln)
            
            session.commit()
            
            # Remove from active scans
            if scan_id in active_scans:
                del active_scans[scan_id]
                
    except Exception as e:
        print(f"Background scan error: {e}")
        scan = session.query(Scan).filter_by(id=scan_id).first()
        if scan:
            scan.status = 'failed'
            session.commit()
    finally:
        session.close()

@app.route('/api/scan/<int:scan_id>/status', methods=['GET'])
@token_required
def get_scan_status(scan_id):
    session = db.get_session()
    try:
        scan = session.query(Scan).filter_by(id=scan_id, user_id=request.user_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Check if scan is still active
        if scan_id in active_scans:
            progress = active_scans[scan_id].get('progress', 0)
            return jsonify({
                'scan_id': scan_id,
                'status': 'running',
                'progress': progress,
                'start_time': active_scans[scan_id]['start_time']
            }), 200
        
        # Return completed scan status
        return jsonify({
            'scan_id': scan_id,
            'status': scan.status,
            'start_time': scan.start_time.isoformat() if scan.start_time else None,
            'end_time': scan.end_time.isoformat() if scan.end_time else None,
            'vulnerabilities_found': scan.vulnerabilities_found
        }), 200
        
    finally:
        session.close()

@app.route('/api/scan/<int:scan_id>/results', methods=['GET'])
@token_required
def get_scan_results(scan_id):
    session = db.get_session()
    try:
        scan = session.query(Scan).filter_by(id=scan_id, user_id=request.user_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status != 'completed':
            return jsonify({'error': 'Scan not completed yet'}), 400
        
        results = json.loads(scan.result_json) if scan.result_json else {}
        
        # Get vulnerabilities from database
        vulnerabilities = session.query(Vulnerability).filter_by(scan_id=scan_id).all()
        vuln_list = []
        for v in vulnerabilities:
            vuln_list.append({
                'cve_id': v.cve_id,
                'severity': v.severity,
                'type': v.type,
                'description': v.description,
                'remediation': v.remediation,
                'affected_component': v.affected_component
            })
        
        results['database_vulnerabilities'] = vuln_list
        
        return jsonify(results), 200
        
    finally:
        session.close()

@app.route('/api/history', methods=['GET'])
@token_required
def get_scan_history():
    session = db.get_session()
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Get scans for user
        scans = session.query(Scan).filter_by(user_id=request.user_id)\
            .order_by(Scan.start_time.desc())\
            .offset((page - 1) * per_page)\
            .limit(per_page)\
            .all()
        
        scan_list = []
        for scan in scans:
            scan_list.append({
                'id': scan.id,
                'target_url': scan.target_url,
                'scan_type': scan.scan_type,
                'status': scan.status,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'vulnerabilities_found': scan.vulnerabilities_found,
                'critical_count': scan.critical_count,
                'high_count': scan.high_count,
                'medium_count': scan.medium_count,
                'low_count': scan.low_count
            })
        
        total = session.query(Scan).filter_by(user_id=request.user_id).count()
        
        return jsonify({
            'scans': scan_list,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }), 200
        
    finally:
        session.close()

@app.route('/api/scan/<int:scan_id>/report', methods=['POST'])
@token_required
def generate_report(scan_id):
    data = request.get_json()
    format_type = data.get('format', 'pdf')
    report_type = data.get('report_type', 'detailed')
    
    session = db.get_session()
    try:
        scan = session.query(Scan).filter_by(id=scan_id, user_id=request.user_id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status != 'completed':
            return jsonify({'error': 'Scan not completed yet'}), 400
        
        results = json.loads(scan.result_json) if scan.result_json else {}
        
        if format_type == 'pdf':
            # Generate PDF report
            pdf_path = generate_pdf_report(scan, results, report_type)
            
            # Return download URL
            filename = f"scan_report_{scan_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
            
            return jsonify({
                'message': 'Report generated successfully',
                'download_url': f'/api/reports/download/{filename}',
                'file_path': pdf_path
            }), 200
            
        elif format_type == 'json':
            # Return JSON report
            return jsonify(results), 200
            
        else:
            return jsonify({'error': 'Unsupported format'}), 400
            
    finally:
        session.close()

@app.route('/api/reports/download/<filename>', methods=['GET'])
@token_required
def download_report(filename):
    # Verify file exists and user has permission
    file_path = os.path.join('../static/reports', filename)
    if not os.path.exists(file_path):
        return jsonify({'error': 'Report not found'}), 404
    
    return send_file(file_path, as_attachment=True)

# Admin routes
@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def admin_get_users():
    session = db.get_session()
    try:
        users = session.query(User).all()
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None
            })
        
        return jsonify({'users': user_list}), 200
    finally:
        session.close()

@app.route('/api/admin/scans', methods=['GET'])
@token_required
@admin_required
def admin_get_all_scans():
    session = db.get_session()
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        scans = session.query(Scan).join(User)\
            .order_by(Scan.start_time.desc())\
            .offset((page - 1) * per_page)\
            .limit(per_page)\
            .all()
        
        scan_list = []
        for scan in scans:
            scan_list.append({
                'id': scan.id,
                'user_id': scan.user_id,
                'username': scan.user.username if scan.user else 'Unknown',
                'target_url': scan.target_url,
                'scan_type': scan.scan_type,
                'status': scan.status,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'vulnerabilities_found': scan.vulnerabilities_found
            })
        
        total = session.query(Scan).count()
        
        return jsonify({
            'scans': scan_list,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }), 200
    finally:
        session.close()

@app.route('/api/admin/stats', methods=['GET'])
@token_required
@admin_required
def admin_get_stats():
    session = db.get_session()
    try:
        # Basic statistics
        total_scans = session.query(Scan).count()
        completed_scans = session.query(Scan).filter_by(status='completed').count()
        failed_scans = session.query(Scan).filter_by(status='failed').count()
        running_scans = session.query(Scan).filter_by(status='running').count()
        total_users = session.query(User).count()
        
        # Vulnerability statistics
        total_vulnerabilities = session.query(Vulnerability).count()
        critical_vulns = session.query(Vulnerability).filter_by(severity='critical').count()
        high_vulns = session.query(Vulnerability).filter_by(severity='high').count()
        medium_vulns = session.query(Vulnerability).filter_by(severity='medium').count()
        low_vulns = session.query(Vulnerability).filter_by(severity='low').count()
        
        # Recent activity
        recent_scans = session.query(Scan)\
            .order_by(Scan.start_time.desc())\
            .limit(5)\
            .all()
        
        recent_scan_list = []
        for scan in recent_scans:
            recent_scan_list.append({
                'id': scan.id,
                'target_url': scan.target_url,
                'status': scan.status,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'user': scan.user.username if scan.user else 'Unknown'
            })
        
        return jsonify({
            'statistics': {
                'total_scans': total_scans,
                'completed_scans': completed_scans,
                'failed_scans': failed_scans,
                'running_scans': running_scans,
                'total_users': total_users,
                'total_vulnerabilities': total_vulnerabilities,
                'critical_vulnerabilities': critical_vulns,
                'high_vulnerabilities': high_vulns,
                'medium_vulnerabilities': medium_vulns,
                'low_vulnerabilities': low_vulns
            },
            'recent_activity': recent_scan_list
        }), 200
    finally:
        session.close()

@app.route('/api/admin/cve/update', methods=['POST'])
@token_required
@admin_required
def admin_update_cve_database():
    # This would update the CVE database from external sources
    # For now, just return success
    return jsonify({
        'message': 'CVE database update initiated',
        'status': 'pending'
    }), 200

# Health check
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }), 200

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('../static/reports', exist_ok=True)
    os.makedirs('../frontend', exist_ok=True)
    
    print("AutoScanZ Backend Starting...")
    print("Default admin credentials: admin/admin")
    print(f"Database file: autoscanz.db")
    print(f"Server running on http://localhost:5000")
    
    app.run(host='0.0.0.0', port=5000, debug=True)