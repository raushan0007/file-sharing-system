import os
import uuid
import datetime
from flask import Flask, request, render_template, send_file, redirect, url_for, flash, jsonify, Response, session
from werkzeug.utils import secure_filename
import threading
import time
import hashlib
import json
from functools import wraps
import math

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production-2024'
app.config['SESSION_TYPE'] = 'filesystem'

# Enhanced Configuration for 2GB max
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'*'}  # Allow all file types
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2GB max file size
DAILY_UPLOAD_LIMIT = 2 * 1024 * 1024 * 1024  # 2GB per day per user
DEFAULT_EXPIRY_DAYS = 7  # Auto-delete after 7 days
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'  # Change this in production

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Create upload directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# File metadata storage with user session tracking
file_data = {}
user_sessions = {}
upload_progress = {}

# Dangerous file extensions
DANGEROUS_EXTENSIONS = {
    'exe', 'bat', 'cmd', 'com', 'scr', 'pif', 'application', 'gadget',
    'msi', 'msp', 'com', 'scr', 'hta', 'cpl', 'msc', 'jar', 'vb', 'vbs',
    'vbe', 'js', 'jse', 'ws', 'wsf', 'wsc', 'wsh', 'ps1', 'ps1xml', 'ps2',
    'ps2xml', 'psc1', 'psc2', 'msh', 'msh1', 'msh2', 'mshxml', 'msh1xml',
    'msh2xml', 'scf', 'lnk', 'inf', 'reg'
}

def get_user_session():
    """Get or create user session based on IP and browser fingerprint"""
    user_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    session_id = hashlib.md5(f"{user_ip}{user_agent}".encode()).hexdigest()[:16]
    
    if session_id not in user_sessions:
        user_sessions[session_id] = {
            'created': datetime.datetime.now(),
            'files': [],
            'ip': user_ip,
            'total_uploads': 0,
            'total_downloads': 0,
            'last_activity': datetime.datetime.now(),
            'total_storage_used': 0,
            'daily_uploads': {
                'date': datetime.datetime.now().date().isoformat(),
                'total_bytes': 0,
                'file_count': 0
            },
            'upload_history': []
        }
    
    user_sessions[session_id]['last_activity'] = datetime.datetime.now()
    
    # Reset daily counter if it's a new day
    current_date = datetime.datetime.now().date().isoformat()
    if user_sessions[session_id]['daily_uploads']['date'] != current_date:
        user_sessions[session_id]['daily_uploads'] = {
            'date': current_date,
            'total_bytes': 0,
            'file_count': 0
        }
    
    return session_id

def get_user_files(session_id):
    """Get files uploaded by specific user"""
    return user_sessions[session_id].get('files', [])

def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def scan_file_safety(file_path, filename):
    """Basic safety scan for files"""
    file_ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if file_ext in DANGEROUS_EXTENSIONS:
        return False, f"File type .{file_ext} is potentially dangerous"
    
    file_size = os.path.getsize(file_path)
    if file_ext in ['exe', 'dll', 'sys'] and file_size < 1024:
        return False, "Suspicious file size for executable"
    
    if filename.count('.') > 1:
        last_ext = filename.rsplit('.', 1)[-1].lower()
        second_last_ext = filename.rsplit('.', 2)[-2].lower()
        if last_ext in DANGEROUS_EXTENSIONS and second_last_ext in ['pdf', 'doc', 'jpg', 'png']:
            return False, "Suspicious double file extension detected"
    
    return True, "File appears safe"

def format_file_size(size_bytes):
    """Convert bytes to human readable format"""
    if size_bytes == 0:
        return "0B"
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def clean_expired_files():
    """Background task to remove expired files"""
    while True:
        current_time = datetime.datetime.now()
        expired_files = []
        
        for file_id, data in file_data.items():
            if data['expiry_time'] <= current_time:
                expired_files.append(file_id)
        
        for file_id in expired_files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_data[file_id]['filename'])
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                # Remove from user sessions
                for session in user_sessions.values():
                    if file_id in session.get('files', []):
                        session['files'].remove(file_id)
                        session['total_storage_used'] -= file_data[file_id]['file_size']
                del file_data[file_id]
                print(f"🗑️ Deleted expired file: {file_id}")
            except Exception as e:
                print(f"Error deleting file {file_id}: {e}")
        
        time.sleep(3600)  # Check every hour

@app.route('/')
def index():
    session_id = get_user_session()
    user_files = get_user_files(session_id)
    
    # Calculate storage used by user
    user_storage = user_sessions[session_id].get('total_storage_used', 0)
    
    # Get daily upload usage
    daily_uploads = user_sessions[session_id].get('daily_uploads', {'total_bytes': 0, 'date': datetime.datetime.now().date().isoformat()})
    daily_used = daily_uploads['total_bytes']
    daily_remaining = DAILY_UPLOAD_LIMIT - daily_used
    daily_percentage = min(100, (daily_used / DAILY_UPLOAD_LIMIT) * 100)
    
    # Get user stats
    user_stats = user_sessions.get(session_id, {})
    
    return render_template('index.html', 
                         user_files_count=len(user_files),
                         user_storage=format_file_size(user_storage),
                         session_id=session_id,
                         user_stats=user_stats,
                         max_file_size=format_file_size(MAX_FILE_SIZE),
                         daily_quota={
                             'used': daily_used,
                             'used_formatted': format_file_size(daily_used),
                             'remaining': daily_remaining,
                             'remaining_formatted': format_file_size(daily_remaining),
                             'limit': DAILY_UPLOAD_LIMIT,
                             'limit_formatted': format_file_size(DAILY_UPLOAD_LIMIT),
                             'percentage': daily_percentage
                         })

@app.route('/upload', methods=['POST'])
def upload_file():
    session_id = get_user_session()
    upload_id = str(uuid.uuid4())[:8]
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Get file size from content-length header for better accuracy
        file_size = int(request.headers.get('Content-Length', 0))
        
        # Validate file size against global limit
        if file_size > MAX_FILE_SIZE:
            return jsonify({
                'error': f'File too large. Maximum size is 2GB. Your file is {format_file_size(file_size)}.'
            }), 400
        
        # Check daily upload limit
        user_daily_usage = user_sessions[session_id]['daily_uploads']['total_bytes']
        remaining_daily_quota = DAILY_UPLOAD_LIMIT - user_daily_usage
        
        if file_size > remaining_daily_quota:
            return jsonify({
                'error': f'Daily upload limit exceeded. You have {format_file_size(remaining_daily_quota)} remaining today.'
            }), 400
        
        if file_size == 0:
            return jsonify({'error': 'File is empty'}), 400
        
        expiry_days = int(request.form.get('expiry_days', DEFAULT_EXPIRY_DAYS))
        expiry_days = max(1, min(30, expiry_days))
        
        # Generate unique file ID
        file_id = str(uuid.uuid4())[:8]
        filename = secure_filename(file.filename)
        unique_filename = f"{file_id}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Initialize progress tracking
        upload_progress[upload_id] = {
            'progress': 0, 
            'status': 'uploading', 
            'uploaded_bytes': 0, 
            'total_bytes': file_size
        }
        
        # Save file directly (Flask handles this efficiently)
        file.save(file_path)
        
        # Verify file was saved correctly
        if not os.path.exists(file_path):
            return jsonify({'error': 'Failed to save file'}), 500
            
        final_file_size = os.path.getsize(file_path)
        
        # Security scan
        upload_progress[upload_id]['status'] = 'scanning'
        upload_progress[upload_id]['progress'] = 90
        
        is_safe, message = scan_file_safety(file_path, filename)
        if not is_safe:
            if os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({'error': f'Security issue: {message}'}), 400
        
        # Update daily upload tracking
        user_sessions[session_id]['daily_uploads']['total_bytes'] += final_file_size
        user_sessions[session_id]['daily_uploads']['file_count'] += 1
        
        # Add to upload history
        user_sessions[session_id]['upload_history'].append({
            'file_id': file_id,
            'filename': filename,
            'size': final_file_size,
            'timestamp': datetime.datetime.now(),
            'expiry_days': expiry_days
        })
        
        # Keep only last 50 uploads in history
        if len(user_sessions[session_id]['upload_history']) > 50:
            user_sessions[session_id]['upload_history'] = user_sessions[session_id]['upload_history'][-50:]
        
        upload_progress[upload_id]['status'] = 'completed'
        upload_progress[upload_id]['progress'] = 100
        upload_progress[upload_id]['uploaded_bytes'] = final_file_size
            
    except Exception as e:
        if 'file_path' in locals() and os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500
    
    # Store file metadata
    expiry_time = datetime.datetime.now() + datetime.timedelta(days=expiry_days)
    
    file_data[file_id] = {
        'filename': unique_filename,
        'original_name': filename,
        'upload_time': datetime.datetime.now(),
        'expiry_time': expiry_time,
        'download_count': 0,
        'file_size': final_file_size,
        'session_id': session_id,
        'content_type': file.content_type or 'application/octet-stream',
        'expiry_days': expiry_days
    }
    
    # Update user session
    if session_id not in user_sessions:
        user_sessions[session_id] = {
            'files': [], 
            'created': datetime.datetime.now(), 
            'total_uploads': 0, 
            'total_downloads': 0, 
            'total_storage_used': 0,
            'daily_uploads': {
                'date': datetime.datetime.now().date().isoformat(),
                'total_bytes': final_file_size,
                'file_count': 1
            },
            'upload_history': []
        }
    
    user_sessions[session_id]['files'].append(file_id)
    user_sessions[session_id]['total_uploads'] += 1
    user_sessions[session_id]['total_storage_used'] += final_file_size
    user_sessions[session_id]['last_activity'] = datetime.datetime.now()
    
    download_link = url_for('download_file', file_id=file_id, _external=True)
    delete_link = url_for('delete_file', file_id=file_id, _external=True)
    
    # Get updated daily usage for response
    daily_used = user_sessions[session_id]['daily_uploads']['total_bytes']
    daily_remaining = DAILY_UPLOAD_LIMIT - daily_used
    
    # Cleanup progress data after 5 minutes
    threading.Timer(300, lambda: upload_progress.pop(upload_id, None)).start()
    
    return jsonify({
        'success': True,
        'download_link': download_link,
        'delete_link': delete_link,
        'file_id': file_id,
        'file_size': final_file_size,
        'file_size_formatted': format_file_size(final_file_size),
        'expiry_time': expiry_time.strftime('%Y-%m-%d at %H:%M'),
        'expiry_days': expiry_days,
        'upload_id': upload_id,
        'daily_usage': {
            'used': daily_used,
            'used_formatted': format_file_size(daily_used),
            'remaining': daily_remaining,
            'remaining_formatted': format_file_size(daily_remaining),
            'limit': DAILY_UPLOAD_LIMIT,
            'limit_formatted': format_file_size(DAILY_UPLOAD_LIMIT),
            'percentage_used': min(100, (daily_used / DAILY_UPLOAD_LIMIT) * 100)
        },
        'message': f'File uploaded successfully! Size: {format_file_size(final_file_size)}. Daily usage: {format_file_size(daily_used)}/{format_file_size(DAILY_UPLOAD_LIMIT)}'
    })

@app.route('/upload-progress/<upload_id>')
def get_upload_progress(upload_id):
    """Get upload progress for a specific upload"""
    progress = upload_progress.get(upload_id, {'progress': 0, 'status': 'unknown', 'uploaded_bytes': 0, 'total_bytes': 0})
    progress['uploaded_formatted'] = format_file_size(progress['uploaded_bytes'])
    progress['total_formatted'] = format_file_size(progress['total_bytes'])
    return jsonify(progress)

@app.route('/download/<file_id>')
def download_file(file_id):
    if file_id not in file_data:
        flash('File not found or expired', 'error')
        return redirect(url_for('index'))
    
    file_info = file_data[file_id]
    
    # Check if file has expired
    if datetime.datetime.now() > file_info['expiry_time']:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        del file_data[file_id]
        flash('File has expired', 'error')
        return redirect(url_for('index'))
    
    # Increment download count and update user stats
    file_data[file_id]['download_count'] += 1
    session_id = file_info['session_id']
    if session_id in user_sessions:
        user_sessions[session_id]['total_downloads'] += 1
        user_sessions[session_id]['last_activity'] = datetime.datetime.now()
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info['filename'])
    
    return send_file(file_path, 
                    as_attachment=True, 
                    download_name=file_info['original_name'],
                    mimetype=file_info['content_type'])

@app.route('/delete/<file_id>')
def delete_file(file_id):
    session_id = get_user_session()
    
    if file_id not in file_data:
        return jsonify({'error': 'File not found'}), 404
    
    # Check if user owns this file
    if file_data[file_id]['session_id'] != session_id:
        return jsonify({'error': 'You can only delete your own files'}), 403
    
    file_info = file_data[file_id]
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info['filename'])
    
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Remove from user sessions and update storage
        if session_id in user_sessions and file_id in user_sessions[session_id]['files']:
            user_sessions[session_id]['files'].remove(file_id)
            user_sessions[session_id]['total_storage_used'] -= file_info['file_size']
        
        del file_data[file_id]
        return jsonify({'success': True, 'message': 'File deleted successfully'})
    except Exception as e:
        return jsonify({'error': f'Error deleting file: {str(e)}'}), 500

@app.route('/my-files')
def my_files():
    """Show files uploaded by current user"""
    session_id = get_user_session()
    user_files = {}
    current_time = datetime.datetime.now()
    
    for file_id in get_user_files(session_id):
        if file_id in file_data:
            file_info = file_data[file_id]
            # Calculate time remaining
            time_remaining = file_info['expiry_time'] - current_time
            days_remaining = time_remaining.days
            hours_remaining = time_remaining.seconds // 3600
            minutes_remaining = (time_remaining.seconds % 3600) // 60
            
            if days_remaining > 0:
                time_remaining_str = f"{days_remaining}d {hours_remaining}h"
            else:
                time_remaining_str = f"{hours_remaining}h {minutes_remaining}m"
                
            file_info['time_remaining'] = time_remaining_str
            file_info['expiry_percentage'] = max(0, min(100, (1 - time_remaining.total_seconds() / 
                                        (file_info['expiry_days'] * 24 * 3600)) * 100))
            user_files[file_id] = file_info
    
    # Get daily quota info
    daily_uploads = user_sessions[session_id].get('daily_uploads', {'total_bytes': 0})
    daily_used = daily_uploads['total_bytes']
    daily_remaining = DAILY_UPLOAD_LIMIT - daily_used
    daily_percentage = min(100, (daily_used / DAILY_UPLOAD_LIMIT) * 100)
    
    user_stats = user_sessions.get(session_id, {})
    return render_template('my_files.html', 
                         files=user_files, 
                         session_id=session_id,
                         user_stats=user_stats,
                         current_time=current_time,
                         format_file_size=format_file_size,
                         daily_quota={
                             'used': daily_used,
                             'used_formatted': format_file_size(daily_used),
                             'remaining': daily_remaining,
                             'remaining_formatted': format_file_size(daily_remaining),
                             'limit': DAILY_UPLOAD_LIMIT,
                             'limit_formatted': format_file_size(DAILY_UPLOAD_LIMIT),
                             'percentage': daily_percentage
                         })

@app.route('/api/quota')
def get_quota_info():
    """API endpoint to get current user's quota information"""
    session_id = get_user_session()
    daily_uploads = user_sessions[session_id].get('daily_uploads', {'total_bytes': 0})
    daily_used = daily_uploads['total_bytes']
    daily_remaining = DAILY_UPLOAD_LIMIT - daily_used
    
    return jsonify({
        'daily_used': daily_used,
        'daily_used_formatted': format_file_size(daily_used),
        'daily_remaining': daily_remaining,
        'daily_remaining_formatted': format_file_size(daily_remaining),
        'daily_limit': DAILY_UPLOAD_LIMIT,
        'daily_limit_formatted': format_file_size(DAILY_UPLOAD_LIMIT),
        'percentage_used': min(100, (daily_used / DAILY_UPLOAD_LIMIT) * 100)
    })

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_login_required
def admin_dashboard():
    """Admin dashboard with comprehensive stats"""
    current_time = datetime.datetime.now()  # Add current_time
    
    total_files = len(file_data)
    total_storage = sum(f['file_size'] for f in file_data.values())
    total_uploads = sum(s.get('total_uploads', 0) for s in user_sessions.values())
    total_downloads = sum(s.get('total_downloads', 0) for s in user_sessions.values())
    active_sessions = len([s for s in user_sessions.values() 
                          if (current_time - s['last_activity']).total_seconds() < 3600])  # Active in last hour
    
    # Calculate daily quota usage across all users
    total_daily_usage = sum(s.get('daily_uploads', {}).get('total_bytes', 0) 
                           for s in user_sessions.values())
    
    # Users who have exceeded or are close to daily limit
    users_near_limit = []
    for session_id, session_data in user_sessions.items():
        daily_used = session_data.get('daily_uploads', {}).get('total_bytes', 0)
        if daily_used > 0:
            percentage = (daily_used / DAILY_UPLOAD_LIMIT) * 100
            if percentage > 50:  # Users using more than 50% of daily quota
                users_near_limit.append({
                    'session_id': session_id[:8],
                    'ip': session_data.get('ip', 'Unknown'),
                    'daily_used': daily_used,
                    'daily_used_formatted': format_file_size(daily_used),
                    'percentage': percentage,
                    'file_count': session_data.get('daily_uploads', {}).get('file_count', 0),
                    'last_activity': session_data.get('last_activity', 'Unknown')
                })
    
    # Sort by usage percentage (highest first)
    users_near_limit.sort(key=lambda x: x['percentage'], reverse=True)
    
    # Files uploaded today
    today = current_time.date()
    files_today = len([f for f in file_data.values() 
                      if f['upload_time'].date() == today])
    
    return render_template('admin_dashboard.html', 
                         total_files=total_files,
                         total_storage=format_file_size(total_storage),
                         total_uploads=total_uploads,
                         total_downloads=total_downloads,
                         active_sessions=active_sessions,
                         files_today=files_today,
                         total_daily_usage=format_file_size(total_daily_usage),
                         users_near_limit=users_near_limit,
                         daily_upload_limit=format_file_size(DAILY_UPLOAD_LIMIT),
                         user_sessions=user_sessions,
                         file_data=file_data,
                         admin_username=session.get('admin_username'),
                         format_file_size=format_file_size,
                         current_time=current_time)  # Pass current_time to template

@app.route('/admin/reset-quota/<session_id>')
@admin_login_required
def admin_reset_quota(session_id):
    """Admin function to reset a user's daily quota"""
    if session_id in user_sessions:
        user_sessions[session_id]['daily_uploads'] = {
            'date': datetime.datetime.now().date().isoformat(),
            'total_bytes': 0,
            'file_count': 0
        }
        flash(f'Daily quota reset for user {session_id[:8]}', 'success')
    else:
        flash('User not found', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/files')
@admin_login_required
def admin_files():
    """Admin view of all files"""
    current_time = datetime.datetime.now()
    
    # Sort files by upload time (newest first)
    sorted_files = sorted(file_data.items(), key=lambda x: x[1]['upload_time'], reverse=True)
    
    return render_template('admin_files.html',
                         files=dict(sorted_files),
                         current_time=current_time,
                         format_file_size=format_file_size,
                         admin_username=session.get('admin_username'))

@app.route('/admin/delete-file/<file_id>')
@admin_login_required
def admin_delete_file(file_id):
    """Admin function to delete any file"""
    if file_id not in file_data:
        flash('File not found', 'error')
        return redirect(url_for('admin_files'))
    
    file_info = file_data[file_id]
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info['filename'])
    
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Remove from user sessions
        session_id = file_info['session_id']
        if session_id in user_sessions and file_id in user_sessions[session_id]['files']:
            user_sessions[session_id]['files'].remove(file_id)
            user_sessions[session_id]['total_storage_used'] -= file_info['file_size']
        
        del file_data[file_id]
        flash('File deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'error')
    
    return redirect(url_for('admin_files'))

# Start cleanup thread
cleanup_thread = threading.Thread(target=clean_expired_files, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    print("🚀 Starting SecureFile Share App (2GB Max)")
    print("📁 Upload folder:", os.path.abspath(UPLOAD_FOLDER))
    print("💾 Max file size: 2GB")
    print("📊 Daily user limit: 2GB")
    print("⏰ Auto-delete: 7 days (configurable)")
    print("🔒 Admin login: /admin/login")
    print("   Username: admin, Password: admin123")
    print("⚡ Optimized for 2GB file uploads")
    print("📈 Daily quota tracking enabled")
    
    # Create upload directory if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        print("📂 Created upload directory")
    
    print("\n🌐 Server starting on http://localhost:5000")
    print("   - Max file size: 2GB")
    print("   - Daily user quota: 2GB")
    print("   - Security scanning enabled")
    print("   - Daily quota tracking active")
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=clean_expired_files, daemon=True)
    cleanup_thread.start()
    print("🧹 Cleanup thread started")
    
    # Run the server with optimized settings
    app.run(
        host='0.0.0.0', 
        port=5001, 
        debug=True, 
        threaded=True
    )