"""
YARA Scanner Application

A standalone application that provides YARA scanning capabilities with a simple web interface.
This application is separate from the main Windows Defender clone app and has minimal dependencies.
"""

import os
import sys
import logging
import time
import json
import webbrowser
import threading
import shutil
from datetime import datetime
from flask import Flask, request, render_template, jsonify, send_from_directory, redirect, url_for
from werkzeug.utils import secure_filename
from security.yara_scanner import scan_file_with_yara, scan_all_folders_with_yara, load_yara_rules

# Import the main application for integration
# We use relative import to avoid circular imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    import app as main_app
    has_main_app = True
    # Only import folder_watcher from the main app if integration is available
    try:
        from app import FolderWatcher as MainFolderWatcher
        has_folder_watcher = True
    except ImportError:
        has_folder_watcher = False
except ImportError as e:
    logging.error(f"Could not import main app: {e}")
    has_main_app = False
    has_folder_watcher = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('yara_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('yara_scanner_app')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB upload limit

# Setup quarantine folder
QUARANTINE_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'quarantine')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

# Comprehensive monitored folders covering all common malware locations
DEFAULT_MONITORED_FOLDERS = [
    # User profile folders - common malware targets
    os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Pictures'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Videos'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Music'),
    
    # Temporary folders - often used by malware
    os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp'),
    os.path.join(os.environ.get('WINDIR', 'C:\Windows'), 'Temp'),
    
    # Startup locations - where persistence mechanisms are often installed
    os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    os.path.join(os.environ.get('PROGRAMDATA', 'C:\ProgramData'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
    
    # AppData locations - common for malware configuration and persistence
    os.path.join(os.environ.get('APPDATA', ''), 'Roaming'),
    os.path.join(os.environ.get('APPDATA', ''), 'Local'),
    os.path.join(os.environ.get('APPDATA', ''), 'LocalLow'),
    
    # Program Files and related locations
    os.path.join(os.environ.get('PROGRAMDATA', 'C:\ProgramData')),
    'C:\Program Files\Common Files',
    'C:\Program Files (x86)\Common Files',
    
    # Critical system locations targeted by sophisticated malware
    os.path.join(os.environ.get('WINDIR', 'C:\Windows'), 'System32'),
    os.path.join(os.environ.get('WINDIR', 'C:\Windows'), 'SysWOW64'),
    os.path.join(os.environ.get('WINDIR', 'C:\Windows'), 'Tasks'),
    
    # Registry backup files - sometimes contain malware code
    os.path.join(os.environ.get('WINDIR', 'C:\Windows'), 'System32', 'config'),
    
    # Recent files - often targeted by ransomware
    os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Recent'),
    
    # Prefetch files - can show evidence of malware execution
    os.path.join(os.environ.get('WINDIR', 'C:\Windows'), 'Prefetch'),
    
    # Downloads from browsers
    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'Downloads'),
    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Edge', 'User Data', 'Default', 'Downloads'),
    
    # USB drive autorun locations
    'C:\Autorun.inf'
]

@app.route('/')
def index():
    """Main dashboard page"""
    # Get YARA rules information
    rules = load_yara_rules()
    rules_info = {
        'count': len(rules) if rules else 0,
        'available': rules is not None and len(rules) > 0
    }
    
    # Get monitored folders
    folders = get_monitored_folders()
    
    return render_template('yara_scanner.html', 
                           rules_info=rules_info,
                           folders=folders)

@app.route('/templates/<path:path>')
def serve_template(path):
    """Serve template files"""
    return send_from_directory('templates', path)

@app.route('/static/<path:path>')
def serve_static(path):
    """Serve static files"""
    return send_from_directory('static', path)

@app.route('/scan', methods=['POST'])
def scan():
    """Scan a folder or file"""
    scan_type = request.form.get('scan_type', 'file')
    
    if scan_type == 'file':
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        # Save uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Scan file
        start_time = time.time()
        matches = scan_file_with_yara(file_path)
        scan_time = time.time() - start_time
        
        # Process results
        results = []
        if matches:
            for match in matches:
                rule_name = getattr(match, 'rule', 'Unknown rule')
                meta = getattr(match, 'meta', {})
                results.append({
                    'rule': rule_name,
                    'description': meta.get('description', 'No description'),
                    'file': file_path
                })
                
            # If suspicious, quarantine the file
            if results:
                detection_info = {
                    'matches': [r['rule'] for r in results],
                    'scan_time': f"{scan_time:.2f}s",
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                quarantine_file(file_path, detection_info)
                
        return jsonify({
            'file': file_path,
            'matches': len(results),
            'scan_time': f"{scan_time:.2f}s",
            'results': results,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    elif scan_type == 'folder':
        folder_path = request.form.get('folder_path', '')
        if not folder_path or not os.path.isdir(folder_path):
            return jsonify({'error': 'Invalid folder path'}), 400
            
        # Scan folder
        start_time = time.time()
        results = scan_all_folders_with_yara([folder_path])
        scan_time = time.time() - start_time
        
        return jsonify({
            'folder': folder_path,
            'matches': len(results),
            'scan_time': f"{scan_time:.2f}s",
            'results': results,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({'error': 'Invalid scan type'}), 400

def quarantine_file(file_path, detection_info):
    """Quarantine a suspicious file by moving it to the quarantine folder
    
    Args:
        file_path (str): Path to the suspicious file
        detection_info (dict): Information about the detection
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Check if the file exists
        if not os.path.exists(file_path):
            logger.error(f"Cannot quarantine non-existent file: {file_path}")
            return False
            
        # Create a unique filename in quarantine
        quarantine_filename = f"quarantined_{os.path.basename(file_path)}_{int(time.time())}"
        quarantine_path = os.path.join(QUARANTINE_FOLDER, quarantine_filename)
        
        # Log the quarantine action
        logger.warning(f"Quarantining suspicious file: {file_path}")
        
        # Ensure quarantine directory exists
        os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
        
        # Copy the file to quarantine (so we have a backup)
        try:
            shutil.copy2(file_path, quarantine_path)
            logger.info(f"File copied to quarantine: {quarantine_path}")
        except Exception as e:
            logger.error(f"Error copying file to quarantine: {e}")
            return False
        
        # Save detection info as JSON
        info_path = quarantine_path + ".json"
        with open(info_path, 'w') as f:
            json.dump({
                'original_path': file_path,
                'quarantine_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'detection_info': detection_info
            }, f, indent=2)
        
        # Try to delete the original file (optional)
        try:
            os.remove(file_path)
            logger.info(f"Deleted original suspicious file: {file_path}")
        except Exception as e:
            logger.error(f"Could not delete original file: {e}")
            # This is not a critical failure, we still have the file quarantined
        
        # If we have the main app integration available, try to add to its database
        if has_main_app:
            try:
                # Convert detection_info to a format compatible with the main app
                yara_results = detection_info.get('matches', [])
                if not isinstance(yara_results, list):
                    yara_results = [yara_results]
                    
                # Import needed modules only if available to avoid errors
                from app import app, db, ScanResult
                from datetime import datetime
                
                # Add to database within app context
                with app.app_context():
                    scan_result = ScanResult(
                        filepath=file_path,
                        result=json.dumps(yara_results),
                        timestamp=datetime.utcnow(),
                        quarantined=True,
                        quarantine_path=quarantine_path
                    )
                    db.session.add(scan_result)
                    db.session.commit()
                    logger.info(f"Added quarantine record to main database")
            except Exception as e:
                logger.error(f"Could not add to main database: {e}")
                # Non-critical error - we still have the file quarantined locally
        
        return True
    except Exception as e:
        logger.error(f"Error quarantining file: {e}")
        return False

@app.route('/scan_all', methods=['POST'])
def scan_all():
    """Scan all monitored folders"""
    folders = get_monitored_folders()
    
    # Scan all folders
    start_time = time.time()
    all_results = scan_all_folders_with_yara(folders)
    scan_time = time.time() - start_time
    
    # Handle any suspicious files
    for result in all_results:
        if isinstance(result, dict) and result.get('file') and result.get('matches'):
            # Attempt to quarantine suspicious file
            quarantine_file(result['file'], result)
    
    return jsonify({
        'folders': folders,
        'matches': len(all_results),
        'scan_time': f"{scan_time:.2f}s",
        'results': all_results,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

def get_monitored_folders():
    """Get list of monitored folders"""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'monitored_folders.json')
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading monitored folders: {e}")
    
    return DEFAULT_MONITORED_FOLDERS

def get_quarantined_files():
    """Get list of quarantined files with their detection info"""
    quarantined_files = []
    
    # Check if quarantine folder exists
    if not os.path.exists(QUARANTINE_FOLDER):
        return quarantined_files
    
    # Find all quarantined files (skip .json info files)
    for filename in os.listdir(QUARANTINE_FOLDER):
        if filename.endswith('.json'):
            continue
            
        file_path = os.path.join(QUARANTINE_FOLDER, filename)
        info_path = file_path + '.json'
        
        # Get detection info if available
        detection_info = {}
        if os.path.exists(info_path):
            try:
                with open(info_path, 'r') as f:
                    detection_info = json.load(f)
            except Exception as e:
                logger.error(f"Error loading detection info: {e}")
        
        quarantined_files.append({
            'filename': filename,
            'quarantine_path': file_path,
            'original_path': detection_info.get('original_path', 'Unknown'),
            'quarantine_time': detection_info.get('quarantine_time', 'Unknown'),
            'detection_info': detection_info.get('detection_info', {})
        })
    
    return sorted(quarantined_files, key=lambda x: x.get('quarantine_time', ''), reverse=True)

@app.route('/add_folder', methods=['POST'])
def add_folder():
    """Add a folder to monitored folders"""
    folder_path = request.form.get('folder_path', '')
    if not folder_path or not os.path.isdir(folder_path):
        return jsonify({'error': 'Invalid folder path'}), 400
        
    folders = get_monitored_folders()
    if folder_path not in folders:
        folders.append(folder_path)
        
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'monitored_folders.json')
    try:
        with open(config_path, 'w') as f:
            json.dump(folders, f)
    except Exception as e:
        logger.error(f"Error saving monitored folders: {e}")
        return jsonify({'error': f'Error saving folder: {e}'}), 500
        
    return jsonify({'success': True, 'folders': folders})

@app.route('/remove_folder', methods=['POST'])
def remove_folder():
    """Remove a folder from monitored folders"""
    folder_path = request.form.get('folder_path', '')
    folders = get_monitored_folders()
    
    if folder_path in folders:
        folders.remove(folder_path)
        
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'monitored_folders.json')
    try:
        with open(config_path, 'w') as f:
            json.dump(folders, f)
    except Exception as e:
        logger.error(f"Error saving monitored folders: {e}")
        return jsonify({'error': f'Error removing folder: {e}'}), 500
        
    return jsonify({'success': True, 'folders': folders})

@app.route('/quarantine')
def view_quarantine():
    """View quarantined files"""
    quarantined_files = get_quarantined_files()
    return render_template('quarantine.html', quarantined_files=quarantined_files)

@app.route('/restore_file', methods=['POST'])
def restore_file():
    """Restore a quarantined file to its original location"""
    file_path = request.form.get('file_path', '')
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'Invalid file path'}), 400
        
    # Get detection info
    info_path = file_path + '.json'
    original_path = ''
    
    if os.path.exists(info_path):
        try:
            with open(info_path, 'r') as f:
                detection_info = json.load(f)
                original_path = detection_info.get('original_path', '')
        except Exception as e:
            logger.error(f"Error loading detection info: {e}")
    
    # If no original path found, ask user for destination
    if not original_path:
        original_path = request.form.get('destination', '')
        
    if not original_path:
        return jsonify({'error': 'Original path not found. Please specify a destination.'}), 400
        
    # Create destination directory if it doesn't exist
    os.makedirs(os.path.dirname(original_path), exist_ok=True)
    
    # Restore file
    try:
        shutil.copy2(file_path, original_path)
        logger.info(f"Restored file to: {original_path}")
        return jsonify({'success': True, 'restored_to': original_path})
    except Exception as e:
        logger.error(f"Error restoring file: {e}")
        return jsonify({'error': f'Error restoring file: {e}'}), 500

@app.route('/delete_quarantined', methods=['POST'])
def delete_quarantined():
    """Permanently delete a quarantined file"""
    file_path = request.form.get('file_path', '')
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({'error': 'Invalid file path'}), 400
        
    # Delete the file and its info
    try:
        os.remove(file_path)
        logger.info(f"Deleted quarantined file: {file_path}")
        
        # Delete info file if it exists
        info_path = file_path + '.json'
        if os.path.exists(info_path):
            os.remove(info_path)
            
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({'error': f'Error deleting file: {e}'}), 500

# Create a simple template for the web interface
os.makedirs('templates', exist_ok=True)
with open(os.path.join('templates', 'yara_scanner.html'), 'w') as f:
    f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>YARA Scanner</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
        }
        .card {
            background-color: white;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="file"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 3px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 3px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        .folder-list {
            list-style-type: none;
            padding: 0;
        }
        .folder-list li {
            padding: 10px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
        }
        .results {
            margin-top: 20px;
        }
        .alert {
            padding: 15px;
            background-color: #f44336;
            color: white;
            margin-bottom: 15px;
            border-radius: 3px;
        }
        .success {
            background-color: #4CAF50;
        }
        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        .tab {
            overflow: hidden;
            border: 1px solid #ccc;
            background-color: #f1f1f1;
            border-radius: 3px 3px 0 0;
        }
        .tab button {
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            transition: 0.3s;
            color: #333;
        }
        .tab button:hover {
            background-color: #ddd;
        }
        .tab button.active {
            background-color: #4CAF50;
            color: white;
        }
        .tabcontent {
            display: none;
            padding: 20px;
            border: 1px solid #ccc;
            border-top: none;
            border-radius: 0 0 3px 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>YARA Scanner</h1>
        
        <div class="card">
            <h2>YARA Rules Status</h2>
            <p>Rules Available: <strong>{{ rules_info.available }}</strong></p>
            <p>Rules Count: <strong>{{ rules_info.count }}</strong></p>
        </div>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'FileScan')">File Scan</button>
            <button class="tablinks" onclick="openTab(event, 'FolderScan')">Folder Scan</button>
            <button class="tablinks" onclick="openTab(event, 'MonitoredFolders')">Monitored Folders</button>
        </div>
        
        <div id="FileScan" class="tabcontent" style="display: block;">
            <h2>Scan File</h2>
            <form id="fileScanForm">
                <div class="form-group">
                    <label for="file">Select File:</label>
                    <input type="file" id="file" name="file" required>
                </div>
                <button type="submit">Scan File</button>
            </form>
        </div>
        
        <div id="FolderScan" class="tabcontent">
            <h2>Scan Folder</h2>
            <form id="folderScanForm">
                <div class="form-group">
                    <label for="folder_path">Folder Path:</label>
                    <input type="text" id="folder_path" name="folder_path" required>
                </div>
                <button type="submit">Scan Folder</button>
            </form>
        </div>
        
        <div id="MonitoredFolders" class="tabcontent">
            <h2>Monitored Folders</h2>
            <ul class="folder-list">
                {% for folder in folders %}
                <li>
                    {{ folder }}
                    <button class="remove-folder" data-folder="{{ folder }}">Remove</button>
                </li>
                {% endfor %}
            </ul>
            
            <h3>Add Folder</h3>
            <form id="addFolderForm">
                <div class="form-group">
                    <label for="add_folder_path">Folder Path:</label>
                    <input type="text" id="add_folder_path" name="folder_path" required>
                </div>
                <button type="submit">Add Folder</button>
            </form>
            
            <h3>Scan All Monitored Folders</h3>
            <button id="scanAllBtn">Scan All Folders</button>
        </div>
        
        <div class="loading" id="loadingIndicator">
            <p>Scanning... Please wait.</p>
        </div>
        
        <div class="results" id="results"></div>
    </div>
    
    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
        
        document.getElementById("fileScanForm").addEventListener("submit", function(e) {
            e.preventDefault();
            var formData = new FormData();
            formData.append('scan_type', 'file');
            formData.append('file', document.getElementById('file').files[0]);
            
            document.getElementById('loadingIndicator').style.display = 'block';
            
            fetch('/scan', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                displayResults(data);
                document.getElementById('loadingIndicator').style.display = 'none';
            })
            .catch(error => {
                document.getElementById('results').innerHTML = `<div class="alert">Error: ${error}</div>`;
                document.getElementById('loadingIndicator').style.display = 'none';
            });
        });
        
        document.getElementById("folderScanForm").addEventListener("submit", function(e) {
            e.preventDefault();
            var formData = new FormData();
            formData.append('scan_type', 'folder');
            formData.append('folder_path', document.getElementById('folder_path').value);
            
            document.getElementById('loadingIndicator').style.display = 'block';
            
            fetch('/scan', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                displayResults(data);
                document.getElementById('loadingIndicator').style.display = 'none';
            })
            .catch(error => {
                document.getElementById('results').innerHTML = `<div class="alert">Error: ${error}</div>`;
                document.getElementById('loadingIndicator').style.display = 'none';
            });
        });
        
        document.getElementById("addFolderForm").addEventListener("submit", function(e) {
            e.preventDefault();
            var formData = new FormData();
            formData.append('folder_path', document.getElementById('add_folder_path').value);
            
            fetch('/add_folder', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    document.getElementById('results').innerHTML = `<div class="alert">Error: ${data.error}</div>`;
                }
            })
            .catch(error => {
                document.getElementById('results').innerHTML = `<div class="alert">Error: ${error}</div>`;
            });
        });
        
        document.querySelectorAll('.remove-folder').forEach(button => {
            button.addEventListener('click', function() {
                var folder = this.getAttribute('data-folder');
                var formData = new FormData();
                formData.append('folder_path', folder);
                
                fetch('/remove_folder', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        location.reload();
                    } else {
                        document.getElementById('results').innerHTML = `<div class="alert">Error: ${data.error}</div>`;
                    }
                })
                .catch(error => {
                    document.getElementById('results').innerHTML = `<div class="alert">Error: ${error}</div>`;
                });
            });
        });
        
        document.getElementById("scanAllBtn").addEventListener("click", function() {
            document.getElementById('loadingIndicator').style.display = 'block';
            
            fetch('/scan_all', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                displayResults(data);
                document.getElementById('loadingIndicator').style.display = 'none';
            })
            .catch(error => {
                document.getElementById('results').innerHTML = `<div class="alert">Error: ${error}</div>`;
                document.getElementById('loadingIndicator').style.display = 'none';
            });
        });
        
        function displayResults(data) {
            var resultsHtml = `
                <div class="card">
                    <h2>Scan Results</h2>
                    <p>Scan Time: ${data.scan_time}</p>
                    <p>Timestamp: ${data.timestamp}</p>
                    <p>Matches Found: ${data.matches}</p>
                `;
                
            if (data.file) {
                resultsHtml += `<p>File: ${data.file}</p>`;
            } else if (data.folder) {
                resultsHtml += `<p>Folder: ${data.folder}</p>`;
            } else if (data.folders) {
                resultsHtml += `<p>Folders: ${data.folders.join(', ')}</p>`;
            }
            
            if (data.results && data.results.length > 0) {
                resultsHtml += `
                    <h3>Matches</h3>
                    <ul>
                `;
                
                data.results.forEach(result => {
                    if (result.rule) {
                        resultsHtml += `<li>Rule: ${result.rule}, Description: ${result.description}, File: ${result.file}</li>`;
                    } else {
                        resultsHtml += `<li>${result}</li>`;
                    }
                });
                
                resultsHtml += `</ul>`;
            } else {
                resultsHtml += `<p>No suspicious files found.</p>`;
            }
            
            resultsHtml += `</div>`;
            
            document.getElementById('results').innerHTML = resultsHtml;
        }
    </script>
</body>
</html>
    """)

# Proxy route for main app's endpoints
@app.route('/proxy/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy_to_main_app(path):
    """Proxy requests to the main app if available"""
    if not has_main_app:
        return jsonify({"error": "Main application not available"}), 404
    
    # This is a simplified proxy implementation
    # In a real-world scenario, you might use a more robust proxy solution
    try:
        # Get the handler from the main app
        handler = getattr(main_app, path, None)
        if handler and callable(handler):
            return handler()
        else:
            return jsonify({"error": f"Handler {path} not found"}), 404
    except Exception as e:
        return jsonify({"error": f"Error proxying to main app: {e}"}), 500

# Serve the main app's static files
@app.route('/static_main/<path:path>')
def serve_main_static(path):
    """Serve static files from the main app"""
    main_static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    return send_from_directory(main_static_folder, path)

if __name__ == '__main__':
    print("Initializing YARA Scanner Application...")
    
    # Create upload folder
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Create templates folder
    os.makedirs('templates', exist_ok=True)
    
    # Load YARA rules
    rules = load_yara_rules()
    if rules:
        print(f"Successfully loaded {len(rules)} YARA rule sets")
    else:
        print("No YARA rules loaded")
    
    # Initialize main app if available
    if has_main_app:
        print("Main antivirus application integrated!")
        print("You can access all main app features from the YARA scanner interface.")
    else:
        print("WARNING: Main application integration not available.")
        print("Only YARA scanning features will be accessible.")
    
    # Create quarantine directory if it doesn't exist
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
    
    # Open browser to the web interface
    webbrowser.open('http://localhost:5001/yara_scanner.html')
    
    # Start scanner in separate thread if we have access to main app's folder watcher
    if has_folder_watcher and has_main_app:
        try:
            # Start folder monitoring in background thread using the main app's folder watcher
            logger.info("Starting folder monitoring using main application's watcher")
            monitored_dirs = get_monitored_folders()
            watcher_thread = threading.Thread(
                target=lambda: MainFolderWatcher(monitored_dirs).start(),
                daemon=True
            )
            watcher_thread.start()
        except Exception as e:
            logger.error(f"Could not start folder watcher: {e}")
    
    # Run the application
    app.run(host='localhost', port=5001, debug=False, threaded=True)
