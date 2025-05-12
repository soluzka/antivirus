"""
Network Monitor Integration Module
----------------------------------
This module provides functions and endpoints to integrate network monitoring functionality
with the main application. It includes functions to get monitored network directories
and display network monitoring information in the dashboard.

To use this module:
1. Import the functions in app.py
2. Register the endpoint in your Flask app
"""
import os
import logging
from datetime import datetime
from flask import jsonify, Blueprint

# Create a blueprint for network monitoring endpoints
network_bp = Blueprint('network', __name__)

def get_monitored_network_directories(network_monitor):
    """
    Get the list of directories being monitored for network activity
    
    Args:
        network_monitor: Instance of the network monitor class
        
    Returns:
        Dictionary with monitored directories information
    """
    try:
        # Get timestamp for last scan
        last_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Define network monitored directories
        # These are common system directories that would be monitored for network activity
        monitored_dirs = [
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\drivers\\etc'),  # hosts file, DNS config
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\config'),  # registry files
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32\\wbem'),  # WMI
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'SysWOW64'),  # 32-bit system files
            os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),  # Startup programs
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Prefetch'),  # Prefetch files
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),  # User startup
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Local\\Temp'),  # Temporary files
            os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'Temp')  # System temp
        ]
        
        # Check if directories exist and are accessible
        directories = []
        for dir_path in monitored_dirs:
            exists = os.path.exists(dir_path)
            accessible = exists and os.access(dir_path, os.R_OK)
            
            # Count files if accessible
            file_count = 0
            if accessible:
                try:
                    # Count files in directory
                    file_count = len([f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))])
                except Exception:
                    pass
            
            directories.append({
                'path': dir_path,
                'exists': exists,
                'accessible': accessible,
                'file_count': file_count
            })
        
        # Create the response data
        data = {
            'success': True,
            'monitoring_status': {
                'enabled': network_monitor and hasattr(network_monitor, 'is_running') and network_monitor.is_running(),
                'last_scan': last_scan,
                'total_directories': len(directories),
                'directories': directories
            }
        }
        
        return data
    except Exception as e:
        logging.error(f"Error getting network monitored directories: {str(e)}")
        return {'success': False, 'error': str(e)}

@network_bp.route('/get_network_monitored_directories', methods=['GET'])
def get_network_monitored_directories_endpoint():
    """Flask endpoint to get network monitored directories"""
    from app import network_monitor
    data = get_monitored_network_directories(network_monitor)
    return jsonify(data)

def register_network_monitor_endpoints(app):
    """Register the network monitor blueprint with the Flask app"""
    app.register_blueprint(network_bp)
    
# Integration instructions
"""
To integrate this module with your main app.py, add the following code:

1. At the top of your app.py with other imports:
   from network_monitor_integration import register_network_monitor_endpoints

2. After your Flask app is initialized:
   register_network_monitor_endpoints(app)

This will register the /get_network_monitored_directories endpoint
with your Flask application.
"""

# CSS styles for network monitored directories display
network_directories_css = """
.network-monitored-directories {
    margin-top: 20px;
    padding: 10px;
    border-top: 1px solid #eee;
}

.monitoring-status {
    margin-bottom: 15px;
}

.monitoring-status .enabled {
    color: #27ae60;
    font-weight: bold;
}

.monitoring-status .disabled {
    color: #c0392b;
    font-weight: bold;
}

.directories-list {
    list-style-type: none;
    padding-left: 0;
    margin-top: 10px;
}

.directories-list li {
    padding: 5px;
    margin-bottom: 3px;
    border-left: 3px solid #eee;
    padding-left: 10px;
}

.directory-active {
    color: #27ae60;
    font-weight: bold;
    margin-right: 5px;
}

.directory-inactive {
    color: #e74c3c;
    font-weight: bold;
    margin-right: 5px;
}

.file-count {
    color: #7f8c8d;
    font-size: 0.9em;
}
"""

# JavaScript for fetching and displaying network monitored directories
network_directories_js = """
// Function to fetch monitored network directories
function fetchMonitoredNetworkDirectories() {
    fetch('/get_network_monitored_directories')
        .then(response => response.json())
        .then(data => {
            updateMonitoredDirectoriesDisplay(data);
        })
        .catch(error => {
            console.error('Error fetching monitored network directories:', error);
        });
}

// Function to display monitored directories
function updateMonitoredDirectoriesDisplay(data) {
    const directoriesContainer = document.getElementById('monitored_directories');
    if (!directoriesContainer) {
        // Create the container if it doesn't exist
        const networkCard = document.querySelector('.card');
        if (networkCard) {
            const newSection = document.createElement('div');
            newSection.className = 'network-monitored-directories';
            newSection.innerHTML = `
                <h4>Monitored Directories</h4>
                <div id="monitored_directories"></div>
            `;
            networkCard.appendChild(newSection);
            directoriesContainer = document.getElementById('monitored_directories');
        } else {
            return;
        }
    }
    
    // Clear previous contents
    directoriesContainer.innerHTML = '';
    
    // Display monitoring status
    if (data && data.success) {
        const status = data.monitoring_status;
        const statusDiv = document.createElement('div');
        statusDiv.className = 'monitoring-status';
        statusDiv.innerHTML = `
            <p><strong>Status:</strong> <span class="${status.enabled ? 'enabled' : 'disabled'}">${status.enabled ? 'ENABLED' : 'DISABLED'}</span></p>
            <p><strong>Last Scan:</strong> ${status.last_scan}</p>
            <p><strong>Total Monitored:</strong> ${status.total_directories} directories</p>
        `;
        directoriesContainer.appendChild(statusDiv);
        
        // Display directory list
        if (status.directories && status.directories.length > 0) {
            const list = document.createElement('ul');
            list.className = 'directories-list';
            
            status.directories.forEach(dir => {
                const li = document.createElement('li');
                const statusClass = dir.exists && dir.accessible ? 'directory-active' : 'directory-inactive';
                const statusIcon = dir.exists && dir.accessible ? '✓' : '⚠️';
                
                li.innerHTML = `<span class="${statusClass}">${statusIcon}</span> ${dir.path}`;
                
                // Add file count if available
                if (dir.file_count !== undefined) {
                    li.innerHTML += ` <span class="file-count">(${dir.file_count} files)</span>`;
                }
                
                list.appendChild(li);
            });
            
            directoriesContainer.appendChild(list);
        } else {
            directoriesContainer.innerHTML += '<p>No directories currently being monitored.</p>';
        }
    } else {
        directoriesContainer.innerHTML = '<p>Error loading monitored directories.</p>';
    }
}
"""

if __name__ == "__main__":
    print("This module is meant to be imported, not run directly.")
    print("See the integration instructions in the comments.")
