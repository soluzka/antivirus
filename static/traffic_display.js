/**
 * Network traffic monitoring display functions
 */

// Update traffic statistics display
function updateTrafficDisplay(trafficData, c2Data) {
    const trafficContainer = document.getElementById('traffic_stats');
    if (!trafficContainer) return;
    
    // Clear the "will appear here" message
    if (trafficContainer.innerText.includes('appear here when')) {
        trafficContainer.innerHTML = '';
    }

    // Format bytes to KB/MB/GB
    const formatBytes = (bytes) => {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB';
        return (bytes / 1073741824).toFixed(2) + ' GB';
    };

    // Create container for statistics if it doesn't exist
    if (!document.getElementById('traffic_content')) {
        const contentDiv = document.createElement('div');
        contentDiv.id = 'traffic_content';
        trafficContainer.appendChild(contentDiv);
    }

    // Build HTML content
    const trafficContent = document.getElementById('traffic_content');
    
    // Return if no traffic data available
    if (!trafficData || trafficData.error) {
        trafficContent.innerHTML = `
            <div class="alert alert-info">
                ${trafficData && trafficData.error ? 'Error: ' + trafficData.error : 'No traffic data available yet. Monitoring is initializing...'}
            </div>`;
        return;
    }

    // Format timestamp
    const timestamp = trafficData.timestamp ? new Date(trafficData.timestamp * 1000).toLocaleString() : 'N/A';
    
    // Build statistics HTML
    let html = `
        <div style="margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #eee;">
            <h4>Connection Summary</h4>
            <div style="display: flex; flex-wrap: wrap; gap: 15px;">
                <div style="flex: 1; min-width: 150px;">
                    <strong>Total Connections:</strong> ${trafficData.total_connections || 0}
                </div>
                <div style="flex: 1; min-width: 150px;">
                    <strong>Inbound Traffic:</strong> ${formatBytes(trafficData.inbound || 0)}
                </div>
                <div style="flex: 1; min-width: 150px;">
                    <strong>Outbound Traffic:</strong> ${formatBytes(trafficData.outbound || 0)}
                </div>
                <div style="flex: 1; min-width: 150px;">
                    <strong>Last Updated:</strong> ${timestamp}
                </div>
            </div>
        </div>`;

    // Active IP addresses
    if (trafficData.active_ips && trafficData.active_ips.length > 0) {
        html += `
            <div style="margin-bottom: 15px;">
                <h4>Active IP Connections (${trafficData.active_ips.length})</h4>
                <div style="max-height: 150px; overflow-y: auto; padding: 5px; background: #f8f8f8; border-radius: 4px;">`;
        
        trafficData.active_ips.forEach(ip => {
            html += `<div style="margin: 3px 0; padding: 2px 5px;">${ip}</div>`;
        });
        
        html += `</div></div>`;
    }

    // Protocol breakdown
    if (trafficData.protocols && Object.keys(trafficData.protocols).length > 0) {
        html += `
            <div style="margin-bottom: 15px;">
                <h4>Protocol Breakdown</h4>
                <div style="display: flex; flex-wrap: wrap; gap: 10px;">`;
        
        for (const [protocol, count] of Object.entries(trafficData.protocols)) {
            html += `
                <div style="flex: 1; min-width: 100px; padding: 8px; background: #f0f0f0; border-radius: 4px; text-align: center;">
                    <strong>${protocol}:</strong> ${count}
                </div>`;
        }
        
        html += `</div></div>`;
    }

    // Process information
    if (trafficData.processes && Object.keys(trafficData.processes).length > 0) {
        html += `
            <div style="margin-bottom: 15px;">
                <h4>Process Network Activity</h4>
                <div style="max-height: 200px; overflow-y: auto;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <thead>
                            <tr style="background: #f0f0f0;">
                                <th style="text-align: left; padding: 8px;">Process</th>
                                <th style="text-align: center; padding: 8px;">Connections</th>
                            </tr>
                        </thead>
                        <tbody>`;
        
        for (const [process, data] of Object.entries(trafficData.processes)) {
            html += `
                <tr style="border-bottom: 1px solid #eee;">
                    <td style="padding: 8px;">${process}</td>
                    <td style="text-align: center; padding: 8px;">${data.connections || 0}</td>
                </tr>`;
        }
        
        html += `</tbody></table></div></div>`;
    }

    // Display C2 detection information if available
    if (c2Data && !c2Data.error) {
        if (c2Data.suspicious_connections && c2Data.suspicious_connections.length > 0) {
            html += `
                <div style="margin-top: 20px; border-top: 1px solid #eee; padding-top: 15px;">
                    <h4 style="color: #e74c3c;">Suspicious Connection Alerts</h4>
                    <div style="max-height: 200px; overflow-y: auto;">`;
            
            c2Data.suspicious_connections.forEach(conn => {
                html += `
                    <div style="margin: 8px 0; padding: 8px; background: #fff3f3; border-left: 3px solid #e74c3c; border-radius: 4px;">
                        <div><strong>Process:</strong> ${conn.process} (PID: ${conn.pid})</div>
                        <div><strong>Remote:</strong> ${conn.remote_ip}:${conn.remote_port}</div>
                        <div><strong>Reason:</strong> <span style="color: #e74c3c;">${conn.reason}</span></div>
                    </div>`;
            });
            
            html += `</div></div>`;
        }
    }

    // Update the content
    trafficContent.innerHTML = html;
}

// Function to fetch traffic statistics from the API
function updateTrafficStats() {
    Promise.all([
        fetch('/get_traffic_stats'),
        fetch('/get_c2_patterns')
    ])
    .then(responses => Promise.all(responses.map(r => r.json())))
    .then(([trafficData, c2Data]) => {
        updateTrafficDisplay(trafficData, c2Data);
    })
    .catch(error => {
        console.error('Error fetching traffic stats:', error);
        const trafficContent = document.getElementById('traffic_content') || document.getElementById('traffic_stats');
        if (trafficContent) {
            trafficContent.innerHTML = `
                <div class="alert alert-warning">
                    Error retrieving traffic statistics: ${error.message || 'Unknown error'}
                </div>`;
        }
    });
}

// Function to start traffic monitoring
function startTrafficMonitoring() {
    fetch('/start_traffic_monitoring', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        console.log('Traffic monitoring started:', data);
    })
    .catch(error => {
        console.error('Error starting traffic monitoring:', error);
    });

    // Start updating traffic stats
    updateTrafficStats();
    
    // Set up interval to update stats every 3 seconds
    window.trafficStatsInterval = setInterval(updateTrafficStats, 3000);
}

// Start traffic monitoring when page loads
document.addEventListener('DOMContentLoaded', function() {
    startTrafficMonitoring();
});
