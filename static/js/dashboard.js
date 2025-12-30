// Dashboard JavaScript with real-time graphs and stress testing

let serverUptimeSeconds = 0;
let rpsChart, cpuChart;

document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    loadServerStatus();
    loadStats();
    loadRecentChecks();
    loadMetrics();

    // Refresh data
    setInterval(() => {
        loadServerStatus();
        loadStats();
        loadRecentChecks();
    }, 10000);

    // Update metrics and graphs every 2 seconds
    setInterval(loadMetrics, 2000);

    // Update uptime display every second
    setInterval(updateUptimeDisplay, 1000);
});

function initializeCharts() {
    // RPS Chart with dynamic scaling
    const rpsCtx = document.getElementById('rpsChart').getContext('2d');
    rpsChart = new Chart(rpsCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Requests/Second',
                data: [],
                borderColor: '#4CAF50',
                backgroundColor: 'rgba(76, 175, 80, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                y: { 
                    beginAtZero: true,
                    ticks: {
                        callback: function(value) {
                            return value.toFixed(1);
                        }
                    }
                },
                x: { display: false }
            },
            plugins: {
                legend: { display: false },
                title: { display: true, text: 'Requests Per Second' }
            }
        }
    });

    // CPU Chart with fixed 0-100% range
    const cpuCtx = document.getElementById('cpuChart').getContext('2d');
    cpuChart = new Chart(cpuCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'CPU Usage %',
                data: [],
                borderColor: '#2196F3',
                backgroundColor: 'rgba(33, 150, 243, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                y: { 
                    beginAtZero: true,
                    min: 0,
                    max: 100,
                    ticks: {
                        callback: function(value) {
                            return value + '%';
                        }
                    }
                },
                x: { display: false }
            },
            plugins: {
                legend: { display: false },
                title: { display: true, text: 'CPU Usage (%)' }
            }
        }
    });
}

async function loadServerStatus() {
    try {
        const response = await fetch('/health');
        const data = await response.json();

        const statusElement = document.getElementById('serverStatus');
        if (data.status === 'healthy') {
            statusElement.textContent = '✅ Healthy';
            statusElement.style.color = 'var(--success-color)';
            
            // Update server uptime from the response
            if (data.uptime_seconds !== undefined) {
                serverUptimeSeconds = data.uptime_seconds;
            }
        } else {
            statusElement.textContent = '❌ Unhealthy';
            statusElement.style.color = 'var(--danger-color)';
        }
        statusElement.classList.remove('loading');
    } catch (error) {
        const statusElement = document.getElementById('serverStatus');
        statusElement.textContent = '❌ Offline';
        statusElement.style.color = 'var(--danger-color)';
        statusElement.classList.remove('loading');
        console.error('Error loading server status:', error);
    }
}

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        // Update statistics
        document.getElementById('totalChecks').textContent = data.total_checks || 0;
        document.getElementById('safeUrls').textContent = data.safe_urls || 0;
        document.getElementById('threatsDetected').textContent = data.threats_detected || 0;
        document.getElementById('unknownDomains').textContent = data.unknown_domains || 0;

        // Update database info
        document.getElementById('knownDomains').textContent = data.known_domains || 0;
        document.getElementById('maliciousPatterns').textContent = data.malicious_patterns || 0;

        // Update security toggles
        updateBadge('patternMatching', data.pattern_matching_enabled);
        updateBadge('domainLookup', data.domain_lookup_enabled);

    } catch (error) {
        console.error('Error loading stats:', error);
        // Show default values if API not available
        displayMockStats();
    }
}

async function loadRecentChecks() {
    try {
        const response = await fetch('/api/recent-checks');
        const data = await response.json();

        const container = document.getElementById('recentChecks');
        
        if (data.checks && data.checks.length > 0) {
            container.innerHTML = data.checks.map(check => `
                <div class="check-item">
                    <span class="check-url">${escapeHtml(check.url)}</span>
                    <span class="check-time">${formatTime(check.timestamp)}</span>
                    <span class="badge ${getBadgeClass(check.status)}">${check.status}</span>
                </div>
            `).join('');
        } else {
            container.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 20px;">No recent checks available</p>';
        }
    } catch (error) {
        console.error('Error loading recent checks:', error);
        displayMockRecentChecks();
    }
}

async function loadMetrics() {
    try {
        const response = await fetch('/api/metrics');
        const data = await response.json();

        // Update current metrics
        document.getElementById('cpu').textContent = data.current.cpu + '%';
        document.getElementById('rps').textContent = data.current.rps.toFixed(1);

        // Update charts with history
        if (data.history && data.history.timestamps.length > 0) {
            const labels = data.history.timestamps.map((_, i) => i);
            
            rpsChart.data.labels = labels;
            rpsChart.data.datasets[0].data = data.history.requests_per_second;
            rpsChart.update('none');

            cpuChart.data.labels = labels;
            cpuChart.data.datasets[0].data = data.history.cpu_usage;
            cpuChart.update('none');
        }
    } catch (error) {
        console.error('Error loading metrics:', error);
    }
}

async function runStressTest(numRequests) {
    const resultDiv = document.getElementById('stressTestResult');
    resultDiv.innerHTML = `<p style="color: #2196F3;">⏳ Running ${numRequests.toLocaleString()} requests...</p>`;
    
    const buttons = document.querySelectorAll('.btn-test');
    buttons.forEach(btn => btn.disabled = true);

    try {
        const startTime = Date.now();
        const response = await fetch('/api/stress-test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ num_requests: numRequests })
        });
        
        const data = await response.json();
        const duration = Date.now() - startTime;

        resultDiv.innerHTML = `
            <div style="background: #f5f5f5; padding: 15px; border-radius: 8px; margin-top: 10px;">
                <p><strong>✅ Test Complete!</strong></p>
                <p>Requests: ${data.num_requests.toLocaleString()}</p>
                <p>Duration: ${data.duration_seconds}s</p>
                <p>Throughput: ${data.requests_per_second.toLocaleString()} req/s</p>
                <p>Success: ${data.success} | Errors: ${data.errors}</p>
            </div>
        `;
    } catch (error) {
        resultDiv.innerHTML = `<p style="color: #f44336;">❌ Error: ${error.message}</p>`;
    } finally {
        buttons.forEach(btn => btn.disabled = false);
    }
}

function updateUptimeDisplay() {
    // Increment local counter by 1 second
    serverUptimeSeconds += 1;
    
    const seconds = serverUptimeSeconds;
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    let uptimeText = '';
    if (days > 0) {
        uptimeText = `${days}d ${hours % 24}h ${minutes % 60}m`;
    } else if (hours > 0) {
        uptimeText = `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
        uptimeText = `${minutes}m ${seconds % 60}s`;
    } else {
        uptimeText = `${seconds}s`;
    }

    document.getElementById('uptime').textContent = uptimeText;
}

function updateBadge(elementId, enabled) {
    const element = document.getElementById(elementId);
    if (enabled) {
        element.textContent = '✅ Enabled';
        element.style.color = 'var(--success-color)';
        element.classList.add('badge-safe');
    } else {
        element.textContent = '❌ Disabled';
        element.style.color = 'var(--text-secondary)';
        element.classList.add('badge-unknown');
    }
}

function getBadgeClass(status) {
    const statusMap = {
        'safe': 'badge-safe',
        'threat': 'badge-malicious',
        'malicious': 'badge-malicious',
        'suspicious': 'badge-suspicious',
        'unknown': 'badge-unknown'
    };
    return statusMap[status?.toLowerCase()] || 'badge-unknown';
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (seconds < 60) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return date.toLocaleDateString();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Mock data functions for when API endpoints are not yet implemented
function displayMockStats() {
    document.getElementById('totalChecks').textContent = '-';
    document.getElementById('safeUrls').textContent = '-';
    document.getElementById('threatsDetected').textContent = '-';
    document.getElementById('unknownDomains').textContent = '-';
    document.getElementById('knownDomains').textContent = '8';
    document.getElementById('maliciousPatterns').textContent = '10';
    updateBadge('patternMatching', true);
    updateBadge('domainLookup', true);
}

function displayMockRecentChecks() {
    const container = document.getElementById('recentChecks');
    container.innerHTML = `
        <p style="color: var(--text-secondary); text-align: center; padding: 20px;">
            📊 Statistics endpoint not yet configured.<br>
            Recent checks will appear here once you start using the service.
        </p>
    `;
}
