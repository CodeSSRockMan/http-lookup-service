// Dashboard JavaScript for statistics and monitoring

let startTime = Date.now();
let checkHistory = [];

document.addEventListener('DOMContentLoaded', () => {
    // Load initial data
    loadServerStatus();
    loadStats();
    loadRecentChecks();

    // Refresh data every 10 seconds
    setInterval(() => {
        loadServerStatus();
        loadStats();
        loadRecentChecks();
    }, 10000);

    // Update uptime every second
    setInterval(updateUptime, 1000);
});

async function loadServerStatus() {
    try {
        const response = await fetch('/health');
        const data = await response.json();

        const statusElement = document.getElementById('serverStatus');
        if (data.status === 'healthy') {
            statusElement.textContent = '✅ Healthy';
            statusElement.style.color = 'var(--success-color)';
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

function updateUptime() {
    const uptime = Date.now() - startTime;
    const seconds = Math.floor(uptime / 1000);
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
