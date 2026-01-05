// Main page JavaScript for URL checking

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('urlCheckForm');
    const urlInput = document.getElementById('urlInput');
    const checkButton = document.getElementById('checkButton');
    const resultsContainer = document.getElementById('results');
    const buttonText = checkButton.querySelector('.button-text');
    const loadingSpinner = checkButton.querySelector('.loading-spinner');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const url = urlInput.value.trim();
        if (!url) return;

        // Show loading state
        checkButton.disabled = true;
        buttonText.style.display = 'none';
        loadingSpinner.style.display = 'inline';
        resultsContainer.style.display = 'none';

        try {
            // Clean the URL and prepare for API call
            let cleanUrl = url;
            
            // Remove scheme if present for API call
            cleanUrl = cleanUrl.replace(/^https?:\/\//, '');
            
            // Make API request
            const response = await fetch(`/urlinfo/1/${cleanUrl}`);
            const data = await response.json();

            if (response.ok) {
                displayResults(data);
            } else {
                displayError(data.detail || 'An error occurred while checking the URL');
            }
        } catch (error) {
            displayError('Failed to connect to the server. Please try again.');
            console.error('Error:', error);
        } finally {
            // Reset button state
            checkButton.disabled = false;
            buttonText.style.display = 'inline';
            loadingSpinner.style.display = 'none';
        }
    });

    function displayResults(data) {
        // Determine decision and styling
        const decision = data.decision || 'UNKNOWN';
        const isAllowed = decision === 'ALLOW';
        
        const statusIcon = isAllowed ? '✅' : '🚫';
        const statusText = decision;
        const statusClass = isAllowed ? 'decision-allow' : 'decision-deny';
        const bannerClass = isAllowed ? 'success-banner' : 'danger-banner';

        let html = `
            <div class="result-card">
                <!-- Decision Banner -->
                <div class="decision-banner ${bannerClass}">
                    <div class="decision-icon">${statusIcon}</div>
                    <div class="decision-content">
                        <div class="decision-title">${statusText}</div>
                        ${data.reason ? `<div class="decision-reason">${escapeHtml(data.reason)}</div>` : 
                          '<div class="decision-reason">No threats detected - URL is safe to visit</div>'}
                    </div>
                </div>

                ${data.threat_detected ? `
                <!-- Threat Information -->
                <div class="threat-alert">
                    <h4>⚠️ Threat Information</h4>
                    <div class="threat-details">
                        <div class="threat-row">
                            <span class="threat-label">Type:</span>
                            <span class="threat-badge">${escapeHtml(data.threat_detected.type?.replace(/_/g, ' ').toUpperCase())}</span>
                        </div>
                        <div class="threat-row">
                            <span class="threat-label">Severity:</span>
                            <span class="severity-badge severity-${data.threat_detected.severity}">${data.threat_detected.severity?.toUpperCase()}</span>
                        </div>
                        <div class="threat-row">
                            <span class="threat-label">Description:</span>
                            <span class="threat-value">${escapeHtml(data.threat_detected.description)}</span>
                        </div>
                        ${data.threat_detected.pattern ? `
                        <div class="threat-row">
                            <span class="threat-label">Pattern:</span>
                            <span class="pattern-text">${escapeHtml(data.threat_detected.pattern)}</span>
                        </div>
                        ` : ''}
                    </div>
                </div>
                ` : ''}

                <!-- URL Information -->
                <div class="result-section">
                    <h4>🔍 URL Information</h4>
                    <div class="info-grid">
                        <div class="info-item">
                            <span class="info-label">URL</span>
                            <span class="info-value url-text">${escapeHtml(data.url)}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Hostname</span>
                            <span class="info-value">${escapeHtml(data.hostname || '-')}</span>
                        </div>
                    </div>
                </div>

                <!-- Security Checks -->
                ${data.security_checks ? `
                <div class="result-section">
                    <h4>🛡️ Security Checks</h4>
                    <div class="checks-grid">
                        <div class="check-item">
                            <div class="check-header">
                                <span class="check-icon">${data.security_checks.malicious_patterns?.found ? '❌' : '✅'}</span>
                                <span class="check-title">Malicious Patterns</span>
                            </div>
                            <div class="check-status ${data.security_checks.malicious_patterns?.found ? 'status-bad' : 'status-good'}">
                                ${data.security_checks.malicious_patterns?.found ? 'Detected' : 'Clean'}
                            </div>
                            ${data.security_checks.malicious_patterns?.found ? `
                            <div class="check-details">
                                <p><strong>Type:</strong> ${escapeHtml(data.security_checks.malicious_patterns.threat_type?.replace(/_/g, ' '))}</p>
                                <p><strong>Pattern:</strong> <code>${escapeHtml(data.security_checks.malicious_patterns.pattern)}</code></p>
                            </div>
                            ` : ''}
                        </div>
                        
                        <div class="check-item">
                            <div class="check-header">
                                <span class="check-icon">${getDomainIcon(data.security_checks.domain_reputation?.status)}</span>
                                <span class="check-title">Domain Reputation</span>
                            </div>
                            <div class="check-status ${getDomainStatusClass(data.security_checks.domain_reputation?.status)}">
                                ${(data.security_checks.domain_reputation?.status || 'unknown').toUpperCase()}
                            </div>
                            ${data.security_checks.domain_reputation?.description ? `
                            <div class="check-details">
                                <p>${escapeHtml(data.security_checks.domain_reputation.description)}</p>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
                ` : ''}
            </div>
        `;

        resultsContainer.innerHTML = html;
        resultsContainer.style.display = 'block';
        
        // Smooth scroll to results
        resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function displayError(message) {
        const html = `
            <div class="result-card">
                <div class="decision-banner danger-banner">
                    <div class="decision-icon">❌</div>
                    <div class="decision-content">
                        <div class="decision-title">ERROR</div>
                        <div class="decision-reason">${escapeHtml(typeof message === 'string' ? message : message.message || 'Unknown error')}</div>
                    </div>
                </div>
            </div>
        `;
        resultsContainer.innerHTML = html;
        resultsContainer.style.display = 'block';
    }

    function getDomainIcon(status) {
        if (status === 'safe') return '✅';
        if (status === 'malicious' || status === 'phishing' || status === 'blacklisted') return '❌';
        return '❓';
    }

    function getDomainStatusClass(status) {
        if (status === 'safe') return 'status-good';
        if (status === 'malicious' || status === 'phishing' || status === 'blacklisted') return 'status-bad';
        return 'status-neutral';
    }

    function getBadgeClass(status) {
        const statusMap = {
            'safe': 'badge-safe',
            'malicious': 'badge-malicious',
            'phishing': 'badge-malicious',
            'blacklisted': 'badge-malicious',
            'suspicious': 'badge-suspicious',
            'unknown': 'badge-unknown'
        };
        return statusMap[status?.toLowerCase()] || 'badge-unknown';
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Allow Enter key to submit
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            form.dispatchEvent(new Event('submit'));
        }
    });

    // Handle test prompt clicks
    document.querySelectorAll('.test-prompt').forEach(button => {
        button.addEventListener('click', () => {
            const url = button.getAttribute('data-url');
            urlInput.value = url;
            form.dispatchEvent(new Event('submit'));
        });
    });
});
