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
        const isSafe = !data.malicious_patterns?.found && 
                      (data.lookup_result?.status === 'safe' || data.lookup_result?.status === 'unknown');
        
        const statusIcon = isSafe ? '✅' : '⚠️';
        const statusText = isSafe ? 'Safe' : 'Threat Detected';
        const statusClass = isSafe ? 'badge-safe' : 'badge-malicious';

        let html = `
            <div class="result-card">
                <div class="result-header">
                    <div class="status-icon">${statusIcon}</div>
                    <div class="result-title">
                        <h3>${statusText}</h3>
                        <div class="result-url">${escapeHtml(data.url)}</div>
                    </div>
                </div>

                <!-- Domain Information -->
                <div class="result-section">
                    <h4>🌐 Domain Information</h4>
                    <div class="info-grid">
                        <div class="info-item">
                            <span class="info-label">Hostname</span>
                            <span class="info-value">${escapeHtml(data.lookup_result?.hostname || '-')}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Reputation</span>
                            <span class="info-value">
                                <span class="badge ${getBadgeClass(data.lookup_result?.status)}">
                                    ${data.lookup_result?.status?.toUpperCase() || 'UNKNOWN'}
                                </span>
                            </span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Database</span>
                            <span class="info-value">${data.lookup_result?.found ? '✅ Found' : '❌ Not Found'}</span>
                        </div>
                    </div>
                    ${data.lookup_result?.description ? `
                        <div style="margin-top: 15px; padding: 15px; background: white; border-radius: 8px;">
                            <strong>Details:</strong> ${escapeHtml(data.lookup_result.description)}
                        </div>
                    ` : ''}
                </div>

                <!-- Malicious Patterns -->
                <div class="result-section">
                    <h4>🛡️ Security Check</h4>
                    ${data.malicious_patterns?.found ? `
                        <div class="threat-alert">
                            <h5>⚠️ Malicious Pattern Detected</h5>
                            <div class="threat-details">
                                <p><strong>Pattern:</strong> ${escapeHtml(data.malicious_patterns.pattern)}</p>
                                <p><strong>Type:</strong> ${escapeHtml(data.malicious_patterns.threat_type?.toUpperCase())}</p>
                                <p><strong>Category:</strong> ${escapeHtml(data.malicious_patterns.pattern_type)}</p>
                                <p><strong>Description:</strong> ${escapeHtml(data.malicious_patterns.description)}</p>
                            </div>
                        </div>
                    ` : `
                        <div style="padding: 15px; background: rgba(52, 168, 83, 0.1); border-radius: 8px; color: var(--success-color);">
                            <strong>✅ No malicious patterns detected</strong>
                            <p style="margin-top: 8px; opacity: 0.8;">This URL passed all security checks.</p>
                        </div>
                    `}
                </div>

                ${data.lookup_result?.last_updated ? `
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-color); color: var(--text-secondary); font-size: 13px;">
                        Last updated: ${new Date(data.lookup_result.last_updated).toLocaleString()}
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
                <div class="result-header">
                    <div class="status-icon">❌</div>
                    <div class="result-title">
                        <h3>Error</h3>
                    </div>
                </div>
                <div class="result-section">
                    <p style="color: var(--danger-color);">${escapeHtml(typeof message === 'string' ? message : message.message || 'Unknown error')}</p>
                </div>
            </div>
        `;
        resultsContainer.innerHTML = html;
        resultsContainer.style.display = 'block';
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
});
