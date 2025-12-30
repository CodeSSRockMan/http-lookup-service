# Frontend Documentation

## Overview

The HTTP Lookup Service includes a modern web interface with two main pages:
- **Search Page** (`/`) - Google-like URL checker
- **Dashboard** (`/dashboard`) - Real-time statistics and monitoring

## Pages

### 1. Search Page (`/`)

A clean, intuitive interface for checking URLs:

**Features:**
- 🔍 Google-like search bar
- Real-time URL validation
- Color-coded threat levels
- Detailed security analysis
- Domain reputation display
- Malicious pattern detection

**Usage:**
1. Enter a URL (with or without `http://`)
2. Click "Check URL" or press Enter
3. View detailed results with:
   - Domain reputation status
   - Malicious pattern detection
   - Security check summary
   - Last updated timestamp

**Example URLs to try:**
- `example.com` - Safe domain
- `malicious-site.com` - Known malicious domain
- `example.com/search?q=<script>alert(1)</script>` - XSS pattern
- `example.com/files/../../etc/passwd` - Path traversal

### 2. Dashboard (`/dashboard`)

Real-time monitoring and statistics:

**Features:**
- 🖥️ Server status (health, uptime, version)
- 📈 Live statistics
  - Total checks performed
  - Safe URLs detected
  - Threats detected
  - Unknown domains checked
- 💾 Database information
  - Known domains count
  - Malicious patterns count
  - Pattern matching status
  - Domain lookup status
- 🕐 Recent checks (last 10 URLs)
- Auto-refresh every 10 seconds

## Navigation

Both pages include a navigation bar with links to:
- 🔍 **Search** - Go to main search page
- 📊 **Dashboard** - View statistics
- 📖 **API Docs** - FastAPI automatic docs

## Design

**Visual Style:**
- Beautiful purple gradient background
- Clean white content cards
- Smooth animations and transitions
- Color-coded status badges:
  - ✅ Green - Safe
  - ⚠️ Red - Malicious/Threat
  - 🟡 Yellow - Suspicious
  - ⚪ Gray - Unknown

**Responsive:**
- Works on desktop, tablet, and mobile
- Adaptive grid layouts
- Touch-friendly buttons

## API Endpoints Used

The frontend communicates with these backend endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/urlinfo/1/{url}` | GET | Check URL for threats |
| `/health` | GET | Server health status |
| `/api/stats` | GET | Get service statistics |
| `/api/recent-checks` | GET | Get recent URL checks |

## Statistics Tracking

The service tracks:
- **Total Checks** - Number of URLs checked
- **Safe URLs** - Clean URLs with no threats
- **Threats Detected** - URLs with malicious patterns or bad reputation
- **Unknown Domains** - Domains not in database

**Note:** Statistics are stored in memory and reset on server restart. For production, use a persistent storage solution.

## Configuration

Frontend is controlled via `config.yaml`:

```yaml
frontend:
  enabled: true              # Enable/disable frontend
  static_dir: "static"       # Static files directory
  endpoints:
    home: "/"                # Search page
    dashboard: "/dashboard"  # Dashboard page
    api_docs: "/docs"        # API documentation
    health: "/health"        # Health check
    stats: "/api/stats"      # Statistics API
    recent_checks: "/api/recent-checks"  # Recent checks API
```

To disable the frontend:
```yaml
frontend:
  enabled: false
```

## Development

### File Structure

```
static/
├── index.html          # Search page
├── dashboard.html      # Dashboard page
├── css/
│   └── style.css       # All styles
└── js/
    ├── main.js         # Search page logic
    └── dashboard.js    # Dashboard logic
```

### Customization

**Change Colors:**
Edit CSS variables in `static/css/style.css`:
```css
:root {
    --primary-color: #4285f4;      /* Blue */
    --success-color: #34a853;      /* Green */
    --warning-color: #fbbc04;      /* Yellow */
    --danger-color: #ea4335;       /* Red */
}
```

**Change Refresh Rate:**
Edit `static/js/dashboard.js`:
```javascript
// Refresh data every 10 seconds
setInterval(() => {
    loadServerStatus();
    loadStats();
    loadRecentChecks();
}, 10000);  // Change this value (in milliseconds)
```

**Add More Statistics:**
1. Update `stats` dict in `main.py`
2. Add new endpoint in `main.py`
3. Update `dashboard.js` to fetch and display

## Browser Compatibility

Tested and works on:
- ✅ Chrome/Edge (latest)
- ✅ Firefox (latest)
- ✅ Safari (latest)
- ✅ Mobile browsers

## Accessibility

- Semantic HTML
- ARIA labels where needed
- Keyboard navigation support
- High contrast colors
- Responsive text sizes

## Performance

- Minimal JavaScript (vanilla JS, no frameworks)
- CSS animations hardware-accelerated
- Lazy loading of images (if added)
- Optimized for fast loading

## Screenshots

### Search Page
- Clean Google-like search interface
- Real-time results with detailed analysis
- Color-coded threat indicators

### Dashboard
- Live server statistics
- Recent checks timeline
- Database status monitoring

## Troubleshooting

**Frontend not loading:**
1. Check `config.yaml` - ensure `frontend.enabled: true`
2. Verify `static/` directory exists
3. Check server logs for errors

**Styles not applying:**
1. Clear browser cache
2. Check browser console for CSS errors
3. Verify `/static/css/style.css` is accessible

**Dashboard not updating:**
1. Check browser console for JavaScript errors
2. Verify API endpoints are accessible
3. Check network tab for failed requests

---

**Last Updated:** 2025-12-22  
**Version:** 1.0.0
