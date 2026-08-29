# browser_extension/ - Browser Extension

Chrome extension for quick domain threat analysis.

## Files

### `manifest.json`
Extension manifest (Manifest V3).

**Permissions:**
- activeTab
- storage
- contextMenus

**Host Permissions:**
- <all_urls>

### `background.js`
Service worker for background tasks.
- Context menu integration
- Message passing

### `content.js`
Content script injected into web pages.
- DOM analysis
- Phishing indicator detection

### `popup.html`
Extension popup UI.
- Quick domain check input
- Results display

### `popup.js`
Popup logic.
- API communication
- Result rendering

## Features
- Right-click context menu for quick scans
- Popup for manual domain input
- Displays risk score and findings
- Links to full dashboard
