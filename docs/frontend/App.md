# front_end/App.jsx - Main React Application

Primary React component for the RETRO_INTEL frontend.

## Features
- User authentication (login/signup)
- Domain analysis with real-time logging
- AI-powered threat analysis
- Export to Excel, PDF, Markdown, TXT
- Responsive dashboard with multiple views

## State Variables

| Variable | Type | Description |
|----------|------|-------------|
| target | string | Domain to analyze |
| user | object | Authenticated user data |
| logs | array | Pipeline execution logs |
| result | object | Analysis results |
| loading | bool | Analysis in progress |
| error | string | Error message |
| activeTab | string | Current raw data tab |
| currentView | string | Current dashboard view |
| aiReport | object | AI analysis report |
| deepScan | bool | Deep scan enabled |
| scanMeta | object | Scan timing metadata |

## Functions

### `analyze()`
Main analysis function.
1. Sends POST to `/api/v1/analyze`
2. Displays pipeline logs with animation
3. Stores result and auto-triggers AI analysis

### `runAIAnalysis()`
Fetch AI-powered threat analysis.
1. Sends POST to `/api/v1/ai-analysis`
2. Displays contextual threat reasoning

### `exportExcel()`
Export analysis to Excel workbook.
- Executive Summary sheet
- Security Headers sheet
- ML Analysis sheet
- Findings sheet
- Raw Evidence sheet
- AI Analysis sheet

### `exportPdf()`
Export to PDF forensic dossier.
- Black background with green terminal theme
- Keyword highlighting for threats

### `exportMarkdown()`
Export to Markdown report.

### `exportRawTxt()`
Export raw terminal dump.

### `shareReport()`
Share report via Web Share API or clipboard.

## Components

### `AuthScreen`
Login/signup form with:
- Email/password validation
- SHA-256 password hashing
- Session token generation
- localStorage persistence

### `AuthInput`
Reusable form input component.

### `normalizeResult(result)`
Normalize backend response to frontend format.

### `defaultHeaderRows()`
Default security header rows.

### `normalizeHeaderRow(header)`
Normalize header row data.

## Navigation Items
- Dashboard
- Threat Analysis
- Domain Intelligence
- IP & Network
- WHOIS Lookup
- SSL/TLS Analysis
- DNS Records
- Content Analysis
- Reputation Lookup
- Entity Attribution
- Brand Impersonation
- Reports
- Saved Scans
- Settings
