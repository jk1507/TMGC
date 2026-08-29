# backend/external_hooks.py - External Hook Integrations

Simple integration point for external threat intel hooks.

## Functions

### `run_external_scans(domain, result)`
Run all external scan hooks for a domain.

**Args:**
- `domain`: Domain to scan
- `result`: Result dict to populate

**Currently runs:**
- PhishTank check (via phishtank_hook)
