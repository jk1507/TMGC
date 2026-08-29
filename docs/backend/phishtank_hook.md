# backend/phishtank_hook.py - PhishTank Integration

Simple PhishTank integration hook.

## Functions

### `run_phishtank(domain, result)`
Run PhishTank check for a domain.

**Args:**
- `domain`: Domain to check
- `result`: Result dict to populate

**Populates:**
- `result["phishtank"]["pt_available"]`: True
- `result["phishtank"]["is_phishing"]`: False (default)

Note: This is a stub implementation. Full PhishTank integration is in `threat_intel.py`.
