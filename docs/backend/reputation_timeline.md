# backend/reputation_timeline.py - Reputation Timeline

Tracks analysis history and reputation changes for domains over time.

## Features
- Recording new analysis results
- Retrieving timeline for a specific domain
- Trend analysis (score changes over time)
- Recent analysis history

## Configuration

```python
TIMELINE_FILE = "reputation_timeline.json"
MAX_ENTRIES_PER_DOMAIN = 50
```

## Functions

### `record_analysis(domain, risk_score, verdict, metadata=None)`
Record a new analysis result for a domain.

**Args:**
- `domain`: The analyzed domain
- `risk_score`: Risk score (0-100)
- `verdict`: Verdict string (SAFE, SUSPICIOUS, PHISHING)
- `metadata`: Optional additional data

**Returns:** The recorded entry with timestamp

### `get_timeline(domain, limit=10)`
Get the analysis timeline for a domain.

**Returns dict with:**
- `domain`: Domain name
- `has_history`: bool
- `total_entries`: Number of entries
- `entries`: Recent entries
- `first_seen`: First analysis timestamp
- `last_seen`: Most recent timestamp
- `trend`: "increasing", "decreasing", or "stable"
- `min_score`: Minimum risk score
- `max_score`: Maximum risk score
- `avg_score`: Average risk score

## Internal Functions

### `_load_timeline()`
Load timeline data from JSON file.

### `_save_timeline(data)`
Save timeline data to JSON file.
