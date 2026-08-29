# backend/continuous_learning.py - Continuous Learning Pipeline

Online training and incremental learning for anti-phishing models.

## Features
- Live threat feed integration for training data
- User feedback incorporation
- Automated retraining triggers
- Model drift detection
- Validation workflow

## Data Classes

### `FeedbackEntry`
User feedback on a scan result (timestamp, domain, verdict, score).

### `TrainingRun`
Record of a training run (accuracy, precision, recall, F1).

### `DriftReport`
Model drift detection report.

### `PipelineStatus`
Overall pipeline status with metrics.

## Functions

### `add_feedback(domain, user_verdict, scan_score, notes="", features=None)`
Record user feedback on a scan result.

**Args:**
- `domain`: The scanned domain
- `user_verdict`: "phishing", "legitimate", or "suspicious"
- `scan_score`: System's risk score
- `notes`: Optional user notes
- `features`: Feature vector from the scan

### `get_feedback(limit=100)`
Retrieve recent feedback entries.

### `train_model(force=False)`
Train or retrain the phishing detection model.

**Triggers:**
- Enough new feedback samples (>=50)
- Drift detected
- Force=True

**Returns training metrics:**
- accuracy, precision, recall, F1
- model_version, samples_used

### `detect_drift()`
Check for model performance drift.

**Compares:**
- Current accuracy vs threshold (0.85)
- Current F1 vs threshold (0.80)

### `get_pipeline_status()`
Get overall pipeline status including:
- feedback_count, training_runs
- last_training, last_drift_check
- drift_detected, pending_retrain

### `submit_feedback_and_check_retrain(domain, verdict, score, features=None)`
Submit feedback and check if retrain is needed.

## Configuration

```python
DRIFT_ACCURACY_THRESHOLD = 0.85
DRIFT_F1_THRESHOLD = 0.80
MIN_SAMPLES_FOR_RETRAIN = 50
RETRAIN_INTERVAL_HOURS = 24
```
