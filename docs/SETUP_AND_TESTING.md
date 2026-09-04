# 🚀 RETRO_INTEL Setup & Testing Guide

## Prerequisites

- Python 3.10+
- Node.js 18+
- npm or yarn

## 1. Backend Setup

### Install Python Dependencies

```bash
cd backend

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install PyTorch Geometric (for GNN)
pip install torch_geometric torch_scatter torch_sparse torch_cluster torch_spline_conv
```

### Download BERT Models

The BERT models will be downloaded automatically on first use. To pre-download:

```python
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Email phishing model
AutoTokenizer.from_pretrained("limnegri/bert-phishing-emails")
AutoModelForSequenceClassification.from_pretrained("limnegri/bert-phishing-emails")

# SMS phishing model
AutoTokenizer.from_pretrained("mariagrazia/bert-sms-phishing")
AutoModelForSequenceClassification.from_pretrained("mariagrazia/bert-sms-phishing")
```

### Start Backend Server

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at: http://localhost:8000

## 2. Frontend Setup

### Install Node Dependencies

```bash
cd front_end
npm install
```

### Start Frontend Development Server

```bash
npm run dev
```

The frontend will be available at: http://localhost:5173

## 3. Testing New Features

### Test BERT Email Phishing Analysis

**API Test:**
```bash
curl -X POST http://localhost:8000/api/v1/bert-analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Dear customer, your account has been suspended. Click here to verify your identity immediately.", "model_type": "email"}'
```

**Expected Response:**
```json
{
  "available": true,
  "score": 85.5,
  "confidence": 72.3,
  "verdict": "phishing",
  "probabilities": {
    "phishing": 0.855,
    "legitimate": 0.145
  },
  "model_name": "bert_email"
}
```

### Test CNN Visual Analysis

**API Test:**
```bash
curl -X POST http://localhost:8000/api/v1/cnn-analyze \
  -H "Content-Type: application/json" \
  -d '{"dom_features": {"total_elements": 150, "form_count": 2, "password_form_count": 1, "script_count": 10, "has_login_form": true, "has_external_action": false}}'
```

**Expected Response:**
```json
{
  "available": true,
  "score": 65.2,
  "confidence": 45.8,
  "verdict": "suspicious",
  "risk_indicators": 2,
  "probabilities": {
    "phishing": 0.652,
    "legitimate": 0.348
  },
  "model_name": "cnn_visual"
}
```

### Test GNN Graph Analysis

**API Test:**
```bash
curl -X POST http://localhost:8000/api/v1/gnn-analyze \
  -H "Content-Type: application/json" \
  -d '{"graph_data": {"node_count": 25, "edge_count": 40, "density": 0.13, "cluster_count": 3, "largest_cluster_size": 15, "shared_infrastructure_count": 8, "centrality_max": 0.45}}'
```

**Expected Response:**
```json
{
  "available": true,
  "score": 55.0,
  "confidence": 65.0,
  "verdict": "suspicious",
  "findings": [
    "Many shared infrastructure edges (8)",
    "Large domain cluster detected (15 domains)"
  ],
  "graph_metrics": {
    "node_count": 25,
    "edge_count": 40,
    "density": 0.13,
    "cluster_count": 3,
    "shared_infrastructure": 8
  },
  "model_name": "gnn_graph"
}
```

### Test Transformer Ensemble

**API Test:**
```bash
curl -X POST http://localhost:8000/api/v1/transformer-ensemble \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "Your account will be suspended unless you verify now!",
    "dom_features": {"password_form_count": 1, "has_external_action": true},
    "graph_data": {"node_count": 10, "shared_infrastructure_count": 5},
    "xgboost_result": {"xgb_available": true, "xgb_score": 72.5}
  }'
```

**Expected Response:**
```json
{
  "available": true,
  "ensemble_score": 68.75,
  "ensemble_confidence": 62.5,
  "ensemble_verdict": "suspicious",
  "risk_level": "high",
  "score": 68,
  "model_scores": {
    "bert_email": 82.5,
    "cnn_visual": 55.0,
    "gnn_graph": 45.0,
    "xgboost_ml": 72.5
  },
  "model_weights": {
    "bert_email": 0.30,
    "cnn_visual": 0.25,
    "gnn_graph": 0.25,
    "xgboost_ml": 0.20
  },
  "findings": [...]
}
```

## 4. Frontend Testing

### Access the Dashboard

1. Open http://localhost:5173 in your browser
2. Login with any email/password (stored in localStorage)
3. Enter a domain and click "ANALYZE"

### Test New Sidebar Features

1. **Email Phishing (BERT)**:
   - Click "Email Phishing (BERT)" in sidebar
   - Paste email content
   - Click "ANALYZE WITH BERT"
   - View results

2. **CNN Visual Analysis**:
   - Run a domain analysis first
   - Click "CNN Visual Analysis" in sidebar
   - Click "RUN CNN ANALYSIS"
   - View results

3. **GNN Graph Analysis**:
   - Run a domain analysis first
   - Click "GNN Graph Analysis" in sidebar
   - Click "RUN GNN ANALYSIS"
   - View results

4. **Transformer Ensemble**:
   - Run a domain analysis first
   - Click "Transformer Ensemble" in sidebar
   - (Optional) Enter email text
   - Click "RUN FULL ENSEMBLE"
   - View combined results

## 5. Verify All Features Work

### Check Feature Status

```bash
curl http://localhost:8000/api/v1/features
```

**Expected Response:**
```json
{
  "v4_features": {
    "email_phishing": true,
    "sms_phishing": true,
    "graph_analysis": true,
    "adversarial_detection": true,
    "continuous_learning": true,
    "misp_otx": true,
    "sandbox_analysis": true,
    "dom_visual_analysis": true,
    "transformer_ensemble": true
  },
  ...
}
```

## 6. Troubleshooting

### BERT Model Not Loading

If BERT models fail to download:
1. Check internet connection
2. Ensure sufficient disk space (~500MB per model)
3. Check firewall/proxy settings

### CUDA/GPU Issues

If you have GPU errors:
- The models will fall back to CPU automatically
- To use GPU, install CUDA-enabled PyTorch:
  ```bash
  pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
  ```

### Port Already in Use

If port 8000 is busy:
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8001
```

Then update the frontend API URL in `front_end/App.jsx`:
```javascript
const API_URL = "http://localhost:8001/api/v1/analyze";
```

## 7. Quick Start Commands

```bash
# Terminal 1: Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Terminal 2: Frontend
cd front_end
npm install
npm run dev
```

Then open http://localhost:5173 and start analyzing!
