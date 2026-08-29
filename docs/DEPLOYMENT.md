# 🚀 RETRO_INTEL — Deployment Guide

## Table of Contents

1. [Quick Start (Docker)](#1-quick-start-docker)
2. [Manual Setup (No Docker)](#2-manual-setup-no-docker)
3. [Production Deployment](#3-production-deployment)
4. [Cloud Deployment](#4-cloud-deployment)
5. [Environment Variables](#5-environment-variables)
6. [Troubleshooting](#6-troubleshooting)

---

# 1. QUICK START (Docker)

## Prerequisites
- Docker Desktop installed ([Download](https://docs.docker.com/get-docker/))
- Docker Compose (included with Docker Desktop)

## One-Command Launch

```bash
# 1. Clone the repository
git clone https://github.com/jk1507/Sih-Hackaton.git
cd Sih-Hackaton

# 2. Create .env file
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY (optional but recommended)

# 3. Start everything
docker-compose up --build
```

## What Happens:
```
✅ Backend starts at http://localhost:8000
✅ Frontend starts at http://localhost:80
✅ API proxy configured (frontend → backend)
✅ Health checks enabled
✅ Auto-restart on crash
```

## Access:
- **Frontend Dashboard:** http://localhost
- **Backend API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health

## Stop:
```bash
docker-compose down
```

## Rebuild After Code Changes:
```bash
docker-compose up --build --force-recreate
```

---

# 2. MANUAL SETUP (No Docker)

## Prerequisites
- Python 3.10+
- Node.js 18+
- npm or yarn

## Backend Setup

```bash
# 1. Navigate to backend
cd backend

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Install Playwright (for browser automation)
python -m playwright install chromium

# 6. Create .env file
cp ../.env.example .env
# Edit .env and add your GEMINI_API_KEY

# 7. Start backend server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Frontend Setup

```bash
# 1. Open new terminal
cd front_end

# 2. Install dependencies
npm install

# 3. Start development server
npm run dev
```

## Access:
- **Frontend:** http://localhost:5173
- **Backend:** http://localhost:8000

---

# 3. PRODUCTION DEPLOYMENT

## Option A: Docker (Recommended)

```bash
# Build and start in detached mode
docker-compose -f docker-compose.yml up -d --build

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Option B: Systemd Services (Linux)

### Backend Service

Create `/etc/systemd/system/retro-intel-backend.service`:

```ini
[Unit]
Description=RETRO_INTEL Backend API
After=network.target

[Service]
Type=simple
user=www-data
workingdirectory=/opt/retro-intel/backend
ExecStart=/opt/retro-intel/backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=5
Environment=PATH=/opt/retro-intel/backend/venv/bin
EnvironmentFile=/opt/retro-intel/.env

[Install]
WantedBy=multi-user.target
```

### Frontend Service (Nginx)

Create `/etc/nginx/sites-available/retro-intel`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Serve React build
    root /opt/retro-intel/front_end/dist;
    index index.html;

    # Proxy API to backend
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # React Router
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(js|css|png|jpg|ico|svg|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable and start:
```bash
sudo ln -s /etc/nginx/sites-available/retro-intel /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx
```

---

# 4. CLOUD DEPLOYMENT

## Option 1: Railway (Easiest)

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Initialize project
railway init

# Add backend service
railway add --name backend

# Set environment variables
railway variables set GEMINI_API_KEY=your_key_here

# Deploy
railway up
```

## Option 2: Render

1. Go to [render.com](https://render.com)
2. Create a new **Web Service**
3. Connect your GitHub repo
4. Settings:
   - **Runtime:** Python
   - **Build Command:** `cd backend && pip install -r requirements.txt`
   - **Start Command:** `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Add environment variables in Render dashboard

For frontend:
1. Create a new **Static Site**
2. Settings:
   - **Build Command:** `cd front_end && npm install && npm run build`
   - **Publish Directory:** `front_end/dist`

## Option 3: Vercel (Frontend) + Railway (Backend)

### Frontend on Vercel:
```bash
# Install Vercel CLI
npm install -g vercel

# Deploy frontend
cd front_end
vercel
```

### Backend on Railway:
```bash
# Deploy backend
cd backend
railway up
```

### Connect them:
Set `VITE_API_URL` in Vercel environment variables to your Railway backend URL.

## Option 4: AWS (Advanced)

### ECS Fargate:
```bash
# Build and push to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.us-east-1.amazonaws.com
docker build -t retro-intel-backend ./backend
docker tag retro-intel-backend:latest <account>.dkr.ecr.us-east-1.amazonaws.com/retro-intel-backend:latest
docker push <account>.dkr.ecr.us-east-1.amazonaws.com/retro-intel-backend:latest
```

---

# 5. ENVIRONMENT VARIABLES

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | No* | None | Google Gemini API key for AI analysis |
| `GOOGLE_SAFE_BROWSING_KEY` | No | None | Google Safe Browsing API key |
| `VIRUSTOTAL_API_KEY` | No | None | VirusTotal API key |
| `PHISHTANK_API_KEY` | No | None | PhishTank API key |
| `ABUSEIPDB_API_KEY` | No | None | AbuseIPDB API key |
| `URLSCAN_API_KEY` | No | None | urlscan.io API key |
| `RATE_LIMIT_PER_MINUTE` | No | 30 | Requests per minute per IP |
| `RATE_LIMIT_PER_HOUR` | No | 200 | Requests per hour per IP |
| `ALLOWED_ORIGINS` | No | localhost:5173 | CORS allowed origins |
| `VITE_API_URL` | No | localhost:8000 | Frontend API URL |

*GEMINI_API_KEY is optional but highly recommended for AI-generated SOC reports.

---

# 6. TROUBLESHOOTING

## Common Issues

### Port Already in Use
```bash
# Find process using port 8000
lsof -i :8000  # Linux/Mac
netstat -ano | findstr :8000  # Windows

# Kill the process
kill -9 <PID>
```

### Docker Build Fails
```bash
# Clean Docker cache
docker system prune -a

# Rebuild without cache
docker-compose build --no-cache
```

### Backend Won't Start
```bash
# Check logs
docker-compose logs backend

# Common fixes:
# 1. Missing .env file
cp .env.example .env

# 2. Missing Python dependencies
pip install -r requirements.txt

# 3. Port conflict
docker-compose down
docker-compose up
```

### Frontend Can't Connect to Backend
```bash
# Check backend is running
curl http://localhost:8000/health

# Check CORS settings in .env
ALLOWED_ORIGINS=http://localhost:5173,http://localhost

# Check nginx proxy config
docker-compose exec frontend cat /etc/nginx/conf.d/default.conf
```

### ML Models Not Found
```bash
# Ensure .pkl files are in backend/
ls backend/*.pkl

# If missing, train models
cd backend
python train_all_models.py
```

### Playwright/Browser Automation Not Working
```bash
# Install Playwright browsers
python -m playwright install chromium --with-deps

# On Ubuntu/Debian, also install:
sudo apt-get install -y libnss3 libatk-bridge2.0-0 libdrm2 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libasound2
```

---

# 7. QUICK REFERENCE

## Start Commands

```bash
# Docker (recommended)
docker-compose up --build

# Manual (development)
# Terminal 1 - Backend
cd backend && pip install -r requirements.txt && uvicorn main:app --reload --port 8000

# Terminal 2 - Frontend
cd front_end && npm install && npm run dev
```

## Access URLs

| Service | URL |
|---------|-----|
| Frontend | http://localhost |
| Backend API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| Health Check | http://localhost:8000/health |
| Feature Status | http://localhost:8000/api/v1/features |

## Test Commands

```bash
# Health check
curl http://localhost:8000/health

# Analyze domain
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "paypa1.com", "deep_scan": true}'

# Check features
curl http://localhost:8000/api/v1/features
```

---

*Deployment guide for SIH 2026 — RETRO_INTEL Team*
