# ☁️ Cloud Deployment Guide
## Deploy RETRO_INTEL to Railway + Vercel

This guide will give you **two public URLs**:
- **Backend API:** `https://your-app.up.railway.app`
- **Frontend Dashboard:** `https://your-app.vercel.app`

---

## 📋 Prerequisites

1. **GitHub Account** (for code hosting)
2. **Railway Account** (free tier: $5 credit/month) → [Sign up](https://railway.app)
3. **Vercel Account** (free tier: 100GB bandwidth/month) → [Sign up](https://vercel.com)
4. **Gemini API Key** (optional but recommended) → [Get key](https://aistudio.google.com/apikey)

---

# PART 1: Deploy Backend to Railway

## Step 1: Push Code to GitHub

```bash
# From your project root
git init
git add .
git commit -m "Initial commit for deployment"
git remote add origin https://github.com/your-username/Sih-Hackaton.git
git push -u origin main
```

## Step 2: Create Railway Project

1. Go to [railway.app](https://railway.app)
2. Click **"Start a New Project"**
3. Select **"Deploy from GitHub Repo"**
4. Select your `Sih-Hackaton` repository
5. Railway will auto-detect it's a Python project

## Step 3: Configure Railway Service

1. In Railway dashboard, click on your service
2. Go to **"Settings"** tab
3. Under **"Build"** section:
   - **Build Command:** `pip install -r backend/requirements.txt`
   - **Start Command:** `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT`

4. Under **"Environment"** section, add variables:

| Variable | Value |
|----------|-------|
| `GEMINI_API_KEY` | your_key_here |
| `PYTHON_VERSION` | 3.11.0 |
| `PIP_CACHE_DIR` | /tmp/pip_cache |

5. Click **"Deploy"**

## Step 4: Get Your Backend URL

1. Go to **"Settings"** → **"Networking"**
2. Click **"Generate Domain"**
3. You'll get a URL like: `https://retro-intel-backend.up.railway.app`
4. **Copy this URL** — you'll need it for the frontend

## Step 5: Test Backend

```bash
# Test health endpoint
curl https://retro-intel-backend.up.railway.app/health

# Test domain analysis
curl -X POST https://retro-intel-backend.up.railway.app/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "paypa1.com", "deep_scan": false}'
```

---

# PART 2: Deploy Frontend to Vercel

## Step 1: Update Frontend API URL

Before deploying, update the frontend to point to your Railway backend.

Edit `front_end/App.jsx` and replace the API URLs:

```javascript
// Find these lines (around line 6-7):
const isDev = import.meta.env.DEV;
const API_URL = isDev ? "/api/v1/analyze" : (import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1/analyze");
const AI_ANALYSIS_API = isDev ? "/api/v1/ai-analysis" : (import.meta.env.VITE_AI_ANALYSIS_API || "http://localhost:8000/api/v1/ai-analysis");

// Replace with:
const API_URL = "/api/v1/analyze";
const AI_ANALYSIS_API = "/api/v1/ai-analysis";
```

**Why?** Vercel will proxy `/api/*` requests to your Railway backend using the `vercel.json` rewrites.

## Step 2: Push Updated Code

```bash
git add .
git commit -m "Update API URLs for production"
git push
```

## Step 3: Create Vercel Project

1. Go to [vercel.com](https://vercel.com)
2. Click **"Add New Project"**
3. Import your `Sih-Hackaton` GitHub repository
4. Configure:
   - **Framework Preset:** Vite
   - **Root Directory:** `front_end`
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`

5. Click **"Deploy"**

## Step 4: Set Environment Variables

1. In Vercel dashboard, go to **"Settings"** → **"Environment Variables"**
2. Add:

| Variable | Value |
|----------|-------|
| `VITE_API_URL` | https://retro-intel-backend.up.railway.app |

3. Click **"Save"**
4. Go to **"Deployments"** and **Redeploy**

## Step 5: Configure API Proxy (Important!)

To make frontend calls go through Vercel to Railway, update `vercel.json`:

```json
{
  "version": 2,
  "buildCommand": "cd front_end && npm run build",
  "outputDirectory": "front_end/dist",
  "rewrites": [
    {
      "source": "/api/:path*",
      "destination": "https://retro-intel-backend.up.railway.app/api/:path*"
    },
    {
      "source": "/health",
      "destination": "https://retro-intel-backend.up.railway.app/health"
    }
  ]
}
```

**Replace** `retro-intel-backend.up.railway.app` with your actual Railway URL.

## Step 6: Get Your Frontend URL

1. Vercel will give you a URL like: `https://retro-intel.vercel.app`
2. **This is your public dashboard URL!**

---

# PART 3: Final Configuration

## Update Frontend App.jsx for Production

Edit `front_end/App.jsx` to handle the proxy correctly:

```javascript
// Around line 6, update these lines:
const isDev = import.meta.env.DEV;
const API_BASE = isDev ? "" : (import.meta.env.VITE_API_URL || "");
const API_URL = `${API_BASE}/api/v1/analyze`;
const AI_ANALYSIS_API = `${API_BASE}/api/v1/ai-analysis`;
```

Then update all fetch calls to use the new pattern. Search for `API_BASE` usage in the file.

## Update CORS on Railway

In Railway, add to your environment variables:

| Variable | Value |
|----------|-------|
| `ALLOWED_ORIGINS` | https://retro-intel.vercel.app,http://localhost:5173 |

---

# PART 4: Verify Everything Works

## Test Checklist

- [ ] Backend health check works: `GET /health`
- [ ] Frontend loads at Vercel URL
- [ ] Domain analysis works from frontend
- [ ] AI analysis works (if Gemini key set)
- [ ] Export functions work (PDF, Excel)
- [ ] No CORS errors in browser console

## Debug Commands

```bash
# Check Railway logs
railway logs

# Check Vercel deployment
vercel logs

# Test backend directly
curl -X POST https://your-railway-url/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "google.com", "deep_scan": false}'
```

---

# 🎯 Your Final URLs

After deployment, you'll have:

| Service | URL | Purpose |
|---------|-----|---------|
| **Frontend** | `https://retro-intel.vercel.app` | Dashboard UI |
| **Backend API** | `https://retro-intel.up.railway.app` | API Server |
| **API Docs** | `https://retro-intel.up.railway.app/docs` | Swagger UI |

---

# 💰 Cost Estimate

| Platform | Free Tier | What You Get |
|----------|-----------|--------------|
| Railway | $5/month credit | ~500 hours of backend |
| Vercel | 100GB bandwidth | Unlimited frontend hosting |
| **Total** | **$0/month** | Full stack deployment |

---

# 🔄 Auto-Deploy

Both platforms auto-deploy on git push:

```bash
# Make changes
git add .
git commit -m "Update feature"
git push

# Railway auto-redeploys backend
# Vercel auto-redeploys frontend
```

---

# ⚠️ Common Issues

### Issue 1: CORS Error
**Symptom:** Frontend can't reach backend
**Fix:** Add your Vercel URL to `ALLOWED_ORIGINS` in Railway env vars

### Issue 2: Backend Cold Start
**Symptom:** First request takes 30+ seconds
**Fix:** Railway free tier has cold starts. Consider upgrading or adding a cron job to keep it awake.

### Issue 3: ML Models Not Found
**Symptom:** Backend crashes on startup
**Fix:** Ensure `.pkl` files are committed to git (they're in `.gitignore` by default)

### Issue 4: Build Fails
**Symptom:** Vercel/Railway build error
**Fix:** Check build logs, ensure all dependencies are in `requirements.txt` / `package.json`

---

# 🚀 Quick Deploy Commands

```bash
# 1. Install Railway CLI
npm install -g @railway/cli

# 2. Login to Railway
railway login

# 3. Initialize Railway project
cd backend
railway init

# 4. Set environment variables
railway variables set GEMINI_API_KEY=your_key_here
railway variables set ALLOWED_ORIGINS=https://your-vercel-url.vercel.app

# 5. Deploy backend
railway up

# 6. Get your Railway URL
railway domain

# 7. Install Vercel CLI
npm install -g vercel

# 8. Deploy frontend
cd ../front_end
vercel --prod

# 9. Set Vercel env var
vercel env add VITE_API_URL
# Enter: https://your-railway-url.up.railway.app
```

---

*Cloud deployment guide for SIH 2026 — RETRO_INTEL Team*
