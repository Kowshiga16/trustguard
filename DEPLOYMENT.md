# TrustGuard - Production Cloud Deployment Guide

This guide covers deploying the **TrustGuard Zero Trust Access Control System** to production cloud environments (Render, Railway, Cloud VPS / Docker, or Local Production).

---

## Architecture Overview

```
                      +---------------------------------------+
                      |          Client / Browser             |
                      +-------------------+-------------------+
                                          | HTTPS
                                          v
                      +---------------------------------------+
                      |   TrustGuard Full-Stack Web Service   |
                      |   (Node.js Express + React SPA)       |
                      |   - Port 3000 / $PORT                 |
                      |   - Static SPA Assets (dist/)         |
                      |   - Policy Enforcement Point (PEP)    |
                      +---------+-------------------+---------+
                                |                   |
                 Zero Trust PDP |                   | Predictions
                 REST API       |                   | REST API
                                v                   v
          +-----------------------+     +-------------------------------+
          |   MongoDB Database    |     |  Isolation Forest ML Service  |
          |   (Atlas / Local)     |     |  (Python FastAPI + Scikit)    |
          |   - Port 27017        |     |  - Port 8000 / $PORT          |
          |   - Land Deeds & ROR  |     |  - NAS Behavioral Scoring     |
          |   - Audit Logs        |     |  - Off-hours & IP Anomaly     |
          +-----------------------+     +-------------------------------+
```

---

## Option 1: 1-Click Cloud Deployment via Render (Recommended)

Render natively supports both Python and Node.js with the included [`render.yaml`](file:///C:/Users/svkow/Downloads/Project1/render.yaml) blueprint.

### Steps:
1. **Push your code to GitHub / GitLab**.
2. **Log in to [Render](https://render.com)**.
3. Click **New +** $\to$ **Blueprint**.
4. Connect your repository. Render automatically reads `render.yaml` and provisions:
   - `trustguard-ml` (Python 3.11 FastAPI microservice)
   - `trustguard-web` (Node.js 20 Express + React service)
5. **Set Environment Variables** on `trustguard-web`:
   - `MONGO_URI`: Your MongoDB Atlas connection URI (e.g. `mongodb+srv://admin:pass@cluster.mongodb.net/trustguard`)
   - `SECURITY_ALERT_EMAIL`: `kowshiga931@gmail.com`
   - `SMTP_USER` / `SMTP_PASS`: Your Gmail App Password for live alert emails.
6. Click **Apply**. Both services will build and deploy automatically!

---

## Option 2: Cloud Deployment via Railway

Railway provides seamless monorepo and multi-container deployments with a free MongoDB plugin.

### Steps:
1. **Install Railway CLI** or open [Railway.app](https://railway.app).
2. Click **New Project** $\to$ **Deploy from GitHub repo**.
3. **Add Database**: Click **+ New** $\to$ **Database** $\to$ **Add MongoDB**.
4. **Deploy ML Microservice**:
   - Add service pointing to `/ml-service`.
   - Build Command: `pip install -r requirements.txt && python -c "from app import load_or_train_model; load_or_train_model()"`
   - Start Command: `uvicorn app:app --host 0.0.0.0 --port $PORT`
5. **Deploy Web Application**:
   - Add service pointing to `/Project1`.
   - Set Environment Variable: `MONGO_URI=${{MongoDB.MONGO_URL}}`
   - Set Environment Variable: `ML_SERVICE_URL=http://${{ML_Service.RAILWAY_PRIVATE_DOMAIN}}:8000/predict`
   - Build Command: `npm install && npm run build`
   - Start Command: `npm start`

---

## Option 3: Self-Hosted Cloud VPS (AWS EC2 / DigitalOcean / Ubuntu) via Docker

For complete sovereignty and dedicated server hosting:

### Prerequisites:
- Ubuntu 22.04 LTS or Debian 12
- Docker & Docker Compose (`sudo apt install docker.io docker-compose -y`)

### Deployment:
1. Clone the repository onto your VPS:
   ```bash
   git clone <your-repo-url> /opt/trustguard
   cd /opt/trustguard
   ```
2. Configure `.env` if desired (SMTP credentials, custom secrets).
3. Start all three services in background:
   ```bash
   docker-compose up -d --build
   ```
4. Check running containers:
   ```bash
   docker-compose ps
   ```
5. View live logs:
   ```bash
   docker-compose logs -f web
   ```
The application will be live at `http://your-server-ip:3000`.

---

## Option 4: Local Production Deployment (Windows)

To run the fully built, high-performance production version on your current machine:

1. Double-click [`start-production.bat`](file:///C:/Users/svkow/Downloads/Project1/start-production.bat) in the project root folder.
2. It launches:
   - Scikit-Learn Isolation Forest daemon on `http://127.0.0.1:8000`
   - Pre-compiled standalone Express production server on `http://localhost:3000`
3. Open `http://localhost:3000` in any browser.

---

## Free Cloud Database Setup (MongoDB Atlas)

If deploying to Render or Railway without a dedicated database container:

1. Go to [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) and create a **Free M0 Sandbox Cluster**.
2. Under **Network Access**, add IP `0.0.0.0/0` (Allow access from anywhere).
3. Under **Database Access**, create a user (e.g. `trustguard_admin` with password).
4. Copy the SRV connection string:
   ```
   mongodb+srv://trustguard_admin:<PASSWORD>@cluster0.mongodb.net/trustguard?retryWrites=true&w=majority
   ```
5. Paste this as `MONGO_URI` in your cloud deployment environment variables.

---

## Environment Variables Reference

| Variable | Required | Default | Purpose |
| :--- | :---: | :--- | :--- |
| `PORT` | Optional | `3000` | Port for the Node.js Express server |
| `NODE_ENV` | Optional | `production` | Set to `production` for optimized static serving |
| `MONGO_URI` | Required | `mongodb://127.0.0.1:27017/trustguard` | MongoDB connection string |
| `MONGO_DB_NAME` | Optional | `trustguard` | Name of MongoDB database |
| `JWT_SECRET` | Required | Auto-generated | Secret key for signing session tokens |
| `JWT_TTL` | Optional | `7d` | Token expiry duration |
| `ML_SERVICE_URL` | Required | `http://127.0.0.1:8000/predict` | HTTP URL of Isolation Forest ML service |
| `ML_TIMEOUT_MS` | Optional | `2000` | Max milliseconds to wait for ML response |
| `ML_SCORE_WEIGHT`| Optional | `0.25` | Weight multiplier of ML risk in trust score |
| `ENABLE_EMAIL_ALERTS`| Optional | `true` | Enables NodeMailer email alerts |
| `SECURITY_ALERT_EMAIL`| Optional | `kowshiga931@gmail.com` | Target recipient for security incidents & OTPs |
| `SMTP_HOST` | Optional | `smtp.gmail.com` | SMTP Server Host |
| `SMTP_PORT` | Optional | `587` | SMTP Server Port |
| `SMTP_USER` | Optional | `""` | SMTP Username / Gmail address |
| `SMTP_PASS` | Optional | `""` | SMTP Password / App Password |

---

## Post-Deployment Verification

Once deployed, verify your cloud instance:

1. **Health Check**:
   - Web API: `https://your-app.onrender.com/api/system/stats` (should return JSON stats)
   - ML Service: `https://your-ml.onrender.com/health` (should return `{"status":"healthy","model_loaded":true}`)
2. **Access Control**:
   - Log in using registered credentials (`raj.kumar@revenue.tn.gov.in` / `Password@123`).
   - Click **View Document** on survey `102/1` to verify certified digital seal generation.
3. **Step-Up Verification**:
   - Access from an unrecognized device or IP to observe dynamic score drop and automated NodeMailer OTP dispatch to `kowshiga931@gmail.com`.
