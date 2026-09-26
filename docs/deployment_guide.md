# CYBERGUARD — Production Deployment Guide

This guide covers all recommended methods for deploying the CYBERGUARD platform:
1. **Method 1: One-Click Full-Stack Docker Compose (Recommended for VPS / Cloud VMs)**
2. **Method 2: Free Cloud Hosting (Vercel Frontend + Render/Railway Backend)**
3. **Method 3: Native Linux VPS (Ubuntu / AWS EC2 with Systemd + Nginx + Let's Encrypt)**

---

## 🛠️ Pre-Deployment Checklist

* [ ] **Google Gemini API Key** (Optional): Add `GEMINI_API_KEY` to your environment variables if you want generative AI explanations (the system automatically falls back to deterministic rule templates if omitted).
* [ ] **Secret Key**: Change `SECRET_KEY` in production to a secure random 64-character token (`openssl rand -hex 32`).
* [ ] **CORS Settings**: In [backend/app/config.py](file:///d:/BPUT%20Project/backend/app/config.py), update allowed origins with your public domain.

---

## 🚀 Method 1: Containerized Full-Stack (Docker Compose)
*Best for: AWS EC2, DigitalOcean Droplet, Linode, Hetzner, or local production server.*

The repository includes production Dockerfiles and a multi-container compose file:
* [backend/Dockerfile](file:///d:/BPUT%20Project/backend/Dockerfile) (Python 3.11 Slim + Uvicorn)
* [frontend/Dockerfile](file:///d:/BPUT%20Project/frontend/Dockerfile) (Multi-stage Node 20 build $\rightarrow$ Nginx Alpine)
* [frontend/nginx.conf](file:///d:/BPUT%20Project/frontend/nginx.conf) (Reverse proxies `/api/` to backend:8000 and serves SPA)
* [docker-compose.prod.yml](file:///d:/BPUT%20Project/docker-compose.prod.yml) (PostgreSQL + Backend + Frontend)

### Step 1: Clone and Configure Environment
```bash
git clone <your-repo-url>
cd "BPUT Project"

# Optional: Set environment variables
export GEMINI_API_KEY="your-gemini-api-key"
export POSTGRES_PASSWORD="a_strong_database_password"
```

### Step 2: Build and Run
```bash
docker compose -f docker-compose.prod.yml up -d --build
```

### Step 3: Verify Running Services
```bash
docker compose -f docker-compose.prod.yml ps
```

* **Frontend Dashboard**: `http://<your-server-ip>/` (Port 80)
* **Backend API & Docs**: `http://<your-server-ip>:8000/docs`
* **Health Check**: `http://<your-server-ip>:8000/health`

---

## ☁️ Method 2: Free-Tier Cloud Deployment (Vercel + Render)
*Best for: Free public hackathon demos and college project presentations.*

### A. Deploy the Backend on Render.com (or Railway.app)
1. Push your code to GitHub.
2. Sign up at [Render.com](https://render.com).
3. Click **New +** $\rightarrow$ **Web Service** $\rightarrow$ Connect your GitHub repository.
4. Set the following settings:
   * **Root Directory**: `backend`
   * **Environment**: `Python 3`
   * **Build Command**: `pip install -r requirements.txt`
   * **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port 10000`
5. In **Environment Variables**, add:
   * `ENVIRONMENT`: `production`
   * `GEMINI_API_KEY`: *(Your key or leave empty for offline rule engine)*
   * `SECRET_KEY`: *(Random secure string)*
6. Click **Deploy Web Service**. You will receive a URL like:
   `https://cyberguard-backend.onrender.com`

### B. Deploy the Frontend on Vercel
1. Sign up at [Vercel.com](https://vercel.com).
2. Click **Add New...** $\rightarrow$ **Project** $\rightarrow$ Import your GitHub repository.
3. Configure the build settings:
   * **Root Directory**: `frontend`
   * **Framework Preset**: `Vite`
   * **Build Command**: `npm run build`
   * **Output Directory**: `dist`
4. In **Environment Variables**, add:
   * `VITE_API_URL`: `https://cyberguard-backend.onrender.com/api/v1`
5. Click **Deploy**. Vercel will give you a public HTTPS URL (e.g. `https://cyberguard.vercel.app`).

---

## 🔒 Method 3: Native Linux VPS (Ubuntu / AWS EC2)
*Best for: High performance, custom domain, and Let's Encrypt SSL.*

### 1. Install System Dependencies
```bash
sudo apt update && sudo apt install -y python3-pip python3-venv nginx certbot python3-certbot-nginx
```

### 2. Setup Backend Systemd Service
Create `/etc/systemd/system/cyberguard.service`:
```ini
[Unit]
Description=CYBERGUARD FastAPI Threat Engine
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/BPUT-Project/backend
ExecStart=/home/ubuntu/BPUT-Project/backend/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cyberguard
```

### 3. Build Frontend
```bash
cd /home/ubuntu/BPUT-Project/frontend
npm ci
VITE_API_URL=/api/v1 npm run build
sudo cp -r dist/* /var/www/cyberguard/
```

### 4. Configure Nginx Reverse Proxy
Create `/etc/nginx/sites-available/cyberguard`:
```nginx
server {
    server_name yourdomain.com;

    root /var/www/cyberguard;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable site and activate SSL:
```bash
sudo ln -s /etc/nginx/sites-available/cyberguard /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d yourdomain.com
```
