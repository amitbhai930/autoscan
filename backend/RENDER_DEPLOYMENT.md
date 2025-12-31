# Deployment Guide: AutoScanZ Backend on Render

## Prerequisites
- GitHub account with your code pushed
- Render.com account (free tier available)

## Step-by-Step Deployment

### 1. Push to GitHub
```bash
cd /path/to/autoscan/backend
git init
git add .
git commit -m "Initial commit: AutoScanZ backend"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/autoscanz-backend.git
git push -u origin main
```

### 2. Create Render Service
1. Go to [render.com](https://render.com)
2. Sign up or log in with your GitHub account
3. Click "New +" → "Web Service"
4. Connect your GitHub repository
5. Select the `autoscanz-backend` repository

### 3. Configure Service
- **Name**: `autoscanz-backend` (or your preferred name)
- **Runtime**: Python
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60`

### 4. Set Environment Variables
In the Render dashboard, add these environment variables:

```
FLASK_ENV = production
SECRET_KEY = [generate a random string or use Render's random value]
PORT = 10000
```

### 5. Deploy
Click "Create Web Service" to deploy. Render will:
- Build your Python environment
- Install dependencies from requirements.txt
- Start the service using Gunicorn

### 6. Monitor Deployment
- Check the logs in Render dashboard
- Your app will be available at: `https://autoscanz-backend.onrender.com` (or your service name)

## Important Notes

### Database
- The app uses SQLite (autoscanz.db) by default
- On Render's free tier, this database will be reset when the service restarts
- **For production**: Switch to PostgreSQL:
  1. Add a PostgreSQL database in Render
  2. Update `database.py` to use PostgreSQL connection string
  3. Set `DATABASE_URL` environment variable

### File Storage
- Reports are stored in `../static/reports/`
- On Render's free tier, files are lost when service restarts
- **For production**: Use cloud storage (AWS S3, Google Cloud Storage, etc.)

### Updates
After making changes locally:
```bash
git add .
git commit -m "Your commit message"
git push origin main
```
Render will automatically redeploy!

## Troubleshooting

### Cold Start Issues
- Free tier services sleep after 15 minutes of inactivity
- First request after sleep may take a minute to respond
- Upgrade to paid plan for always-on service

### Port Issues
- Render automatically assigns a port via the `$PORT` environment variable
- The app is configured to use this automatically

### CORS Issues
If frontend is on a different domain:
- Update CORS configuration in app.py if needed
- Current config allows cross-origin requests

### Database Connection Issues
- Check logs in Render dashboard
- Ensure database.py can find the database file
