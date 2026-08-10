# SPECTRA Troubleshooting Guide

## Quick Diagnostic Checklist

```bash
# Check all services are running
netstat -ano | findstr :27017  # MongoDB
netstat -ano | findstr :5001   # Flask AI Engine
netstat -ano | findstr :8081   # Spring Boot Backend
netstat -ano | findstr :3000   # React Frontend

# Check models exist
ls ai-engine/models/  # Should see: threat_scorer.pkl, anomaly_detector.pkl
```

---

## Common Issues

### 1. Backend Won't Start
**Error**: `Port 8081 already in use`

**Solution**:
```bash
netstat -ano | findstr :8081
taskkill /PID <PID> /F
```

---

### 2. Flask Not Responding
**Error**: `Connection refused to localhost:5001`

**Solution**:
```bash
cd ai-engine
python app.py
```

---

### 3. MongoDB Connection Failed
**Error**: `MongoTimeoutException`

**Solution**:
```bash
mongod --dbpath /data/db
```

---

### 4. Models Not Found
**Error**: `FileNotFoundError: models/threat_scorer.pkl`

**Solution**:
```bash
cd ai-engine
python train_models.py --demo
```

---

### 5. Login Failed
**Error**: `Invalid credentials`

**Solution**: Use `admin` / `admin123` (default credentials)

---

### 6. Evidence Ingestion Failed
**Error**: `No evidence found`

**Solution**:
- Check path is correct and accessible
- Use absolute paths (e.g., `C:\Evidence\Files`)
- Try Demo Data first

---

### 7. Analysis Times Out
**Error**: `Request timeout`

**Solution**:
- Reduce number of files (max 1000)
- Use smaller folders

---

### 8. All Scores Are 0
**Cause**: Evidence is benign (normal files)

**Solution**: This is correct! Test with known threats:
```bash
.\test_trained_attacks.bat
```

---

### 9. Windows Event Logs Can't Be Read
**Error**: `Permission denied`

**Solution**:
- Copy logs to your workspace first
- Or use Demo Data instead
- Install python-evtx: `pip install python-evtx`

---

### 10. Python Dependencies Missing
**Error**: `ModuleNotFoundError`

**Solution**:
```bash
cd ai-engine
pip install -r requirements.txt
```

---

## Restart All Services

If nothing works, restart everything in order:

```bash
# 1. MongoDB
mongod --dbpath /data/db

# 2. Flask
cd ai-engine
python app.py

# 3. Spring Boot
cd backend
mvn spring-boot:run

# 4. React
cd frontend
npm start
```

---

## Still Having Issues?

1. Check logs in terminal output
2. Try Demo Data first to verify system works
3. Check environment variables are set
4. See README.md for detailed setup instructions
