# 🚀 SPECTRA Real Evidence - Quick Start Guide

## ⚡ 3-Minute Setup

### Step 1: Install Dependencies (30 seconds)
```bash
pip install python-evtx scapy
```

### Step 2: Test It Works (1 minute)
```bash
python test_real_evidence.py
```

**You should see:**
```
✔ Collected 4 artifacts
✅ TEST PASSED: Real evidence collection working!
```

### Step 3: Start Services (1 minute)
```bash
# Terminal 1: MongoDB
mongod --dbpath /data/db

# Terminal 2: Flask AI
cd ai-engine && python app.py

# Terminal 3: Spring Backend
cd backend && mvn spring-boot:run

# Terminal 4: React Frontend
cd frontend && npm start
```

### Step 4: Use Real Evidence (30 seconds)
1. Open http://localhost:3000
2. Login: `admin` / `admin123`
3. Click **Ingest** tab
4. Select **System Paths** mode
5. Enter path: `/tmp/test-evidence` (or your evidence directory)
6. Click **Ingest into CASE-001**
7. Click **Run Analysis** (top bar)
8. View results in all tabs

---

## 🎯 What Was Fixed

### Problem
- Frontend always sent demo data (ignored user paths)
- Backend never called Python evidence collector
- Timeline showed fake events

### Solution
- ✅ Frontend sends real paths to backend
- ✅ Backend calls Python to scan files
- ✅ Timeline built from real timestamps
- ✅ Overview shows real statistics

---

## 📋 Quick Test

### Create Test Evidence
```bash
mkdir /tmp/test-evidence
echo "test" > /tmp/test-evidence/mimikatz.exe
echo "test" > /tmp/test-evidence/tor.exe
echo "test" > /tmp/test-evidence/document.pdf
```

### Ingest and Analyze
1. Ingest tab → System Paths
2. Enter: `/tmp/test-evidence`
3. Click Ingest
4. Click Run Analysis

### Expected Results
- **Evidence tab**: 3 files listed
- **mimikatz.exe**: Score ~90-98 (CRITICAL)
- **tor.exe**: Score ~70-80 (HIGH)
- **document.pdf**: Score ~0-20 (LOW)
- **Timeline**: 3 events in chronological order
- **Overview**: Real charts and statistics

---

## 🔍 Evidence Types Supported

| Type | File Format | What It Extracts |
|------|-------------|------------------|
| **File System** | Any files | Name, size, SHA-256, timestamps |
| **Windows Logs** | `.evtx` | Event IDs, failed logins, log clearing |
| **Browser History** | SQLite DB | URLs, visit counts, TOR access |
| **Network Packets** | `.pcap` | IPs, ports, suspicious traffic |

---

## 📊 Scoring System

### Rule-Based (Instant Flags)
- `mimikatz.exe` → 98/100
- `tor.exe` → 80/100
- Event ID 1102 (log cleared) → 80/100
- Port 4444 (Metasploit) → 70/100

### ML-Based (RandomForest)
- 200 decision trees
- Trained on 5000+ samples
- Predicts: 0-100 threat score

### Final Score
```
Final = (ML × 0.6) + (Rule × 0.4)
```

**Example:**
- ML predicts: 85
- Rule flags: 98 (mimikatz)
- Final: (85 × 0.6) + (98 × 0.4) = **90/100** → **CRITICAL**

---

## 🐛 Troubleshooting

### "python-evtx not installed"
```bash
pip install python-evtx
```

### "scapy not installed"
```bash
pip install scapy
```

### "No evidence found"
- Check path is correct
- Ensure files exist in directory
- Check file permissions

### "Timeline empty"
- Click "Run Analysis" after ingest
- Check artifacts have timestamps
- Verify Flask service running

### "Overview not updating"
- Click "Run Analysis" button
- Check browser console for errors
- Verify backend API calls succeed

---

## 📚 Full Documentation

- **CHANGES_SUMMARY.md** - What was changed and why
- **IMPLEMENTATION_GUIDE.md** - Technical details and architecture
- **REAL_DATA_SETUP.md** - Complete setup instructions
- **test_real_evidence.py** - Test script

---

## ✅ Success Checklist

- [ ] Dependencies installed (`python-evtx`, `scapy`)
- [ ] Test script passes (`python test_real_evidence.py`)
- [ ] All services running (MongoDB, Flask, Spring, React)
- [ ] Can ingest real evidence paths
- [ ] Evidence table shows real files
- [ ] Timeline displays chronological events
- [ ] Overview charts show real data
- [ ] High-risk files get high scores (70-98)
- [ ] Normal files get low scores (0-30)

---

## 🎉 You're Ready!

Your SPECTRA system now processes **real forensic evidence** instead of demo data.

**Test it:**
```bash
python test_real_evidence.py
```

**Use it:**
1. Create evidence directory
2. Ingest via UI
3. Run Analysis
4. Review results

**Questions?** Check the full documentation files listed above.

---

## 🚀 Real-World Usage

### Typical Workflow

```
1. Collect Evidence
   - Copy files from suspect machine
   - Export Windows Event Logs (.evtx)
   - Export browser history (SQLite)
   - Capture network traffic (.pcap)

2. Organize Evidence
   /case-001/
   ├── disk_image/
   ├── Security.evtx
   ├── History
   └── capture.pcap

3. Ingest into SPECTRA
   - Ingest tab → System Paths
   - Enter all paths
   - Click Ingest

4. Run Analysis
   - Click "Run Analysis" button
   - Wait for AI processing
   - Review results

5. Generate Report
   - Report auto-generated
   - SHA-256 hash computed
   - Hash stored on blockchain
   - Export as PDF for court
```

### Evidence Paths Examples

**Windows:**
```
File System: C:\Users\suspect\Downloads
EVTX: C:\Windows\System32\winevt\Logs\Security.evtx
Chrome: C:\Users\suspect\AppData\Local\Google\Chrome\User Data\Default\History
PCAP: C:\evidence\network-capture.pcap
```

**Linux:**
```
File System: /home/suspect/Downloads
Chrome: /home/suspect/.config/google-chrome/Default/History
PCAP: /evidence/capture.pcap
```

---

## 💡 Pro Tips

1. **Start with file system scan** - Fastest way to find suspicious files
2. **Add event logs** - Reveals authentication and system changes
3. **Include browser history** - Detects TOR and dark web access
4. **Capture network traffic** - Shows C2 callbacks and data exfiltration
5. **Run analysis after each ingest** - See results immediately
6. **Use feedback system** - Improve ML model accuracy over time

---

**Ready to investigate? Start with:** `python test_real_evidence.py` 🎯
