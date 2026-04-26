# SPECTRA — AI-Powered Digital Forensics & Cybercrime Investigation System

```
███████╗██████╗ ███████╗ ██████╗████████╗██████╗  █████╗
██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝███████║
╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║
███████║██║     ███████╗╚██████╗   ██║   ██║  ██║██║  ██║
╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
```

> Real-world AI forensics platform: evidence ingestion → ML threat scoring
> → anomaly detection → crime timeline → tamper-proof blockchain storage.

---

## Architecture

```
Evidence Sources (files, logs, browser, .pcap)
        │
        ▼
┌─────────────────────┐
│  Phase 1 — AI Engine│  Python • scikit-learn
│  train_models.py    │  RandomForest + IsolationForest
│  evidence_collector │  FileSystem / EVTX / SQLite / PCAP
│  timeline_engine.py │  Chronological reconstruction
└──────────┬──────────┘
           │ REST
           ▼
┌──────────────────────┐
│  Phase 2 — Flask API │  POST /score /anomaly /timeline /retrain
└──────────┬───────────┘
           │ REST (WebClient)
           ▼
┌───────────────────────────┐
│  Phase 3 — Spring Boot    │  JWT auth • MongoDB • blockchain bridge
│  POST /api/ingest         │
│  POST /api/analyze        │
│  GET  /api/reports        │
│  POST /api/feedback       │
│  POST /api/blockchain     │
└────┬───────────┬──────────┘
     │           │
     ▼           ▼
  MongoDB    Ethereum (Ganache)
             ForensicStorage.sol
             Phase 5 — blockchain.py
           │
           ▼
┌─────────────────────┐
│  Phase 4 — React    │  Login • Dashboard • Evidence table
│                     │  Timeline • Charts • Blockchain verify
└─────────────────────┘
```

---

## Project Structure

```
spectra/
├── ai-engine/
│   ├── train_models.py          # Dataset preprocessing + model training
│   ├── app.py                   # Flask AI REST API
│   ├── timeline_engine.py       # Crime timeline reconstruction
│   ├── requirements.txt
│   └── models/                  # Saved .pkl files (after training)
│       ├── threat_scorer.pkl
│       ├── anomaly_detector.pkl
│       └── evaluation_report.json
│
├── ingestion/
│   └── evidence_collector.py    # File / EVTX / Browser / PCAP parsers
│
├── backend/                     # Spring Boot (Java 17)
│   ├── pom.xml
│   └── src/main/java/com/spectra/
│       ├── SpectraApplication.java
│       ├── config/SecurityConfig.java
│       ├── controller/Controllers.java
│       ├── model/ {Evidence, ForensicReport, Feedback}
│       ├── security/ {JwtTokenProvider, JwtAuthFilter}
│       └── service/ {EvidenceService, ReportService,
│                     FeedbackService, BlockchainService}
│
├── blockchain/
│   ├── ForensicStorage.sol      # Solidity smart contract
│   ├── blockchain.py            # Web3.py deploy + interact
│   └── deployment.json          # Created after deploy
│
├── frontend/                    # React 18
│   ├── package.json
│   └── src/
│       ├── App.js
│       ├── index.js
│       ├── styles.css
│       ├── context/AuthContext.js
│       ├── services/api.js
│       ├── pages/ {LoginPage, DashboardPage}
│       └── components/ {ThreatScoreChart, TimelineView,
│                        EvidenceTable, BlockchainVerifier, IngestPanel}
└── README.md
```

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.10+ | AI engine + Flask + blockchain |
| Java | 17 | Spring Boot backend |
| Maven | 3.8+ | Build Spring Boot |
| Node.js | 18+ | React frontend |
| MongoDB | 6+ | Database |
| Ganache | latest | Local Ethereum blockchain |

---

## Quick Start (All 5 Phases)

### Step 1 — Clone and set up

```bash
git clone <repo>
cd spectra
```

---

### Step 2 — Phase 1: Train AI Models

```bash
cd ai-engine
pip install -r requirements.txt

# Option A: Demo data (no real dataset needed)
python train_models.py --demo

# Option B: Real datasets
python train_models.py --dataset cicids2017 --path ./data/cicids.csv
python train_models.py --dataset unsw       --path ./data/unsw.csv
python train_models.py --dataset kdd        --path ./data/kdd.csv
```

Expected output:
```
✔ RandomForest training complete
✔ IsolationForest training complete
Accuracy:  0.9642
F1:        0.9587
Models saved: models/threat_scorer.pkl, models/anomaly_detector.pkl
✔ Phase 1 complete.
```

---

### Step 3 — Phase 2: Start Flask AI Service

```bash
cd ai-engine
export SPECTRA_API_KEY=spectra-dev-key-change-in-prod

# Development
python app.py

# Production
gunicorn -w 4 -b 0.0.0.0:5001 app:app
```

Test it:
```bash
curl -X POST http://localhost:5001/score \
  -H "Content-Type: application/json" \
  -H "X-API-Key: spectra-dev-key-change-in-prod" \
  -d '{
    "artifact_id": "test001",
    "network_activity": 0.9,
    "session_time": 0.1,
    "data_transfer": 0.8,
    "connection_status": 2,
    "rule_score": 70
  }'
```

---

### Step 4 — Phase 3: Start Spring Boot Backend

```bash
# Start MongoDB
mongod --dbpath /data/db

# Start backend
cd backend
export JWT_SECRET=spectra-super-secret-key-change-in-prod-min-256-bits
export MONGO_URI=mongodb://localhost:27017/spectra
export FLASK_URL=http://localhost:5001
export FLASK_API_KEY=spectra-dev-key-change-in-prod

mvn spring-boot:run
```

Seed a default admin user via MongoDB shell:
```javascript
use spectra
db.users.insertOne({
  username: "admin",
  email: "admin@spectra.local",
  passwordHash: "$2a$10$...",   // bcrypt of "admin123"
  roles: ["ROLE_ADMIN", "ROLE_INVESTIGATOR"],
  active: true,
  createdAt: new Date()
})
```

Test login:
```bash
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
# Returns: { "token": "eyJ..." }
```

---

### Step 5 — Phase 5: Deploy Blockchain

```bash
# Install and start Ganache
npm install -g ganache
ganache --port 7545 --accounts 10 --deterministic

# Deploy contract
cd blockchain
pip install web3 py-solc-x flask flask-cors
python blockchain.py deploy

# Full demo (deploy + store + verify + tamper test)
python blockchain.py demo

# Run as microservice (optional — Spring Boot calls it)
python blockchain.py serve
```

---

### Step 6 — Phase 4: Start React Frontend

```bash
cd frontend
npm install
npm start
```

Open http://localhost:3000  
Login: `admin / admin123`

---

## Full E2E Workflow

```
1. Login at http://localhost:3000/login
2. Go to Ingest tab → click "Ingest into CASE-001" (demo data)
3. Click "Run Analysis" (top bar)
   → Spring Boot calls Flask /score and /anomaly for each artifact
   → Scores written to MongoDB
   → Timeline built via Flask /timeline
   → Report generated with SHA-256 hash
   → Hash stored on Ethereum via blockchain.py
4. View Overview tab → stat cards + charts update
5. View Evidence tab → priority-ranked table with scores
6. View Timeline tab → chronological crime reconstruction
7. View Blockchain tab → verify report integrity on-chain
8. Submit investigator feedback on any artifact
   → Stored in MongoDB feedback collection
   → When 50+ samples accumulate, auto-retrain triggers
   → Flask /retrain called → new models saved
```

---

## API Reference

### Flask AI Service (port 5001)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/score` | Threat score (0–100) |
| POST | `/anomaly` | Anomaly detection |
| POST | `/timeline` | Timeline reconstruction |
| POST | `/batch_score` | Score multiple artifacts |
| POST | `/retrain` | Trigger self-learning retrain |

### Spring Boot Backend (port 8080/api)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/login` | — | Get JWT token |
| POST | `/ingest` | JWT | Ingest artifacts |
| POST | `/ingest/analyze` | JWT | Run AI analysis |
| GET | `/reports` | JWT | List reports |
| GET | `/reports/{id}` | JWT | Get single report |
| POST | `/reports` | JWT | Generate report |
| POST | `/feedback` | JWT | Submit feedback |
| POST | `/feedback/trigger-retrain` | JWT | Force retrain |
| POST | `/blockchain` | JWT | Store hash on chain |
| GET | `/blockchain/verify/{id}` | JWT | Verify integrity |

---

## Dataset Sources

| Dataset | URL | Description |
|---------|-----|-------------|
| CICIDS2017 | https://www.unb.ca/cic/datasets/ids-2017.html | Network intrusion |
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | Modern attacks |
| KDD Cup 99 | http://kdd.ics.uci.edu/databases/kddcup99/ | Classic benchmark |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SPECTRA_API_KEY` | `spectra-dev-key-change-in-prod` | Flask API auth key |
| `JWT_SECRET` | (dev value) | Spring Boot JWT signing secret |
| `MONGO_URI` | `mongodb://localhost:27017/spectra` | MongoDB connection |
| `FLASK_URL` | `http://localhost:5001` | Flask service URL |
| `BLOCKCHAIN_RPC` | `http://127.0.0.1:7545` | Ganache RPC |
| `BLOCKCHAIN_PRIVATE_KEY` | (empty = Ganache) | Ethereum private key |
| `CONTRACT_ADDRESS` | (set after deploy) | Deployed contract address |
| `REACT_APP_API_URL` | `http://localhost:8080/api` | Backend URL for React |

---

## Security Notes

- **Change all secrets** before production deployment
- JWT secret must be at least 256 bits
- MongoDB should require authentication in production
- Ganache is for development only — use a real testnet/mainnet for production
- The Flask API key should be rotated regularly

---

## Ports Summary

| Service | Port |
|---------|------|
| React frontend | 3000 |
| Spring Boot API | 8080 |
| Flask AI service | 5001 |
| Blockchain bridge | 5002 |
| Ganache | 7545 |
| MongoDB | 27017 |
