# 🧠 NetRCA AI – AI-Agent-Based Root Cause Analysis for Network Failures

NetRCA AI is an **AI-powered, graph-based root cause analysis system** that detects, analyzes, and explains **network failures and security-impacting misconfigurations** in real time.

The platform combines **log ingestion, causal graph modeling, and AI-agent reasoning** to provide **SOC-style RCA reports** with explainable insights.

---

# 🚨 Problem Statement

Modern network systems generate large volumes of logs, making it difficult to:

* Identify the **true root cause** of failures  
* Distinguish between **attacks vs misconfigurations**  
* Understand **event relationships**  
* Perform **real-time analysis**  

Traditional monitoring systems rely on alerts and manual debugging, leading to:

* Slow incident resolution  
* High operational effort  
* Inaccurate RCA  

NetRCA AI solves this by providing an **automated, explainable, and security-aware RCA system**.

---

# 💡 Solution Overview

NetRCA AI integrates:

* Log ingestion & preprocessing  
* Event correlation engine  
* Graph-based causal modeling (DAG)  
* AI-agent reasoning pipeline  
* Real-time dashboard visualization  

The system transforms raw logs into **structured incidents**, builds **causal graphs**, and generates **intelligent RCA reports**.

---

# ⚙️ Key Features

##  1. Log Ingestion Engine

The system collects logs from:

* Firewalls  
* VPN Gateways  
* Servers & Applications  
* Monitoring Tools  

Processing includes:

* Parsing & structuring  
* Time ordering  
* Feature extraction  

---

##  2. Event Correlation Engine

The system groups logs using:

* Time windows (5-minute intervals)  
* Resource context (IP, service, port)  

It detects:

* Misconfiguration cascades  
* DDoS / volumetric attacks  

---

##  3. Graph-Based RCA (DAG)

Each log is treated as a node in a graph.

The system:

* Builds a Directed Acyclic Graph (DAG)  
* Identifies root cause nodes (in-degree = 0)  
* Finds impact nodes (max downstream effect)  
* Extracts causal paths  

---

##  4. AI-Agent RCA Engine

The AI generates structured reports including:

* Root Cause  
* What Changed  
* Why It Happened  
* Security Impact  
* Risk Level  
* Remediation Steps  
* Confidence Score  

### Reasoning Flow

Observation → Hypothesis → Validation → Conclusion

---

##  5. Real-Time Dashboard

The frontend provides:

* Live incident feed  
* Global risk score  
* Active alarms  
* Graph-based RCA visualization  
* SOC-style RCA reports  

---

##  6. Security Layer

The system ensures:

* AES-GCM encryption (data confidentiality)  
* SHA-512 hashing (data integrity)  
* HMAC-SHA512 authentication  
* TLS readiness  

---

##  7. Audit Trail

Tracks:

* Incident creation  
* RCA execution  
* Status updates  

Ensures traceability and accountability.

---

# 🏗 System Architecture

Log Sources (Firewall, VPN, Servers, Monitoring)  
            ↓  
Log Ingestion & Preprocessing  
            ↓  
Event Correlation Engine  
            ↓  
Graph Construction (NetworkX DAG)  
            ↓  
AI-Agent RCA Engine  
            ↓  
Visualization Dashboard (React)  

---

# 🛠 Tech Stack

## Frontend

* React (Vite)  
* JavaScript  
* CSS  
* SVG Graph Rendering  

## Backend

* FastAPI  
* Python  
* NetworkX  
* SQLAlchemy  
* SQLite  

## Security

* AES-GCM Encryption  
* SHA-512 Hashing  
* HMAC Authentication  

## AI / Reasoning

* LLM-based RCA (optional OpenAI API)  
* Prompt Engineering  
* Structured JSON output  

---

# 📂 Project Structure

netrca-ai  
│  
├── backend  
│   ├── main.py  
│   ├── database.py  
│   ├── models.py  
│   ├── schemas.py  
│   │  
│   ├── services  
│   │   ├── ingestion_service.py  
│   │   ├── correlation_service.py  
│   │   ├── ai_service.py  
│   │   ├── queue_service.py  
│   │   └── audit_service.py  
│   │  
│   └── utils  
│       └── crypto_utils.py  
│  
├── frontend  
│   ├── src  
│   │   ├── App.jsx  
│   │   └── index.css  
│   └── vite.config.js  
│  
└── README.md  

---

# 🚀 How to Run the Project

##  Run Backend

cd backend  
uvicorn main:app --reload  

Backend runs on:  
http://127.0.0.1:8000  

---

##  Run Frontend

cd frontend  
npm install  
npm run dev  

Frontend runs on:  
http://localhost:5174  

---

# ⚡ Demo Flow

1. Click **Seed Demo Logs**  
2. Incidents are created automatically  
3. RCA runs in background  
4. View:  
   * Graph-based RCA  
   * SOC-style report  
   * Security evidence  

---

#  Example Output

✔ Root Cause Identification  
✔ Causal Chain (event sequence)  
✔ Graph Visualization (DAG)  
✔ AI Reasoning Steps  
✔ Risk Level & Confidence Score  
✔ Remediation Suggestions  

---

# 🌍 Impact

NetRCA AI helps:

* Reduce incident resolution time  
* Improve RCA accuracy  
* Provide explainable AI insights  
* Enable real-time monitoring  
* Enhance network security  

---

# 🔮 Future Improvements

* Real-time streaming (Kafka)  
* WebSocket live updates  
* CVE / MITRE ATT&CK integration  
* Multi-cloud support  
* Docker & Kubernetes deployment  
* Self-learning AI agent  

---

# ⚡ NetRCA AI – Intelligent RCA Powered by Graphs + AI
