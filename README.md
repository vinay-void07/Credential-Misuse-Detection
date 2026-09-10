# Prism Network – Real-Time Credential Misuse Detection System

## 1. Project Overview & Problem Statement
Traditional cybersecurity architectures stop at authentication:
> *Does the incoming request provide a valid username, password, and unexpired JWT?*

However, modern cyberattacks frequently involve **compromised legitimate credentials** — through phishing, session token theft, infostealer malware, compromised developer workstations, or insider threats. Once an attacker obtains valid credentials, traditional access control models treat every incoming request as legitimate.

**Prism Network** is a cybersecurity system built to detect **credential misuse and abnormal behavioral patterns even when valid credentials are being used**.

The system strictly decouples:
1. **Authentication**: *who are you?* (Verified via bcrypt password hashing, JWT creation, and server-side session persistence).
2. **Authorization**: *are you allowed to do this?* (Enforced server-side via explicit RBAC permission matrix for intern, senior_dev, and admin roles).
3. **Activity Logging**: *what did you do?* (Automatic auditing of every HTTP request, status code, IP, and deterministic device fingerprinting).
4. **Behavioral Detection**: *is this behavior abnormal?* (Feature extraction across rolling windows fed to scikit-learn IsolationForest).
5. **Risk Engine**: *how risky is this behavior?* (Hybrid scoring combining ML anomaly points [0–40] and rule-based security signals [0–60] on a calibrated 0–100 scale).
6. **Alert System**: *should security investigate?* (Evidence-based alert generation with transparent triggers).
7. **Response Engine**: *what should security do next?* (Actionable operational recommendations, including immediate server-side session termination).

---

## 2. System Architecture & Request Flow

16 Kernel Components interact as follows:
1. Real HTTP Request arrives at FastAPI.
2. ActivityLoggerMiddleware starts timer, resolves client IP and device fingerprint (SHA-256).
3. Auth Dependencies verify JWT token and confirm the session is ACTIVE in SQLite (Blocks terminated sessions with HTTP 401).
4. RBAC Permission Guard checks role versus resource sensitivity (Intern requesting Confidential receives HTTP 403 Forbidden).
5. Response is returned to the client.
6. Middleware finally block posts an ActivityLog record (whether access was allowed or denied).
7. Feature Engineering extracts 10 rolling window metrics from ActivityLogs.
8. RsilationForest ML (0 - 40 points) and Rule Engine (0 - 60 points) compute a composite 0-100 risk score.
9. If risk >= 45, an Alert is generated in the database with full evidence and response guidance.

---

## 3. Technology Stack

* **Backend Framework**: FastAPI (0.115+) with Uvicorn
 * **Database & ORM**: SQLite with SQLAlchemy 2.0
* **Authentication & Cryptography**: PyJWT (HMAC-SHA256) & bcrypt via binary extension
* **Machine Learning**: scikit-learn (IsolationForest), NumPy, joblib
 * **Data Schemas**: Pydantic v2
 * **Testing & HTTP Simulation**: pytest & HTTPX


---

## 4. Running the Application & Verification

### 1. Initialize & Seed Database
```powershell
cd D:\prism-network
python scripts\init_db.py
python scripts\seed_data.py
python scripts\train_model.py
```

### 2. Run All 15 Automated Tests
```powershell
pytest -v tests/
```

### 3. Start Backend Server
`l``powershell
python run.py
```
* **Swagger UI**: http://127.0.0.1:8000/docs
* **ReDoc UI**: http://127.0.0.1:8000/redoc
* **Health Check**: http://127.0.0.1:8000/health

### 4. Run the End-to-End Demo
Start a second terminal window3
```powershell
python scripts\demo.py
```

---

## 5. Demo Scenarios & Results

| Scenario | Actor & Credentials | Action / Trigger | RBAC Result | Risk Score | Alerts | Response |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Scenario 1: Normal User | aditi (Intern)<br>Valid JWT | Views internal docs during work hours | ALLOWED (200) | 0.98 / 100 | 0 | Normal baseline. Continue monitoring. |
| Scenario 2: Suspicious Intern | aditi (Intern)<br>Valid JWT | Accesses executive payroll off-hours from new device | DENIED (403) | 75.54 / 100 | 1 (High) | RBAC blocks access. Alert recommends MTA. |
| Scenario 3: Valid Credential Misuse | rahul (Senior Dev)<br>Valid JWT | Rapidly downloads 22+ confidential documents | ALLOWED (200) | 78.54 / 100 | 14 (Critical/High) | RBAC allows, but ML & Rules flag bulk exfiltration. Alert recommends session termination. |
| Scenario 4: Incident Response | Attacker holding Rahul's JWT | Admin terminates session; attacker tries another download | BLOCKED (401) | — | — | Session terminated server-side. Token invalidated. |
