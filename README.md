# Credential-Misuse-Detection
 A mini project focused on identifying and analyzing credential misuse to improve authentication security and detect unauthorized access attempts.
 Sure — for your **AI Credential Misuse Detection** department project, I’d keep the README student-level, practical, and focused on the **working product**, not research claims.

# AI-Based Credential Misuse Detection System

## 📌 Project Overview

The **AI-Based Credential Misuse Detection System** is a cybersecurity project designed to identify suspicious activity caused by the misuse of legitimate user credentials.

In many organizations, an attacker or unauthorized person may use valid usernames and passwords to access systems. Since the credentials are legitimate, traditional security mechanisms may not immediately identify the activity as malicious.

Our system analyzes user activity logs and uses **machine learning-based anomaly detection** to identify unusual behavior and generate a risk score for users.

The project is implemented as a **working student-level prototype** that demonstrates how AI and data analysis can assist in detecting possible credential misuse.

---

## 🎯 Objectives

* Monitor user activity through system logs.
* Establish a baseline of normal user behavior.
* Detect unusual or suspicious activities.
* Calculate a risk score for users.
* Classify activities/users based on their risk level.
* Provide security alerts for potentially suspicious behavior.
* Store activity and prediction results in a database.
* Display the results through a simple dashboard.

---

## 🏗️ System Architecture

```text
                    ┌─────────────────────┐
                    │   User Activity     │
                    │       Logs          │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Data Collection   │
                    │    & Processing     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Feature Extraction  │
                    │                     │
                    │ • Login frequency   │
                    │ • Access time       │
                    │ • IP address        │
                    │ • Resource access   │
                    │ • Session activity  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ ML / Anomaly        │
                    │ Detection Model     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Risk Score &        │
                    │ Classification      │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
        ┌─────────────────┐         ┌─────────────────┐
        │ Security Alert  │         │    Dashboard    │
        └─────────────────┘         └─────────────────┘
```

---

## 🔑 Main Features

### 1. User Activity Monitoring

The system records activities such as:

* Login/logout
* Login time
* IP address
* Resource accessed
* Access frequency
* Session information
* Action type

### 2. User Behavior Analysis

The collected activity is converted into useful features that represent the user's normal behavior.

Examples:

* Number of logins
* Login time patterns
* Number of resources accessed
* Unusual resource access
* Changes in IP address
* Session duration
* Frequency of activity

### 3. Anomaly Detection

The machine learning component analyzes the extracted features and identifies activities that differ significantly from normal behavior.

### 4. Risk Scoring

A risk score is generated based on suspicious activity.

Example:

```text
0 – 30    → Low Risk
31 – 70   → Medium Risk
71 – 100  → High Risk
```

### 5. Alert Generation

When suspicious activity crosses a predefined threshold, the system generates an alert for further investigation.

### 6. Dashboard

A simple dashboard displays:

* Total users
* Total activities
* Suspicious activities
* High-risk users
* Risk scores
* Recent alerts

---

## 🗄️ Database

The project uses **SQLite** for storing system data.

Main tables include:

```text
users
activity_logs
model_results
alerts
```

### Users

Stores information about system users.

```text
user_id
name
role
department
baseline_metadata
```

### Activity Logs

Stores user activities.

```text
log_id
user_id
timestamp
action_type
resource_accessed
ip_address
session_info
raw_data
```

### Model Results

Stores machine learning predictions.

```text
result_id
user_id
timestamp
anomaly_score
risk_score
risk_level
prediction
```

### Alerts

Stores generated security alerts.

```text
alert_id
user_id
timestamp
alert_type
severity
description
status
```

---

## 🤖 Machine Learning

The machine learning module uses user activity features to identify abnormal behavior.

The general workflow is:

```text
Raw Logs
   ↓
Data Cleaning
   ↓
Feature Extraction
   ↓
Feature Scaling
   ↓
Model Prediction
   ↓
Anomaly Score
   ↓
Risk Score
   ↓
Alert
```

The model can be trained using cybersecurity activity datasets such as the **CMU CERT Insider Threat Dataset** or generated/synthetic activity data.

---

## 🛠️ Technology Stack

### Frontend / Dashboard

* Python
* Streamlit

### Backend

* Python
* FastAPI

### Database

* SQLite

### Machine Learning

* Python
* Pandas
* NumPy
* Scikit-learn

### Development Tools

* VS Code
* Git
* GitHub

---

## 📂 Project Structure

```text
credential-misuse-detection/
│
├── backend/
│   ├── app.py
│   ├── database.py
│   ├── models.py
│   └── routes/
│
├── ml/
│   ├── preprocessing.py
│   ├── feature_engineering.py
│   ├── train.py
│   └── predict.py
│
├── data/
│   ├── raw/
│   └── processed/
│
├── dashboard/
│   └── app.py
│
├── database/
│   └── credential_misuse.db
│
├── models/
│   └── trained_model.pkl
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 🚀 How to Run

### 1. Clone the Repository

```bash
git clone <repository-url>
cd credential-misuse-detection
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Initialize the Database

```bash
python database/database.py
```

### 5. Run the Backend

```bash
uvicorn backend.app:app --reload
```

### 6. Run the Dashboard

```bash
streamlit run dashboard/app.py
```

---

## 📊 Example Detection

A normal user might have:

```text
Login Time:       09:15 AM
IP Address:       192.168.1.10
Resources:        4
Session Duration: 35 minutes
Risk Score:       18
Risk Level:       LOW
```

A potentially suspicious user might have:

```text
Login Time:       02:47 AM
IP Address:       Different IP
Resources:        25
Session Duration: 180 minutes
Risk Score:       86
Risk Level:       HIGH
```

The second activity can trigger a security alert for investigation.

---

## 🔐 Security Considerations

This project is intended as an **educational prototype**.

It does not automatically block users or terminate accounts. A high-risk prediction should be treated as an indication for further investigation rather than proof that a user is malicious.

---

## 🎓 Project Scope

This project focuses on building a practical prototype that demonstrates:

* Cybersecurity monitoring
* User behavior analysis
* Machine learning
* Anomaly detection
* Database management
* API development
* Dashboard visualization

The goal is to demonstrate how these technologies can be combined into a simple credential misuse detection system.

---

## 🔮 Future Enhancements

Possible future improvements include:

* Real-time log monitoring
* More advanced anomaly detection models
* Real-time notifications
* Email/SMS alerts
* Role-based access control
* Integration with SIEM systems
* Explainable AI for individual risk scores
* Continuous user behavior profiling
* Deployment on cloud infrastructure

---

## 👥 Project Type

**Department Mini/Major Project — Student-Level Implementation**

This project is developed for educational purposes to demonstrate the practical application of **Artificial Intelligence, Machine Learning, Database Systems, Backend APIs, and Cybersecurity**.

---

## 📜 Disclaimer

This project is intended strictly for educational and defensive cybersecurity purposes. It should only be used with authorized data, systems, and user activity.

