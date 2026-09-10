def test_activity_logging_on_allowed_and_denied(client):
    # Admin login to check logs
    admin_login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
    admin_token = admin_login.json()["access_token"]

    # Intern performs allowed request
    intern_login = client.post("/api/v1/auth/login", json={"username": "aditi", "password": "intern123"})
    intern_token = intern_login.json()["access_token"]
    client.get("/api/v1/resources/1", headers={"Authorization": f"Bearer {intern_token}"})

    # Intern performs denied request
    client.get("/api/v1/resources/3", headers={"Authorization": f"Bearer {intern_token}"})

    # Query activity logs as admin
    logs_res = client.get("/api/v1/activities", headers={"Authorization": f"Bearer {admin_token}"})
    assert logs_res.status_code == 200
    logs = logs_res.json()
    assert len(logs) >= 2

    # Verify at least one allowed and one denied
    has_allowed = any(l["allowed"] is True and l["endpoint"].endswith("/resources/1") for l in logs)
    has_denied = any(l["allowed"] is False and l["status_code"] == 403 for l in logs)
    assert has_allowed
    assert has_denied

def test_suspicious_behavior_triggers_risk_and_alert(client):
    admin_login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
    admin_token = admin_login.json()["access_token"]

    intern_login = client.post("/api/v1/auth/login", json={"username": "aditi", "password": "intern123"})
    intern_token = intern_login.json()["access_token"]
    session_id = intern_login.json()["session_id"]

    # Trigger off-hours + unrecognized device + confidential permission violation
    suspicious_headers = {
        "Authorization": f"Bearer {intern_token}",
        "x-device-id": "adversary-kali-laptop-99",
        "x-simulated-hour": "23"
    }
    client.get("/api/v1/resources/3", headers=suspicious_headers)

    # Check session risk
    sess_res = client.get(f"/api/v1/sessions/{session_id}", headers={"Authorization": f"Bearer {intern_token}"})
    assert sess_res.status_code == 200
    risk = sess_res.json()["risk_score"]
    assert risk >= 45.0  # Alert threshold breached

    # Query alerts as admin
    alerts_res = client.get(f"/api/v1/alerts?session_id={session_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert["severity"] in ("medium", "high", "critical")
    assert "UNRECOGNIZED_DEVICE" in alert["evidence"]["triggered_rules"] or "PERMISSION_VIOLATION" in alert["evidence"]["triggered_rules"]
