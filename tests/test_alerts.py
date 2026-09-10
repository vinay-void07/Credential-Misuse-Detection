def test_intern_forbidden_from_viewing_alerts(client):
    intern_login = client.post("/api/v1/auth/login", json={"username": "aditi", "password": "intern123"})
    intern_token = intern_login.json()["access_token"]

    res = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {intern_token}"})
    assert res.status_code == 403
    assert "interns cannot access" in res.json()["detail"].lower()

def test_admin_can_update_alert_status(client):
    admin_login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Fetch alerts
    alerts_res = client.get("/api/v1/alerts", headers=admin_headers)
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    if len(alerts) > 0:
        alert_id = alerts[0]["id"]
        patch_res = client.patch(
            f"/api/v1/alerts/{alert_id}",
            json={"status": "investigating"},
            headers=admin_headers
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["status"] == "investigating"
