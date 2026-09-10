def test_valid_login(client):
    res = client.post("/api/v1/auth/login", json={"username": "aditi", "password": "intern123"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["role"] == "intern"
    assert data["username"] == "aditi"
    assert "session_id" in data

def test_invalid_password(client):
    res = client.post("/api/v1/auth/login", json={"username": "aditi", "password": "wrongpassword"})
    assert res.status_code == 401
    assert "Invalid" in res.json()["detail"]

def test_inactive_user_cannot_login(client):
    res = client.post("/api/v1/auth/login", json={"username": "banned", "password": "banned123"})
    assert res.status_code == 403
    assert "inactive" in res.json()["detail"].lower()

def test_auth_me_endpoint(client):
    login_res = client.post("/api/v1/auth/login", json={"username": "aditi", "password": "intern123"})
    token = login_res.json()["access_token"]
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["username"] == "aditi"

def test_missing_or_invalid_jwt(client):
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    res2 = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid.token.value"})
    assert res2.status_code == 401
