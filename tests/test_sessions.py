def test_session_lifecycle_and_termination(client):
    login_res = client.post("/api/v1/auth/login", json={"username": "aditi", "password": "intern123"})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    session_id = login_res.json()["session_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify session query
    s_res = client.get(f"/api/v1/sessions/{session_id}", headers=headers)
    assert s_res.status_code == 200
    assert s_res.json()["status"] == "active"

    # Terminate session
    term_res = client.post(f"/api/v1/sessions/{session_id}/terminate", headers=headers)
    assert term_res.status_code == 200
    assert term_res.json()["status"] == "terminated"

    # Protected request with same token must now return 401 Unauthorized
    failed_req = client.get("/api/v1/resources/1", headers=headers)
    assert failed_req.status_code == 401
    assert "terminated" in failed_req.json()["detail"].lower()
