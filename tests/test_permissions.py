def test_intern_access_public_and_internal(client):
    login_res = client.post("/api/v1/auth/login", json={"username": "aditi", "password": "intern123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Public: allowed
    res_pub = client.get("/api/v1/resources/1", headers=headers)
    assert res_pub.status_code == 200

    # Internal: allowed
    res_int = client.get("/api/v1/resources/2", headers=headers)
    assert res_int.status_code == 200

def test_intern_denied_confidential_resource(client):
    login_res = client.post("/api/v1/auth/login", json={"username": "aditi", "password": "intern123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Confidential resource #3 should return 403 Forbidden
    res_conf = client.get("/api/v1/resources/3", headers=headers)
    assert res_conf.status_code == 403
    assert "Permission denied" in res_conf.json()["detail"]

def test_senior_dev_can_access_confidential(client):
    login_res = client.post("/api/v1/auth/login", json={"username": "rahul", "password": "dev123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Senior dev allowed to read confidential
    res = client.get("/api/v1/resources/3", headers=headers)
    assert res.status_code == 200
    assert res.json()["sensitivity"] == "confidential"

    # Senior dev allowed to download confidential
    dl_res = client.get("/api/v1/resources/3/download", headers=headers)
    assert dl_res.status_code == 200
    assert "download_timestamp" in dl_res.json()
