def test_resource_listing(client):
    login_res = client.post("/api/v1/auth/login", json={"username": "rahul", "password": "dev123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/v1/resources", headers=headers)
    assert res.status_code == 200
    assert len(res.json()) >= 3

def test_resource_not_found(client):
    login_res = client.post("/api/v1/auth/login", json={"username": "rahul", "password": "dev123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/v1/resources/99999", headers=headers)
    assert res.status_code == 404
