import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database.database import Base, get_db
from app.main import app
from app.core.security import hash_password
from app.database.models import User, Resource, Permission

TEST_DB_URL = "sqlite:///D:/prism-network/data/test_prism.db"
engine_test = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine_test)

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.drop_all(bind=engine_test)
    Base.metadata.create_all(bind=engine_test)
    db = TestingSessionLocal()
    try:
        # Permissions
        db.add_all([
            Permission(role="intern", sensitivity="public", allowed_actions="read"),
            Permission(role="intern", sensitivity="internal", allowed_actions="read"),
            Permission(role="intern", sensitivity="confidential", allowed_actions="denied"),
            Permission(role="senior_dev", sensitivity="public", allowed_actions="read"),
            Permission(role="senior_dev", sensitivity="internal", allowed_actions="read,write,download,update"),
            Permission(role="senior_dev", sensitivity="confidential", allowed_actions="read,download"),
            Permission(role="admin", sensitivity="public", allowed_actions="full"),
            Permission(role="admin", sensitivity="internal", allowed_actions="full"),
            Permission(role="admin", sensitivity="confidential", allowed_actions="full"),
        ])
        # Users
        admin_u = User(username="admin", email="admin@test.com", password_hash=hash_password("admin123"), role="admin", is_active=True)
        intern_u = User(username="aditi", email="aditi@test.com", password_hash=hash_password("intern123"), role="intern", is_active=True)
        dev_u = User(username="rahul", email="rahul@test.com", password_hash=hash_password("dev123"), role="senior_dev", is_active=True)
        inactive_u = User(username="banned", email="banned@test.com", password_hash=hash_password("banned123"), role="intern", is_active=False)
        db.add_all([admin_u, intern_u, dev_u, inactive_u])
        db.commit()

        # Resources
        res_pub = Resource(name="Public Handbook", sensitivity="public", resource_type="document", owner_id=admin_u.id)
        res_int = Resource(name="Internal Arch", sensitivity="internal", resource_type="document", owner_id=admin_u.id)
        res_conf = Resource(name="Confidential Salaries", sensitivity="confidential", resource_type="document", owner_id=admin_u.id)
        db.add_all([res_pub, res_int, res_conf])
        db.commit()
    finally:
        db.close()
    yield
    # Teardown
    Base.metadata.drop_all(bind=engine_test)
    if os.path.exists("D:/prism-network/data/test_prism.db"):
        try:
            os.remove("D:/prism-network/data/test_prism.db")
        except Exception:
            pass

@pytest.fixture
def client():
    app.state.db_factory = TestingSessionLocal
    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()