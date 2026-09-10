import os
import sys

# Ensure root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database.database import SessionLocal
from app.database.models import User, Resource, Permission
from app.core.security import hash_password

def seed_database():
    db = SessionLocal()
    try:
        print("[*] Seeding database with initial users, resources, and permissions...")

        # 1. Seed Permissions Table for reference/documentation
        permission_entries = [
            ("intern", "public", "read"),
            ("intern", "internal", "read"),
            ("intern", "confidential", "denied"),
            ("senior_dev", "public", "read"),
            ("senior_dev", "internal", "read,write,download,update"),
            ("senior_dev", "confidential", "read,download"),
            ("admin", "public", "full"),
            ("admin", "internal", "full"),
            ("admin", "confidential", "full"),
        ]
        for role, sens, actions in permission_entries:
            exists = db.query(Permission).filter(
                Permission.role == role,
                Permission.sensitivity == sens
            ).first()
            if not exists:
                db.add(Permission(role=role, sensitivity=sens, allowed_actions=actions))

        # 2. Seed Users
        users_data = [
            {"username": "aditi", "email": "aditi@prism.corp", "role": "intern", "password": "password123"},
            {"username": "rahul", "email": "rahul@prism.corp", "role": "senior_dev", "password": "password123"},
            {"username": "admin", "email": "admin@prism.corp", "role": "admin", "password": "AdminPassword123!"}
        ]

        users_map = {}
        for u in users_data:
            existing_user = db.query(User).filter(User.username == u["username"]).first()
            if not existing_user:
                new_user = User(
                    username=u["username"],
                    email=u["email"],
                    password_hash=hash_password(u["password"]),
                    role=u["role"],
                    is_active=True
                )
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                users_map[u["username"]] = new_user
                print(f"[+] Created user: {u['username']} (role: {u['role']})")
            else:
                users_map[u["username"]] = existing_user
                print(f"[-] User {u['username']} already exists.")

        # 3. Seed Resources (public, internal, confidential)
        resources_data = [
            # Public
            ("Company Handbook 2026", "General employment guidelines, office policies, and culture", "public", "document"),
            ("Corporate Code of Ethics", "Code of conduct, compliance, and reporting ethics", "public", "document"),
            ("Public API Documentation", "Public REST API guidelines and developer specifications", "public", "document"),
            ("Brand Guidelines & Assets", "Logo usage, color palettes, and typography", "public", "document"),
            ("Annual Public Social Report", "Corporate sustainability and social impact report", "public", "document"),

            # Internal
            ("Engineering Onboarding Guide", "Development environment setup, git workflow, and linting rules", "internal", "document"),
            ("Architecture Overview Diagram", "High level microservice architecture and data flow", "internal", "document"),
            ("Internal API Service Catalog", "Internal service endpoints, gRPC protos, and SLA documentation", "internal", "document"),
            ("Database Migration Playbook", "Steps for safely executing Alembic schema migrations", "internal", "document"),
            ("DevOps CI/CD Deployment Guide", "GitHub Actions pipeline configurations and release process", "internal", "document"),
            ("Frontend Component Library Docs", "Design system UI patterns and React component API", "internal", "document"),
            ("Incident Postmortem Guidelines", "Blameless postmortem template and incident response procedures", "internal", "document"),
            ("QA Testing Framework Manual", "Integration testing guidelines and Playwright test setup", "internal", "document"),
            ("Office Network WiFi Config", "VPN client configuration and internal wireless setup", "internal", "document"),
            ("Code Review Best Practices", "Pull request review checklist and security guidelines", "internal", "document"),
        ]

        # Confidential Resources (50 distinct items for realistic bulk download scenarios)
        confidential_items = [
            ("HR Salary Compensation Master 2026", "Executive and employee salary tables with bonus bands"),
            ("Q3 Financial Balance Sheet & Earnings", "Unreleased quarterly financial statements and projections"),
            ("Production DB Root Master Credentials", "Emergency access tokens and database master passwords"),
            ("Strategic M&A Acquisition Target Dossier", "Confidential corporate acquisition proposals and valuations"),
            ("Customer PII & Payment Token Vault", "PCI-DSS encrypted cardholder token mappings"),
            ("Legal Defense Strategy - Patent Lawsuit", "Attorney-client privileged litigation briefs"),
            ("Board of Directors Private Meeting Minutes", "Executive committee meeting minutes and strategic voting records"),
            ("Internal Audit Vulnerability Assessment", "Penetration test findings with unpatched zero-day vulnerabilities"),
            ("Core Trading Algorithm Source Code", "Proprietary algorithmic execution strategies"),
            ("Enterprise Client Master Service Agreements", "Client contract fee schedules and non-disclosure terms"),
            ("Key Management Service (KMS) Root Keypairs", "Hardware security module (HSM) export bundles"),
            ("Tax Filing & Offshore Holdings Audit", "Internal revenue audit and treasury bank records"),
            ("Health Insurance & Medical Leave Claims", "Employee private HIPAA medical leaves and health claims"),
            ("Supply Chain Supplier Pricing Contracts", "Raw material wholesale cost negotiations"),
            ("Disaster Recovery Plan with Site Passcodes", "Physical data center floor access codes and biometric backups")
        ]

        # Extend with numbered confidential documents to support bulk downloads
        for i in range(1, 40):
            confidential_items.append((
                f"Confidential Customer Audit Record #{1000 + i}",
                f"Confidential enterprise compliance audit record file #{1000 + i}"
            ))

        for name, desc in confidential_items:
            resources_data.append((name, desc, "confidential", "document"))

        admin_user = users_map.get("admin")
        admin_id = admin_user.id if admin_user else 1

        added_count = 0
        for name, desc, sensitivity, r_type in resources_data:
            existing = db.query(Resource).filter(Resource.name == name).first()
            if not existing:
                res = Resource(
                    name=name,
                    description=desc,
                    resource_type=r_type,
                    sensitivity=sensitivity,
                    owner_id=admin_id,
                    file_size_kb=256
                )
                db.add(res)
                added_count += 1

        db.commit()
        print(f"[+] Seeding complete! Added {added_count} resources.")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
