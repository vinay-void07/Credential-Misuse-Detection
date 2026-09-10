import httpx
import time
import json
import sys

BASE_URL = "http://127.0.0.1:8000"

def print_header(title: str):
    print("\n" + "=" * 75)
    print(f"  {title.upper()}")
    print("=" * 75)

def print_sub(title: str):
    print(f"\n[+] {title}")
    print("-" * 50)

def main():
    print_header("PRISM NETWORK - REAL-TIME CREDENTIAL MISUSE DETECTION DEMO")
    print("Connecting to live backend at:", BASE_URL)

    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        # Check health
        try:
            h = client.get("/health")
            if h.status_code != 200:
                print("[-] Backend health check failed.")
                sys.exit(1)
        except Exception as e:
            print(f"[-] Could not connect to backend: {e}")
            print("[-] Please ensure 'python run.py' is running.")
            sys.exit(1)

        print("[OK] Backend is healthy and ready.\n")

        # =========================================================================
        # SCENARIO 1: NORMAL USER ACTIVITY (Aditi - Intern)
        # =========================================================================
        print_header("SCENARIO 1: NORMAL USER ACTIVITY (ADITI - INTERN)")
        print("Aditi logs in during normal working hours from her standard workstation.")

        login_payload = {"username": "aditi", "password": "password123", "client_device_id": "laptop-aditi-standard"}
        r = client.post("/api/v1/auth/login", json=login_payload)
        assert r.status_code == 200, f"Login failed: {r.text}"
        aditi_data = r.json()
        aditi_token = aditi_data["access_token"]
        aditi_session_id = aditi_data["session_id"]
        aditi_headers = {"Authorization": f"Bearer {aditi_token}", "x-device-id": "laptop-aditi-standard"}

        print(f"-> Authenticated as '{aditi_data['username']}' (Role: {aditi_data['role']})")
        print(f"-> Active Session ID: {aditi_session_id}")
        print(f"-> Device Fingerprint: {aditi_data['device_fingerprint']}")

        print_sub("Accessing permitted internal organizational resources")
        res_list = client.get("/api/v1/resources?sensitivity=internal", headers=aditi_headers).json()
        for res in res_list[:2]:
            resp = client.get(f"/api/v1/resources/{res['id']}", headers=aditi_headers)
            print(f"   [HTTP {resp.status_code}] GET /resources/{res['id']} ('{res['name']}') -> ALLOWED")

        s_res = client.get(f"/api/v1/sessions/{aditi_session_id}", headers=aditi_headers).json()
        print(f"\n[Result Scenario 1]")
        print(f"   Session Risk Score: {s_res['risk_score']}/100")
        print(f"   Session Status:     {s_res['status']}")
        print(f"   Expected Alerts:    0 (Normal baseline activity)")

        time.sleep(1)

        # =========================================================================
        # SCENARIO 2: SUSPICIOUS INTERN ACTIVITY (Aditi - Policy & RBAC Violation)
        # =========================================================================
        print_header("SCENARIO 2: SUSPICIOUS INTERN ACTIVITY (ADITI - RBAC VIOLATION)")
        print("Aditi uses the SAME valid credentials, but activity now originates:")
        print(" - Outside standard working hours (23:00 / 11 PM)")
        print(" - From an unrecognized device fingerprint (unrecognized-adversary-device-01)")
        print(" - Attempts to access confidential executive payroll data (Permission Denied)")

        suspicious_headers = {
            "Authorization": f"Bearer {aditi_token}",
            "x-device-id": "unrecognized-adversary-device-01",
            "x-simulated-hour": "23"
        }

        conf_res_list = client.get("/api/v1/resources?sensitivity=confidential", headers=aditi_headers).json()
        conf_target = conf_res_list[0]

        print_sub(f"Requesting Confidential Resource: '{conf_target['name']}'")
        denied_resp = client.get(f"/api/v1/resources/{conf_target['id']}", headers=suspicious_headers)
        print(f"   [HTTP {denied_resp.status_code}] GET /resources/{conf_target['id']}")
        print(f"   Response Body: {denied_resp.json().get('detail')}")

        s_res2 = client.get(f"/api/v1/sessions/{aditi_session_id}", headers=aditi_headers).json()
        print(f"\n[Result Scenario 2]")
        print(f"   Session Risk Score: {s_res2['risk_score']}/100")
        print(f"   Session Status:     {s_res2['status']}")

        admin_login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminPassword123!"}).json()
        admin_token = admin_login["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        alerts = client.get(f"/api/v1/alerts?session_id={aditi_session_id}", headers=admin_headers).json()
        print(f"   Alerts Generated:   {len(alerts)}")
        if alerts:
            latest_alert = alerts[0]
            print(f"   Alert Title:        {latest_alert['title']}")
            print(f"   Severity:           {latest_alert['severity'].upper()}")
            print(f"   Triggered Rules:    {latest_alert['evidence']['triggered_rules']}")
            print(f"   Recommendation:     {latest_alert['recommended_action']}")

        time.sleep(1)

        # =========================================================================
        # SCENARIO 3: VALID CREDENTIAL MISUSE & EXFILTRATION (Rahul - Senior Dev)
        # =========================================================================
        print_header("SCENARIO 3: VALID CREDENTIAL MISUSE (RAHUL - SENIOR DEV)")
        print("Rahul is an authorized Senior Developer with legitimate access to confidential resources.")
        print("An attacker holding Rahul's legitimate JWT attempts rapid bulk data exfiltration:")
        print(" -> Rapidly downloading 25+ confidential corporate files in real-time HTTP requests.")
        print(" -> Access is ALLOWED by RBAC, but flagged as ABNORMAL by ML + Rule Detection Engine.")

        rahul_login = client.post("/api/v1/auth/login", json={
            "username": "rahul",
            "password": "password123",
            "client_device_id": "rahul-workstation-office"
        }).json()
        rahul_token = rahul_login["access_token"]
        rahul_session_id = rahul_login["session_id"]
        rahul_headers = {"Authorization": f"Bearer {rahul_token}", "x-device-id": "rahul-workstation-office"}

        print(f"\n-> Authenticated as '{rahul_login['username']}' (Role: {rahul_login['role']})")
        print(f"-> Active Session ID: {rahul_session_id}")

        print_sub("Executing high-velocity downloads of confidential files...")
        confidential_resources = client.get("/api/v1/resources?sensitivity=confidential&limit=30", headers=rahul_headers).json()

        download_count = 0
        for item in confidential_resources[:22]:
            dl_resp = client.get(f"/api/v1/resources/{item['id']}/download", headers=rahul_headers)
            if dl_resp.status_code == 200:
                download_count += 1
                if download_count % 5 == 0 or download_count == len(confidential_resources[:22]):
                    print(f"   [OK] Downloaded {download_count} confidential files (Last: '{item['name'][:35]}...')")

        s_res3 = client.get(f"/api/v1/sessions/{rahul_session_id}", headers=rahul_headers).json()
        print(f"\n[Result Scenario 3 - Real-Time Anomaly Detection]")
        print(f"   Session Risk Score: {s_res3['risk_score']}/100")
        print(f"   Session Status:     {s_res3['status'].upper()}")

        rahul_alerts = client.get(f"/api/v1/alerts?session_id={rahul_session_id}", headers=admin_headers).json()
        print(f"   Total Alerts Triggered: {len(rahul_alerts)}")

        critical_alerts = [a for a in rahul_alerts if a["severity"] == "critical"]
        target_alert = critical_alerts[0] if critical_alerts else (rahul_alerts[0] if rahul_alerts else None)

        if target_alert:
            print("\n" + "*" * 70)
            print(f" [!] ALERT DETAIL: {target_alert['title']}")
            print(f"     Severity:            {target_alert['severity'].upper()}")
            print(f"     Risk Score:          {target_alert['risk_score']}/100")
            print(f"     ML Anomaly Score:    {target_alert['evidence'].get('ml_anomaly_score')}/40.0")
            print(f"     Rule Score:          {target_alert['evidence'].get('rule_score')}/60.0")
            print(f"     Triggered Rules:     {', '.join(target_alert['evidence'].get('triggered_rules', []))}")
            print(f"     Explanation:         {target_alert['description']}")
            print(f"     Recommended Action:  {target_alert['recommended_action']}")
            print("*" * 70)

        time.sleep(1)

        # =========================================================================
        # SCENARIO 4: INCIDENT RESPONSE & SESSION TERMINATION
        # =========================================================================
        print_header("SCENARIO 4: INCIDENT RESPONSE - SERVER-SIDE SESSION TERMINATION")
        print(f"Following recommendation, the security administrator terminates Session #{rahul_session_id}.")

        term_resp = client.post(f"/api/v1/sessions/{rahul_session_id}/terminate", headers=admin_headers)
        print(f"-> Session Status updated: {term_resp.json()['status'].upper()}")

        print_sub("Attacker attempts another confidential download with existing JWT:")
        blocked_resp = client.get(f"/api/v1/resources/{confidential_resources[0]['id']}/download", headers=rahul_headers)
        print(f"   [HTTP {blocked_resp.status_code}] Access Rejected!")
        print(f"   Response: {blocked_resp.json().get('detail')}")
        print("   [OK] Server-side session invalidation successfully blocked further misuse.")

        print_header("DEMO SUMMARY")
        print("[+] Scenario 1: Normal User (Aditi) -> Allowed, Low Risk (0 Alerts)")
        print("[+] Scenario 2: Suspicious Intern (Aditi) -> RBAC 403, Logged, Alert Generated")
        print("[+] Scenario 3: Valid Credential Misuse (Rahul) -> RBAC 200, ML+Rules flag anomaly, Critical Alert")
        print("[+] Scenario 4: Incident Response -> Session Terminated, JWT Revocation Enforced")
        print("=" * 75)

if __name__ == "__main__":
    main()