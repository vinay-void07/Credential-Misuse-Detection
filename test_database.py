from database import (
    get_user_count,
    get_activity_count,
    get_anomaly_count,
    get_open_alert_count,
    get_recent_activity,
    get_recent_alerts,
    get_alerts_by_user
)


print("===== DATABASE TEST =====")

print("\nDashboard Summary")
print("-----------------")
print("Users:", get_user_count())
print("Activities:", get_activity_count())
print("Anomalies:", get_anomaly_count())
print("Open Alerts:", get_open_alert_count())


print("\nRecent Activity")
print("----------------")

activities = get_recent_activity()

for activity in activities:
    print(
        f"{activity['name']} | "
        f"{activity['action_type']} | "
        f"{activity['resource_accessed']}"
    )


print("\nRecent Alerts")
print("-------------")

alerts = get_recent_alerts()

for alert in alerts:
    print(
        f"{alert['name']} | "
        f"Risk: {alert['risk_score']} | "
        f"Severity: {alert['severity_bucket']} | "
        f"Status: {alert['status']}"
    )


print("\n===== TEST COMPLETE =====")