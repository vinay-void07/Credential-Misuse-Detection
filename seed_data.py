from database import (
    create_tables,
    insert_user,
    insert_activity_log,
    insert_model_result,
    insert_alert
)


def seed_database():
    create_tables()

    # Create users
    arun_id = insert_user(
        "Arun",
        "Employee",
        "Finance",
        "Normal working hours: 09:00-18:00"
    )

    ravi_id = insert_user(
        "Ravi",
        "Manager",
        "HR",
        "Normal working hours: 09:00-18:00"
    )

    priya_id = insert_user(
        "Priya",
        "Administrator",
        "IT",
        "Normal working hours: 08:30-17:30"
    )

    # Arun - normal activity
    log1 = insert_activity_log(
        user_id=arun_id,
        timestamp="2026-08-25 09:30:00",
        action_type="LOGIN",
        resource_accessed="company_portal",
        ip_address="192.168.1.10",
        session_info="session_001"
    )

    insert_model_result(
        log_id=log1,
        anomaly_score=0.42,
        is_anomaly=0,
        model_version="IF_v1",
        scored_at="2026-08-25 09:31:00"
    )

    # Ravi - normal activity
    log2 = insert_activity_log(
        user_id=ravi_id,
        timestamp="2026-08-25 10:00:00",
        action_type="FILE_ACCESS",
        resource_accessed="hr_report.xlsx",
        ip_address="192.168.1.20",
        session_info="session_002"
    )

    insert_model_result(
        log_id=log2,
        anomaly_score=0.35,
        is_anomaly=0,
        model_version="IF_v1",
        scored_at="2026-08-25 10:01:00"
    )

    # Priya - suspicious activity
    log3 = insert_activity_log(
        user_id=priya_id,
        timestamp="2026-08-25 23:45:00",
        action_type="DOWNLOAD",
        resource_accessed="employee_salary_data.xlsx",
        ip_address="10.10.10.99",
        session_info="session_003"
    )

    insert_model_result(
        log_id=log3,
        anomaly_score=-0.72,
        is_anomaly=1,
        model_version="IF_v1",
        scored_at="2026-08-25 23:46:00"
    )

    insert_alert(
        user_id=priya_id,
        log_id=log3,
        risk_score=91,
        severity_bucket="Critical",
        triggered_features="after_hours,large_download,new_ip",
        explanation_text=(
            "Unusual file download detected outside normal "
            "working hours from a new IP address."
        ),
        status="open",
        created_at="2026-08-25 23:46:00"
    )

    print("Seed data inserted successfully!")


if __name__ == "__main__":
    seed_database()