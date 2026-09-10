from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.models import User, Session as UserSession, Alert, ActivityLog
from app.detection.feature_engineering import extract_behavioral_features
from app.detection.isolation_forest import detector
from app.security.rules import evaluate_rules
from app.detection.explanation import generate_alert_explanation
from app.response.response_engine import get_recommended_response

class RiskEngine:
    """
    Central Risk Engine:
    Combines IsolationForest ML anomaly score (0-40) + Rule-based security signals (0-60)
    to generate an explainable 0-100 risk score and creates Alerts when thresholds are breached.
    """
    def evaluate_and_alert(
        self,
        db: Session,
        user_id: int,
        session_id: int,
        latest_activity: Optional[ActivityLog] = None,
        reference_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)

        # 1. Feature Engineering
        features = extract_behavioral_features(
            db=db,
            user_id=user_id,
            session_id=session_id,
            window_minutes=5,
            reference_time=reference_time
        )

        # 2. Machine Learning Anomaly Detection (IsolationForest)
        ml_result = detector.score_anomaly(features["vector"])

        # 3. Rule-based Evaluation
        rule_result = evaluate_rules(features)

        # 4. Composite Risk Score (0 - 100)
        # ML contribution: 0 - 40 points
        # Rule contribution: 0 - 60 points
        composite_score = round(ml_result["ml_score"] + rule_result["rule_score"], 2)
        composite_score = min(100.0, max(0.0, composite_score))

        # Determine severity level
        if composite_score >= settings.CRITICAL_THRESHOLD:
            severity = "critical"
        elif composite_score >= 65.0:
            severity = "high"
        elif composite_score >= settings.ALERT_THRESHOLD:
            severity = "medium"
        else:
            severity = "low"

        # Update Session state in DB
        user_session = db.query(UserSession).filter(UserSession.id == session_id).first()
        if user_session:
            user_session.risk_score = composite_score
            user_session.last_activity_at = reference_time
            if severity in ("critical", "high"):
                user_session.status = "suspicious"
            db.commit()

        # 5. Alert Generation
        alert_created = False
        alert_record = None
        if composite_score >= settings.ALERT_THRESHOLD:
            explanation_data = generate_alert_explanation(
                severity=severity,
                risk_score=composite_score,
                ml_result=ml_result,
                rule_result=rule_result,
                features=features
            )
            recommended_action = get_recommended_response(severity, composite_score)

            alert_record = Alert(
                user_id=user_id,
                session_id=session_id,
                severity=severity,
                risk_score=composite_score,
                alert_type=rule_result["triggered_rules"][0] if rule_result["triggered_rules"] else "BEHAVIORAL_ANOMALY",
                title=explanation_data["title"],
                description=explanation_data["description"],
                evidence=explanation_data["evidence"],
                recommended_action=recommended_action,
                created_at=reference_time,
                status="open"
            )
            db.add(alert_record)
            db.commit()
            db.refresh(alert_record)
            alert_created = True

        return {
            "risk_score": composite_score,
            "severity": severity,
            "ml_anomaly_score": ml_result["ml_score"],
            "rule_score": rule_result["rule_score"],
            "triggered_rules": rule_result["triggered_rules"],
            "features": features,
            "alert_created": alert_created,
            "alert_id": alert_record.id if alert_record else None
        }

risk_engine = RiskEngine()
