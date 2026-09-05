"""
response_engine.py
-------------------
Member B deliverable: Simulated Response Engine

Maps a severity bucket (as returned by risk_engine.get_severity()) to a set
of SIMULATED SOC response recommendations. Nothing here performs a real
enforcement action (no account lockout, no real email, no real ticket) --
this is intentionally a recommendation/demo layer, matching the project's
MVP scope.

Usage:
    from risk_engine import calculate_risk_score, get_severity
    from response_engine import get_response

    score = calculate_risk_score(triggered_factors)
    severity = get_severity(score)
    response = get_response(severity, score)
"""

from typing import Dict, Any, Optional


# ---------------------------------------------------------------------------
# One response profile per severity bucket.
# "auto_action" is a SIMULATED action label only -- nothing executes it.
# ---------------------------------------------------------------------------

RESPONSE_PROFILES = {
    "Info": {
        "priority": "P4",
        "auto_action": "None",
        "recommended_actions": [
            "No action required.",
            "Log activity for baseline/behavioral history only.",
        ],
    },
    "Low": {
        "priority": "P3",
        "auto_action": "None",
        "recommended_actions": [
            "Add to user's activity log for trend monitoring.",
            "No immediate analyst review required.",
        ],
    },
    "Medium": {
        "priority": "P2",
        "auto_action": "Flag for review",
        "recommended_actions": [
            "Flag session for analyst review within 24 hours.",
            "Cross-check against user's recent activity history.",
            "No automatic restriction applied at this stage.",
        ],
    },
    "High": {
        "priority": "P1",
        "auto_action": "Notify SOC analyst (simulated)",
        "recommended_actions": [
            "Notify on-call SOC analyst immediately (simulated alert).",
            "Recommend step-up authentication (e.g. MFA re-prompt) on next action.",
            "Review session's accessed resources for sensitive data exposure.",
        ],
    },
    "Critical": {
        "priority": "P0",
        "auto_action": "Simulated session suspension + SOC escalation",
        "recommended_actions": [
            "Simulate immediate session suspension pending review.",
            "Escalate to SOC lead and account owner's manager (simulated).",
            "Recommend forced password reset and full MFA re-verification.",
            "Preserve session logs for incident investigation.",
        ],
    },
}


def get_response(severity: str, score: Optional[float] = None) -> Dict[str, Any]:
    """
    Return a simulated SOC response recommendation for a given severity bucket.

    Args:
        severity: one of "Info", "Low", "Medium", "High", "Critical"
                  (exact output of risk_engine.get_severity()).
        score: optional numeric score, used only to enrich the summary line.

    Returns:
        {
            "severity": str,
            "priority": str,            e.g. "P0" (most urgent) .. "P4" (least urgent)
            "auto_action": str,         simulated action label, not a real effect
            "recommended_actions": List[str],
            "summary": str,
        }
    """
    profile = RESPONSE_PROFILES.get(severity)

    if profile is None:
        # Unknown severity string -- fail safe with a manual-review response
        # rather than silently doing nothing.
        profile = {
            "priority": "P2",
            "auto_action": "Flag for manual review (unrecognized severity)",
            "recommended_actions": [
                f"Severity value '{severity}' not recognized -- route to analyst for manual triage.",
            ],
        }

    score_part = f" (score={score:.0f})" if score is not None else ""
    summary = f"[{profile['priority']}] {severity}{score_part} -> {profile['auto_action']}"

    return {
        "severity": severity,
        "priority": profile["priority"],
        "auto_action": profile["auto_action"],
        "recommended_actions": profile["recommended_actions"],
        "summary": summary,
    }


if __name__ == "__main__":
    for severity in ["Info", "Low", "Medium", "High", "Critical"]:
        result = get_response(severity, score={"Info": 5, "Low": 20, "Medium": 55, "High": 76, "Critical": 99}[severity])
        print(result["summary"])
        for action in result["recommended_actions"]:
            print("   -", action)
        print()
