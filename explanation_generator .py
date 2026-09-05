from risk_engine import RISK_WEIGHTS

"""
explanation_generator.py
-------------------------
Member B deliverable: Explanation Generator

Consumes the exact same `triggered_factors` dict that risk_engine.py's
calculate_risk_score() takes:

    {
        "ml_anomaly": 0.7,             # float 0-1 intensity
        "off_hours": True,             # bool
        "unusual_location": True,
        "high_volume_access": False,
        "sensitive_resource": True,
        "privilege_escalation": False,
        "failed_auth_attempts": False,
        "rare_action_for_user": True,
    }

Weights are pulled directly from RISK_WEIGHTS in risk_engine.py (not
duplicated here), so this file automatically stays in sync if the weights
change.

Priority = weight * value (bool True == 1, False == 0; float used as-is).
This mirrors exactly how calculate_risk_score() computes each factor's
contribution to the final score, so "highest-contributing first" here means
the same thing it means in the score itself.
"""

from typing import Dict, Union, List, Optional


# ---------------------------------------------------------------------------
# One template per factor (the 8 keys currently in RISK_WEIGHTS).
# Each is a function: value (bool or float) -> sentence (str)
# ---------------------------------------------------------------------------

TEMPLATES = {
    "ml_anomaly": lambda v:
        f"The ML anomaly detector flagged this session with {v * 100:.0f}% confidence.",

    "off_hours": lambda v:
        "Activity occurred outside this user's normal working hours.",

    "unusual_location": lambda v:
        "Access originated from a location/IP not typically associated with this user.",

    "high_volume_access": lambda v:
        "An unusually high volume of resource access/data transfer was recorded.",

    "sensitive_resource": lambda v:
        "A sensitive resource was accessed that this user does not normally touch.",

    "privilege_escalation": lambda v:
        "The session involved a privilege escalation or admin-level action.",

    "failed_auth_attempts": lambda v:
        "The session was preceded by failed authentication attempts.",

    "rare_action_for_user": lambda v:
        "The user performed an action that is rare relative to their historical baseline.",
}


def _fallback_template(factor_name: str, value) -> str:
    """Covers any factor added to RISK_WEIGHTS later without a template yet."""
    readable = factor_name.replace("_", " ")
    return f"Anomalous factor detected: {readable} (value={value})."


def _summary_sentence(score: float, severity: str) -> str:
    severity_phrases = {
        "Info": "no significant concern",
        "Low": "low concern",
        "Medium": "moderate concern",
        "High": "high concern",
        "Critical": "critical concern requiring immediate review",
    }
    phrase = severity_phrases.get(severity, severity.lower())
    return f"Risk score {score:.0f}/100 ({severity}) — {phrase}."


def generate_explanation(
    triggered_factors: Dict[str, Union[bool, float]],
    score: float,
    severity: str,
) -> List[str]:
    """
    Build a prioritized, plain-English explanation for a risk score.

    Args:
        triggered_factors: same flat dict risk_engine.calculate_risk_score() takes
                            (factor_name -> bool or 0-1 float).
        score: value returned by calculate_risk_score().
        severity: value returned by get_severity(score).

    Returns:
        List[str]: sentence 0 is the score/severity summary; the rest are
        ordered by each factor's actual contribution to the score
        (weight * value), highest first. Factors with 0/False are skipped.
    """
    contributions = []

    for factor, weight in RISK_WEIGHTS.items():
        value = triggered_factors.get(factor, 0)

        if isinstance(value, bool):
            contribution = weight if value else 0
            fired = value
        else:
            contribution = weight * value
            fired = value > 0

        if fired:
            contributions.append((factor, value, contribution))

    # Highest contribution to the score first
    contributions.sort(key=lambda item: item[2], reverse=True)

    sentences = [_summary_sentence(score, severity)]
    for factor, value, _contribution in contributions:
        template = TEMPLATES.get(factor)
        if template:
            sentences.append(template(value))
        else:
            sentences.append(_fallback_template(factor, value))

    return sentences


if __name__ == "__main__":
    from risk_engine import calculate_risk_score, get_severity

    suspicious_activity = {
        "ml_anomaly": 0.7,
        "off_hours": True,
        "unusual_location": True,
        "high_volume_access": False,
        "sensitive_resource": True,
        "privilege_escalation": False,
        "failed_auth_attempts": False,
        "rare_action_for_user": True,
    }

    score = calculate_risk_score(suspicious_activity)
    severity = get_severity(score)

    for line in generate_explanation(suspicious_activity, score, severity):
        print("-", line)
