"""MITRE ATT&CK mapping.

Each mapping states: technique id/name, observed evidence, the reasoning,
a *qualified* confidence, alternative explanations, and limitations.

Names/descriptions were checked against the official MITRE ATT&CK site
(attack.mitre.org, Enterprise techniques as listed in
``docs/MITRE_MAPPING.md``).  These are candidates driven by evidence --
they are never automatic labels, and no HTTP request alone proves a
broader scanning campaign or a successful compromise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class MitreMapping:
    technique_id: str
    technique_name: str
    rationale: str
    confidence: str  # "low" | "moderate" | "high"
    alternatives: str
    limitations: str
    # The evidence string is filled per event by map_event(); templates
    # below describe the technique-level reasoning only.
    evidence: str = ""


_T1083 = MitreMapping(
    technique_id="T1083",
    technique_name="File and Directory Discovery",
    confidence="moderate",
    rationale=(
        "Requests for hidden configuration, repository metadata, or "
        "backup files are consistent with an adversary enumerating "
        "well-known file locations to find credentials or sensitive data."
    ),
    alternatives=(
        "Automated vulnerability scanners probe these paths routinely; "
        "the source may be a scanning tool rather than a targeted actor."
    ),
    limitations=(
        "The request itself shows only that these paths were probed; no "
        "file was actually returned, so no real discovery succeeded."
    ),
)

_T1082 = MitreMapping(
    technique_id="T1082",
    technique_name="System Information Discovery",
    confidence="low",
    rationale=(
        "Requests for server-status/server-info/phpinfo pages can reveal "
        "system configuration when served; probing them may indicate an "
        "interest in system information."
    ),
    alternatives=(
        "Some monitoring tools request phpinfo as a health probe; benign "
        "administrators also trigger these pages."
    ),
    limitations=(
        "The honeypot returns controlled, non-revealing responses, so no "
        "actual system information was ever disclosed."
    ),
)

_T1046 = MitreMapping(
    technique_id="T1046",
    technique_name="Network Service Discovery",
    confidence="low",
    rationale=(
        "Broad HTTP probing across many unrelated route categories in a "
        "short time is consistent with service/endpoint scanning."
    ),
    alternatives=(
        "Internet-wide scanners and search crawlers sweep millions of "
        "addresses daily; breadth alone is not targeting."
    ),
    limitations=(
        "Applied only at aggregate per-IP level in the analysis stage; "
        "never inferred from a single request."
    ),
)

_T1110_PARENT = MitreMapping(
    technique_id="T1110",
    technique_name="Brute Force",
    confidence="low",
    rationale=(
        "Requests to login endpoints are consistent with credential "
        "checking behaviour against the (decoy) authentication surface."
    ),
    alternatives=(
        "A single login request may be a link preview, a mistyped URL, "
        "or routine scanner coverage."
    ),
    limitations=(
        "The decoy has no real authentication; no credentials existed to "
        "guess. Values of submitted fields are never stored."
    ),
)

_T1110_001 = MitreMapping(
    technique_id="T1110.001",
    technique_name="Brute Force: Password Guessing",
    confidence="moderate",
    rationale=(
        "Repeated login attempts with credential-like fields from the "
        "same source within the observation window are consistent with "
        "repeated password guessing attempts."
    ),
    alternatives=(
        "Automated tooling re-checking endpoints (e.g. uptime monitors "
        "or misconfigured clients) can also repeat login requests."
    ),
    limitations=(
        "Frequency evidence only demonstrates repetition, not a "
        "successful authentication or a human adversary."
    ),
)

_EVENT_RULES: dict[str, MitreMapping] = {
    "Configuration file probing": _T1083,
    "Repository metadata probing": _T1083,
    "Backup and database file discovery": _T1083,
    "Server information discovery": _T1082,
    "Service console discovery": _T1082,
    "Login endpoint probing": _T1110_PARENT,
    "CMS endpoint discovery": _T1110_PARENT,
}


def map_event(classification: Optional[str],
              credential_user: bool = False,
              credential_pass: bool = False) -> Optional[MitreMapping]:
    """Map one classified event to a (qualified) technique, if justified."""
    if not classification:
        return None
    if classification == "Repeated authentication probing":
        if credential_user or credential_pass:
            mapping = _T1110_001
        else:
            mapping = _T1110_PARENT
    else:
        mapping = _EVENT_RULES.get(classification)
    if mapping is None:
        return None
    # The evidence is the observation that triggered the rule.
    evidence = (
        f"Observed request classified as '{classification}' "
        f"(credential fields present: user={bool(credential_user)}, "
        f"pass={bool(credential_pass)})."
    )
    return MitreMapping(
        technique_id=mapping.technique_id,
        technique_name=mapping.technique_name,
        evidence=evidence,
        rationale=mapping.rationale,
        confidence=mapping.confidence,
        alternatives=mapping.alternatives,
        limitations=mapping.limitations,
    )


def aggregate_rule(min_route_categories: int = 3) -> dict[str, str]:
    """Aggregate-level rule description for per-IP service scanning.

    Returns a mapping template used by the analysis stage when a single
    source IP probes three or more distinct route categories within the
    observation period.  Single-request mappings avoid this rule.
    """
    return {
        "technique_id": _T1046.technique_id,
        "technique_name": _T1046.technique_name,
        "confidence": _T1046.confidence,
        "rationale": _T1046.rationale,
        "alternatives": _T1046.alternatives,
        "limitations": _T1046.limitations,
        "rule": (
            f"source_ip probed >= {min_route_categories} distinct "
            "route categories in the observation period"
        ),
    }


TECHNIQUE_REFERENCES = {
    "T1083": "https://attack.mitre.org/techniques/T1083/",
    "T1082": "https://attack.mitre.org/techniques/T1082/",
    "T1046": "https://attack.mitre.org/techniques/T1046/",
    "T1110": "https://attack.mitre.org/techniques/T1110/",
    "T1110.001": "https://attack.mitre.org/techniques/T1110/001/",
}
