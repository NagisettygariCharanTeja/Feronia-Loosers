import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from schemas.models import Finding
from pipeline.synthesizer import synthesize


def _make_finding(severity: str, confidence: float, node: str, action: str) -> Finding:
    return Finding(
        agent_source="secops",
        severity=severity,
        confidence=confidence,
        affected_node=node,
        description=f"Test finding for {node}",
        plain_english=f"Test finding for {node}",
        recommended_action=action,
        evidence_path=[node],
    )


def test_deterministic_sort():
    findings = [
        _make_finding("medium", 0.7, "node-a", "flag_for_review"),
        _make_finding("critical", 0.9, "node-b", "restrict_security_group"),
        _make_finding("high", 0.8, "node-c", "enable_encryption"),
        _make_finding("low", 0.5, "node-d", "tag_resource"),
    ]
    sorted1, _ = synthesize(findings)
    sorted2, _ = synthesize(findings)
    ids1 = [f.finding_id for f in sorted1]
    ids2 = [f.finding_id for f in sorted2]
    assert ids1 == ids2


def test_critical_before_others():
    findings = [
        _make_finding("low", 0.9, "node-a", "tag_resource"),
        _make_finding("critical", 0.5, "node-b", "restrict_security_group"),
        _make_finding("medium", 0.8, "node-c", "enable_encryption"),
        _make_finding("high", 0.7, "node-d", "disable_public_access"),
    ]
    sorted_findings, _ = synthesize(findings)
    severities = [f.severity for f in sorted_findings]
    assert severities[0] == "critical"
    assert severities.index("critical") < severities.index("high")
    assert severities.index("high") < severities.index("medium")
    assert severities.index("medium") < severities.index("low")


def test_higher_confidence_first_within_severity():
    findings = [
        _make_finding("high", 0.6, "node-a", "flag_for_review"),
        _make_finding("high", 0.95, "node-b", "restrict_security_group"),
        _make_finding("high", 0.8, "node-c", "enable_encryption"),
    ]
    sorted_findings, _ = synthesize(findings)
    confidences = [f.confidence for f in sorted_findings]
    assert confidences == sorted(confidences, reverse=True)
