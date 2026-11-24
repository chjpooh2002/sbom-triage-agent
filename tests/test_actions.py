from pathlib import Path

import pytest

from triage.actions import build_actions
from triage.models import PriorityResult, Remediation, TriageBundle


FIXTURE = Path(__file__).parent / "fixtures/finals/action_bundle.json"


@pytest.fixture
def bundle():
    return TriageBundle.model_validate_json(FIXTURE.read_text(encoding="utf-8"))


def test_actions_preserve_verdicts_and_group_only_covered_candidates(bundle):
    before = bundle.model_dump()
    upgrade, image, confirm = build_actions(bundle)
    assert [(a.kind, a.findings, a.target, a.counts) for a in [upgrade, image, confirm]] == [
        ("upgrade", ["finding-1", "finding-2"], "1.8", {"affected": 1, "undetermined": 1}),
        ("base_image", ["finding-4", "finding-5"], "4.8.10", {"affected": 0, "undetermined": 2}),
        ("confirm", ["finding-3"], "", {"affected": 0, "undetermined": 1}),
    ]
    assert upgrade.evidence_ids == ["E1"]
    assert image.evidence_ids == ["E2"]
    assert confirm.team == confirm.work_request.to_team
    assert [(m.what, m.where) for m in confirm.missing_info] == [("활성 옵션", "배포 설정")]
    assert bundle.model_dump() == before
    bundle.findings.reverse()
    assert build_actions(bundle) == [upgrade, image, confirm]


def test_plan_precedes_fixed_versions_and_uses_ranked_representative(bundle):
    bundle.remediations = [Remediation(finding_key="finding-1", target_version="2.1")]
    bundle.results = [PriorityResult(finding_key="finding-2", tier="P1", rank=1, score=91)]
    upgrade, image = build_actions(bundle)
    assert upgrade.kind == "upgrade" and upgrade.target == "2.1"
    assert upgrade.counts == {"affected": 1, "undetermined": 2}
    assert upgrade.top_finding == "finding-2"
    assert image.kind == "base_image"


@pytest.mark.parametrize("fix", ["unknown", ">=1.1", "1.x", "", "0.9"])
def test_uncertain_or_older_fix_stays_in_confirmation(bundle, fix):
    bundle.findings[1].vulnerability.fixed_versions = [fix]
    upgrade, _, confirm = build_actions(bundle)
    assert upgrade.findings == ["finding-1"]
    assert set(confirm.findings) == {"finding-2", "finding-3"}
    assert len(confirm.missing_info) == 1


def test_known_affected_target_stays_pending(bundle):
    bundle.findings[1].vulnerability.affected_ranges = [">=1.8,<2.2"]
    assert build_actions(bundle)[0].findings == ["finding-1"]


def test_image_source_minor_and_affected_priority(bundle):
    other = bundle.findings[4]
    other.component = other.component.model_copy(update={"sources": ["other/Dockerfile"], "evidence_ids": []})
    other.verdict.state = "affected"
    other.vulnerability.fixed_versions = ["4.9.1"]
    bundle.results = [PriorityResult(finding_key=other.key, tier="P2", rank=2, score=70)]
    first, upgrade, image, confirm = build_actions(bundle)
    assert [a.kind for a in (first, upgrade, image, confirm)] == ["base_image", "upgrade", "base_image", "confirm"]
    assert first.target == "같은 줄 최신 패치"
    assert image.target == "4.8.9"

def test_multiple_images_share_dockerfile_action_without_crossing_version_lines(bundle):
    other = bundle.findings[4]
    other.component = other.component.model_copy(update={"id": "second-runtime", "declared_spec": "second:9.2",
                                                        "version": "9.2"})
    other.vulnerability.fixed_versions = ["9.2.7"]
    image = next(a for a in build_actions(bundle) if a.kind == "base_image")
    assert len(image.findings) == 2
    assert "second:9.2" in image.title and "demo:4.8-slim" in image.title
    assert image.target == "같은 줄 최신 패치"


def test_upgrade_fallback_uses_highest_of_minimum_line_fixes(bundle):
    first, second = bundle.findings[:2]
    second.verdict.state = "affected"
    first.vulnerability.fixed_versions = ["0.9", "1.1", "1.8", "3.0"]
    second.vulnerability.fixed_versions = ["2.0", "1.9", "1.4"]
    assert build_actions(bundle)[0].target == "1.4"


def test_no_same_major_fix_requires_target_confirmation(bundle):
    bundle.findings[0].vulnerability.fixed_versions = ["0.9", "1.0", "2.0", "3.1"]
    upgrade, _, confirm = build_actions(bundle)
    assert upgrade.target == "" and upgrade.findings == ["finding-1"]
    assert set(confirm.findings) == {"finding-2", "finding-3"}
