from app.schemas.scan import PackageScanResult, UpgradeRecommendation, ReleaseValidation, DependencyCheckReport
from app.schemas.vulnerability import VulnerabilityFinding
from app.services.upgrade_plan import build_upgrade_plan


def package(status='candidate', candidate='2', evidence=True):
    return PackageScanResult(package='Demo_Package', installed_version='1', extras=['SOCKS'],
        vulnerabilities=[VulnerabilityFinding(id='CVE-2024-1234', aliases=[], summary='Example vulnerability', severity='HIGH')],
        upgrade_recommendation=UpgradeRecommendation(status=status, recommended_version=candidate,
            reason='test', release_checks=[ReleaseValidation(version=candidate or '2', status='available',
                remaining_vulnerability_ids=[] if evidence else None)]))


def test_export_changes_only_verified_candidates_and_preserves_extras():
    plan = build_upgrade_plan([package()])
    assert 'demo-package[socks]==2\n' in plan.requirements_text
    assert plan.items[0].action == 'upgrade'
    assert plan.items[0].priority == 'high'
    assert 'major_upgrade' in plan.warnings
    assert plan.status == 'review_required'


def test_unverified_candidate_keeps_installed_pin():
    plan = build_upgrade_plan([package(evidence=False)])
    assert plan.items[0].proposed_version == '1'
    assert plan.items[0].action == 'review'
    assert 'retained_vulnerable' in plan.warnings


def test_failed_recommendation_keeps_original():
    assert build_upgrade_plan([package('verification_failed', None)]).items[0].proposed_version == '1'


def test_conflicting_plan_remains_a_review_draft():
    checks = DependencyCheckReport(status='conflicts_found', selected_versions={},
        conflict_count=1, unresolved_count=2, checks=[])
    plan = build_upgrade_plan([package()], checks)
    assert {'dependency_conflicts', 'dependency_incomplete'} <= set(plan.warnings)
    assert '# Review: dependency_conflicts' in plan.requirements_text


def test_python_or_wheel_checks_must_match_target():
    p = package()
    p.upgrade_recommendation.target_python = '3.12.0'
    p.upgrade_recommendation.target_platform = 'win_amd64'
    assert build_upgrade_plan([p]).items[0].action == 'review'
    p.upgrade_recommendation.release_checks[0].python_compatible = True
    p.upgrade_recommendation.release_checks[0].wheel_compatible = True
    assert build_upgrade_plan([p]).items[0].action == 'upgrade'
