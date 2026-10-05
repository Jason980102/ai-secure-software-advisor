import pytest
from app.services.normalization import normalize
from app.services.severity import highest_cvss
from app.services.recommendation import recommend_upgrade
from app.services.osv_service import OSVServiceError
from app.schemas.vulnerability import VulnerabilityFinding

VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

def finding(fixes):
    return VulnerabilityFinding(id='CVE-2024-12345', aliases=[], summary='test', fixed_versions=fixes)

def test_cvss3_score():
    result = highest_cvss([{'type': 'CVSS_V3', 'score': VECTOR}])
    assert result['score'] == 9.8
    assert result['severity'] == 'CRITICAL'

def test_cvss4_and_invalid_vectors():
    entries = [{'type': 'CVSS_V3', 'score': 'invalid'}, {'type': 'other', 'score': VECTOR},
        {'type': 'CVSS_V4', 'score': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N'}]
    assert highest_cvss(entries)['score'] == 9.9
    assert highest_cvss(entries[:2]) is None

def test_cvss2_and_zero():
    assert highest_cvss([{'type':'CVSS_V2','score':'AV:N/AC:L/Au:N/C:C/I:C/A:C'}])['score'] == 10
    zero = VECTOR.replace('C:H/I:H/A:H', 'C:N/I:N/A:N')
    assert highest_cvss([{'type':'CVSS_V3','score':zero}])['severity'] == 'NONE'

def test_normalization_cvss_overrides_label_and_filters_package():
    records = [{'id': 'GHSA-a', 'aliases': [], 'severity': [{'type':'CVSS_V3','score':VECTOR}],
        'database_specific': {'severity':'LOW'}, 'affected': [{'package': {'name':'other','ecosystem':'PyPI'},
        'severity': [{'type':'CVSS_V2','score':'AV:N/AC:L/Au:N/C:C/I:C/A:C'}]}]}]
    result = normalize(records, 'requests')[0]
    assert (result.severity, result.cvss_score, result.severity_source) == ('CRITICAL', 9.8, 'cvss')
    assert result.cvss_vector == VECTOR
    records[0]['severity'][0]['score'] = 'invalid'
    result = normalize(records, 'requests')[0]
    assert result.severity == 'LOW'
    assert result.cvss_score is None

def test_combined_fix_bound_and_recheck():
    calls = []
    def lookup(name, version):
        calls.append((name, version))
        return [finding([])] if version == '2.9' else []
    result = recommend_upgrade('a', '1', [finding(['2.5', '2.10']), finding(['2.9'])], lookup)
    assert calls == [('a', '2.9'), ('a', '2.10')]
    assert result.recommended_version == '2.10'
    assert result.major_upgrade is True

@pytest.mark.parametrize('fixes', [[], ['oops'], ['0.9'], ['2.0rc1']])
def test_no_eligible_fix(fixes):
    result = recommend_upgrade('a', '1', [finding(fixes)], lambda *a: pytest.fail('query'))
    assert result.status == 'manual_review'

def test_clean_package_no_query():
    assert recommend_upgrade('a', '1', [], lambda *a: pytest.fail('query')).status == 'not_needed'

def test_failed_candidate_preserves_report():
    def lookup(*args):
        raise OSVServiceError('timeout')
    result = recommend_upgrade('a', '1', [finding(['2'])], lookup)
    assert result.status == 'verification_failed'
    assert result.recommended_version is None

def test_candidate_limit():
    calls = []
    def lookup(*args):
        calls.append(args)
        return [finding([])]
    result = recommend_upgrade('a', '1', [finding([str(i) for i in range(2, 10)])], lookup)
    assert len(calls) == 5
    assert result.status == 'manual_review'
