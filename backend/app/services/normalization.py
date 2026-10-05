import re

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from app.schemas.vulnerability import VulnerabilityFinding as Vulnerability


from app.services.severity import highest_cvss

LEVELS = ["UNKNOWN", "LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"]


def normalize(records: list[dict], package: str) -> list[Vulnerability]:
    # Merge connected alias groups, including bridges discovered later.
    groups = []
    for record in records:
        if record.get("withdrawn"):
            continue
        ids = {record["id"], *record.get("aliases", [])}
        matches = [group for group in groups if group[0] & ids]
        items = [record]
        for group in matches:
            ids |= group[0]
            items.extend(group[1])
            groups.remove(group)
        groups.append((ids, items))
    results = []
    for ids, items in groups:
        cves = sorted(i for i in ids if re.fullmatch(r"CVE-\d{4}-\d{4,}", i))
        fixed, levels = set(), ["UNKNOWN"]
        severity_entries = []
        for record in items:
            severity_entries.extend(record.get("severity", []))
            level = str(record.get("database_specific", {}).get("severity", "UNKNOWN")).upper()
            if level in LEVELS:
                levels.append(level)
            for affected in record.get("affected", []):
                info = affected.get("package", {})
                if info.get("ecosystem") != "PyPI" or canonicalize_name(info.get("name", "")) != package:
                    continue
                severity_entries.extend(affected.get("severity", []))
                level = str(affected.get("ecosystem_specific", {}).get("severity", "UNKNOWN")).upper()
                if level in LEVELS:
                    levels.append(level)
                for span in affected.get("ranges", []):
                    if span.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                        continue
                    for event in span.get("events", []):
                        if "fixed" in event:
                            try:
                                fixed.add(str(Version(event["fixed"])))
                            except InvalidVersion:
                                pass
        cvss = highest_cvss(severity_entries)
        primary = cves[0] if cves else sorted(ids)[0]
        results.append(Vulnerability(
            id=primary, aliases=sorted(ids - {primary}),
            summary=next((item["summary"] for item in items if item.get("summary")), ""),
            severity=cvss["severity"] if cvss else max(levels, key=LEVELS.index),
            severity_source="cvss" if cvss else ("database_label" if len(levels) > 1 else "unknown"),
            cvss_score=cvss["score"] if cvss else None,
            cvss_vector=cvss["vector"] if cvss else None,
            cvss_type=cvss["type"] if cvss else None,
            fixed_versions=sorted(fixed, key=Version),
        ))
    return sorted(results, key=lambda v: v.id)
