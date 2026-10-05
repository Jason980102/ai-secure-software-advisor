import httpx
from app.schemas.vulnerability import VulnerabilityFinding
from app.services.normalization import normalize

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

class OSVServiceError(Exception):
    """OSV query failed; no complete report can be returned."""

def query_vulnerabilities(package_name: str, version: str) -> list[VulnerabilityFinding]:
    payload = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}
    records, tokens = [], set()
    try:
        with httpx.Client(timeout=10.0) as client:
            for _ in range(100):
                response = client.post(OSV_QUERY_URL, json=payload)
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict) or not isinstance(data.get("vulns", []), list):
                    raise ValueError("Invalid OSV response")
                page = data.get("vulns", [])
                if any(not isinstance(v, dict) or not isinstance(v.get("id"), str) for v in page):
                    raise ValueError("Invalid vulnerability record")
                records.extend(page)
                token = data.get("next_page_token")
                if not token:
                    return normalize(records, package_name)
                if not isinstance(token, str) or token in tokens:
                    raise ValueError("Invalid pagination token")
                tokens.add(token)
                payload["page_token"] = token
            raise ValueError("OSV pagination limit exceeded")
    except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise OSVServiceError(f"Failed to query OSV for {package_name}=={version}") from exc
