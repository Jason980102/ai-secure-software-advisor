from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError


def highest_cvss(entries: list[dict]) -> dict | None:
    scores = []
    for entry in entries:
        calculator = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}.get(entry.get("type"))
        vector = entry.get("score")
        if calculator is None or not isinstance(vector, str):
            continue
        try:
            result = calculator(vector)
            scores.append({"score": float(result.scores()[0]),
                           "severity": result.severities()[0].upper(),
                           "vector": vector, "type": entry["type"]})
        except (CVSSError, ValueError):
            continue
    return max(scores, key=lambda score: (score["score"], score["type"], score["vector"])) if scores else None
