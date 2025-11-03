from datetime import datetime, timezone
from uuid import uuid4
import requests
from datetime import datetime, date
from typing import Optional, List, Any, Dict, Tuple


def randomUUID():
    return str(uuid4())




def get_latest_timestamp():
    # get current datetime in UTC
    dt = datetime.now(timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")



def online_data_grabber(keyword):
    url_base = 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch='
    external_api_url = f"{url_base}{keyword}"

    try:
        response = requests.get(external_api_url, timeout=(5))
        response.raise_for_status()

        return response.json()        
    except Exception as e:
        return None, external_api_url
    





def five_year_cutoff(today: Optional[date | datetime] = None) -> date:
    """
    Return the calendar DATE exactly 5 years before 'today'.
    """

    date_five_ago = datetime.now(timezone.utc).date()

    # Subtract 5 calendar years, handling Feb 29
    y = date_five_ago.year - 5
    m = date_five_ago.month
    day = date_five_ago.day
    
    return date(y, m, day)
        


def parse_nvd_datetime(dt_str: str) -> datetime:
    """
    NVD timestamps are ISO 8601, sometimes ending with 'Z' (UTC) and
    sometimes with fractional seconds. Return a timezone-aware UTC datetime.
    Examples NVD values: '2020-01-01T00:00:00.000Z', '2019-12-31T12:34:56.789'
    """
    s = dt_str.strip()
    # Make 'Z' RFC3339 explicit for datetime.fromisoformat
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.date()


# def filter_last_5_years_from_back(data: dict, keep_original_order: bool = True) -> list[dict]:
def filter_last_5_years_from_back(data: dict) -> list[dict]:
    """
    data: full NVD response dict with key "vulnerabilities".
    Walks from the END (newest first) and stops at first out-of-range item.
    Returns only the items within the last 5 years.

    If keep_original_order is True, results are returned oldest->newest (as in the input).
    Otherwise, they are returned newest->oldest (as encountered walking backwards).
    """
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return []

    cutoff_d = five_year_cutoff()



    # print(cutoff_d)
    # print(parse_nvd_datetime("2012-11-01T10:44:47.843") >= cutoff_d)

    # """
    picked = []

    # iterate from the end; break as soon as we hit one older than cutoff
    for item in reversed(vulns):
        cve = item.get("cve", {})
        pub_str = cve.get("published") or cve.get("publishedDate")
        if not pub_str:
            # no published date; skip but DO NOT stop the scan
            continue

        try:
            pub_date = parse_nvd_datetime(pub_str)
        except Exception:
            # if parse fails, skip this record but keep scanning
            continue

        if pub_date >= cutoff_d:
            picked.append(item)
        else:
            # because list is sorted by published ascending,
            # everything earlier will also be out-of-range → stop
            break

    # restore input ordering if desired
    # if keep_original_order:
    #     picked.reverse()
    return picked

# """


def _english_description(cve_obj: Dict[str, Any]) -> str:
    """Get the english decription for the CVE since multiple language might be available"""
    descs = cve_obj.get("descriptions") or []
    for d in descs:
        if d.get("lang") == "en" and d.get("value"):
            return d["value"].strip()
    return ""


def _cvss_pick(cve_obj: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    """Prefer CVSS v3.1 (Primary from nvd), then any v3.1, then v3.0, then v2.0."""
    metrics = cve_obj.get("metrics") or {}

    def pick_from(key: str, base_key: str = "cvssMetricV31"):
        for block in metrics.get(base_key, []):
            data = block.get("cvssData") or {}
            score = data.get("baseScore")
            sev = data.get("baseSeverity")
            if score is not None and sev:
                return float(score), str(sev)
        return None, None

    score, sev = pick_from("cvssMetricV31", "cvssMetricV31")
    if score is not None:
        return score, sev

    # try v3.0
    score, sev = pick_from("cvssMetricV30", "cvssMetricV30")
    if score is not None:
        return score, sev

    # try v4.0 (some feeds include it)
    score, sev = pick_from("cvssMetricV40", "cvssMetricV40")
    if score is not None:
        return score, sev

    # fallback v2.0
    for block in metrics.get("cvssMetricV2", []):
        data = block.get("cvssData") or {}
        score = data.get("baseScore")
        sev = block.get("baseSeverity")
        if score is not None and sev:
            return float(score), str(sev)

    return None, None




def to_telex_parts(items: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Convert CVE objects into Telex 'parts' text entries (one dict per vulnerability).
    """
    parts: List[Dict[str, str]] = []
    for item in items:
        cve = item.get("cve") or {}
        cve_id = cve.get("id") or "Unknown CVE"
        published = cve.get("published")
        last_mod = cve.get("lastModified")
        score, sev = _cvss_pick(cve)
        desc = _english_description(cve)

        # # Optional CISA KEV notes if present in the object
        # kev_added = cve.get("cisaExploitAdd")
        # kev_required = cve.get("cisaRequiredAction")
        # kev_note = ""
        # if kev_added:
        #     kev_note = f"\n• CISA KEV: added {kev_added}"
        #     if kev_required:
        #         kev_note += f"\n• Action: {kev_required}"

        line = (
            f"{cve_id}"
            f"\n• Severity: {sev or 'N/A'} ({'' if score is None else score})"
            # f"\n• Published: {published.isoformat() if published else 'N/A'}"
            f"\n• Published: {published if published else 'N/A'}"
            # f"\n• Last Modified: {last_mod.isoformat() if last_mod else 'N/A'}"
            f"\n• Last Modified: {last_mod if last_mod else 'N/A'}"
            f"\n• Summary: {desc or 'No English summary available.'}"
            # f"{kev_note}"
        )

        parts.append({"kind": "text", "text": line})
    return parts