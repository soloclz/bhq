"""Narrow, source-verified normalization of RustHound builtin placeholders.

The caller validates every original record and envelope before calling this.
Never deduplicate across files, silently union edges, or replace real records.
"""
from collections import defaultdict
import json
import re

VERSIONS = {"RustHound-CE v2.5.12", "RustHound-CE v2.5.13"}
BUILTINS = {
    "544": "ADMINISTRATORS", "548": "ACCOUNT OPERATORS",
    "550": "PRINT OPERATORS", "554": "PRE-WINDOWS 2000 COMPATIBLE ACCESS",
    "557": "INCOMING FOREST TRUST BUILDERS", "560": "WINDOWS AUTHORIZATION ACCESS GROUP",
    "561": "TERMINAL SERVER LICENSE SERVERS",
}


def _placeholder_for(actual, candidate):
    sid = actual["ObjectIdentifier"]
    match = re.fullmatch(r"([A-Z0-9.-]+)-S-1-5-32-(544|548|550|554|557|560|561)", sid)
    if not match or actual.get("IsDeleted") is not False:
        return False
    domain, rid = match.groups()
    props = actual.get("Properties", {})
    domain_sid = props.get("domainsid", "")
    if not isinstance(domain_sid, str) or not re.fullmatch(r"S-1-5-21-\d+-\d+-\d+", domain_sid):
        return False
    dn = props.get("distinguishedname", "")
    expected_suffix = ",CN=BUILTIN," + ",".join("DC=" + part for part in domain.split("."))
    if (not isinstance(dn, str) or not dn.upper().startswith("CN=")
            or not dn.upper().endswith(expected_suffix)
            or not isinstance(props.get("domain"), str)
            or props["domain"].upper() != domain
            or not props.get("samaccountname")):
        return False
    # The checker leaves WAAG.domain empty; other placeholders keep input casing.
    candidate_domain = candidate.get("Properties", {}).get("domain")
    if rid == "560":
        if candidate_domain != "":
            return False
    elif not isinstance(candidate_domain, str) or candidate_domain.upper() != domain:
        return False
    expected = {
        "ObjectIdentifier": sid, "IsDeleted": False, "IsACLProtected": False,
        "Members": [], "Aces": [], "ContainedBy": None,
        "Properties": {
            "domain": candidate_domain, "name": f"{BUILTINS[rid]}@{domain}",
            "distinguishedname": "", "domainsid": domain_sid,
            "isaclprotected": False, "highvalue": rid in {"544", "548", "550"},
            "samaccountname": "", "description": None, "whencreated": 0,
            "admincount": False,
        },
    }
    # JSON comparison also distinguishes false from 0; extra fields must not vanish.
    return json.dumps(candidate, sort_keys=True) == json.dumps(expected, sort_keys=True)


def normalize_groups(data, meta, source):
    if meta.get("collectorversion") not in VERSIONS or meta.get("version") != 6:
        return data, []
    by_sid = defaultdict(list)
    for index, obj in enumerate(data):
        by_sid[obj["ObjectIdentifier"]].append(index)
    dropped, notices = set(), []
    for sid, indices in by_sid.items():
        if len(indices) != 2:
            continue
        left, right = indices
        for actual, placeholder in ((left, right), (right, left)):
            if _placeholder_for(data[actual], data[placeholder]):
                dropped.add(placeholder)
                notices.append({"source": source, "object_identifier": sid,
                                "kept_index": actual, "placeholder_index": placeholder})
                break
    return [obj for i, obj in enumerate(data) if i not in dropped], notices
