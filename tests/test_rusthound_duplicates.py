"""Synthetic regressions for real/default builtin collisions; no lab data."""
from copy import deepcopy
import json
import zipfile

import pytest

from bhq import queries, report
from bhq.loader import CollectionError, load

NAMES = [(544, "ADMINISTRATORS"), (548, "ACCOUNT OPERATORS"),
         (550, "PRINT OPERATORS"), (554, "PRE-WINDOWS 2000 COMPATIBLE ACCESS"),
         (557, "INCOMING FOREST TRUST BUILDERS"), (560, "WINDOWS AUTHORIZATION ACCESS GROUP"),
         (561, "TERMINAL SERVER LICENSE SERVERS")]
DOMAIN_SID = "S-1-5-21-10-20-30"
USER = DOMAIN_SID + "-1101"


def pair(rid=548, name="ACCOUNT OPERATORS"):
    default = {
        "ObjectIdentifier": f"EXAMPLE.TEST-S-1-5-32-{rid}",
        "IsDeleted": False, "IsACLProtected": False, "ContainedBy": None,
        "Members": [], "Aces": [],
        "Properties": {"name": f"{name}@EXAMPLE.TEST",
                       "domain": "" if rid == 560 else "example.test",
                       "domainsid": DOMAIN_SID, "distinguishedname": "",
                       "samaccountname": "", "description": None,
                       "whencreated": 0, "admincount": False,
                       "isaclprotected": False, "highvalue": rid in (544, 548, 550)},
    }
    actual = deepcopy(default)
    actual["Properties"].update({"domain": "EXAMPLE.TEST",
        "distinguishedname": f"CN={name},CN=BUILTIN,DC=EXAMPLE,DC=TEST",
        "samaccountname": name.title(), "description": "Synthetic actual directory object",
        "whencreated": 1234, "admincount": True, "isaclprotected": True})
    actual["IsACLProtected"] = True
    actual["Members"] = [{"ObjectIdentifier": USER, "ObjectType": "User"}]
    actual["Aces"] = [{"PrincipalSID": USER, "PrincipalType": "User",
                       "RightName": "WriteDacl", "IsInherited": False}]
    return actual, default


def write(tmp_path, rows, version="2.5.12", meta_changes=None, name="sample_groups.json"):
    meta = {"type": "groups", "count": len(rows), "version": 6, "methods": 0,
            "collectorversion": f"RustHound-CE v{version}"}
    meta.update(meta_changes or {})
    file = tmp_path / name
    file.write_text(json.dumps({"data": rows, "meta": meta}))
    return file


@pytest.mark.parametrize("rid,name", NAMES)
@pytest.mark.parametrize("version", ["2.5.12", "2.5.13"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("zipped", [False, True])
def test_preserve_real_record_and_report_normalization(tmp_path, rid, name, version, reverse, zipped):
    actual, default = pair(rid, name)
    rows = [default, actual] if reverse else [actual, default]
    file = write(tmp_path, rows, version)
    original = file.read_bytes()
    source = tmp_path
    if zipped:
        source = tmp_path / "input.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.write(file, file.name)
    graph = load(source)
    sid = actual["ObjectIdentifier"]
    assert graph.groups == [actual]
    assert graph.by_sid[sid] == actual
    assert graph.member_edges[USER] == [sid]
    assert (sid, "WriteDacl") in graph.control_edges[USER]
    assert graph.collection_metadata[file.name]["count"] == 2
    assert graph.collection_normalizations == [{"source": file.name, "object_identifier": sid,
        "kept_index": 1 if reverse else 0, "placeholder_index": 0 if reverse else 1}]
    assert any("placeholders normalized" in message for message in queries.diagnostics(graph))
    assert any("placeholders normalized" in message for message in report.build(graph)["analysis"]["warnings"])
    assert file.read_bytes() == original


@pytest.mark.parametrize("change", [
    "member", "ace", "extra_property", "extra_top", "description", "timestamp",
    "deleted", "protected", "contained", "domain", "domainsid", "name", "highvalue",
    "bool_as_int", "real_dn", "real_domain", "real_deleted", "triple", "two_real", "two_default",
])
def test_refuse_ambiguous_or_nonempty_duplicates(tmp_path, change):
    actual, default = pair()
    props = default["Properties"]
    if change == "member": default["Members"] = deepcopy(actual["Members"])
    elif change == "ace": default["Aces"] = deepcopy(actual["Aces"])
    elif change == "extra_property": props["extra"] = "must not vanish"
    elif change == "extra_top": default["Extra"] = []
    elif change == "description": props["description"] = "independent information"
    elif change == "timestamp": props["whencreated"] = 42
    elif change == "deleted": default["IsDeleted"] = True
    elif change == "protected": default["IsACLProtected"] = True
    elif change == "contained": default["ContainedBy"] = {"ObjectIdentifier": DOMAIN_SID, "ObjectType": "Domain"}
    elif change == "domain": props["domain"] = "OTHER.TEST"
    elif change == "domainsid": props["domainsid"] = "S-1-5-21-40-50-60"
    elif change == "name": props["name"] = "OTHER@EXAMPLE.TEST"
    elif change == "highvalue": props["highvalue"] = False
    elif change == "bool_as_int": props["admincount"] = 0
    elif change == "real_dn": actual["Properties"]["distinguishedname"] = "CN=OTHER,OU=ELSEWHERE,DC=EXAMPLE,DC=TEST"
    elif change == "real_domain": actual["Properties"]["domain"] = "OTHER.TEST"
    elif change == "real_deleted": actual["IsDeleted"] = True
    rows = [actual, default]
    if change == "triple": rows.append(deepcopy(default))
    elif change == "two_real": rows = [actual, deepcopy(actual)]
    elif change == "two_default": rows = [default, deepcopy(default)]
    write(tmp_path, rows)
    with pytest.raises(CollectionError):
        load(tmp_path)


@pytest.mark.parametrize("meta", [{"collectorversion": "SharpHound"},
    {"collectorversion": "RustHound-CE v2.5.14"}, {"version": 5}, {"count": 1}])
def test_require_verified_envelope(tmp_path, meta):
    write(tmp_path, list(pair()), meta_changes=meta)
    with pytest.raises(CollectionError):
        load(tmp_path)


def test_never_normalize_across_files(tmp_path):
    actual, default = pair()
    write(tmp_path, [actual])
    write(tmp_path, [default], name="other_groups.json")
    with pytest.raises(CollectionError, match="do not mix collection snapshots"):
        load(tmp_path)


def test_standalone_default_is_not_removed(tmp_path):
    _, default = pair()
    write(tmp_path, [default])
    graph = load(tmp_path)
    assert graph.groups == [default]
    assert graph.collection_normalizations == []
