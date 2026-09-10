"""Reduced synthetic JSON excerpts based on RustHound-CE v2.5.12 source.

These are not live collector output or serializer-generated golden files.
See docs/rusthound-ce.md for exact upstream revision and field provenance.
"""
from copy import deepcopy
import json
import zipfile

import pytest

from bhq import cli, queries, report
from bhq.loader import CollectionError, load

DOMAIN = "S-1-5-21-10-20-30"
ALICE, BOB, GROUP = (f"{DOMAIN}-{rid}" for rid in (1001, 1002, 1600))
FRONTEND, BACKEND = (f"{DOMAIN}-{rid}" for rid in (2001, 2002))
COLLECTOR = "RustHound-CE v2.5.12"
PREFIX = "20260911000000_EXAMPLE.TEST"


def member(sid, kind="Computer"):
    return {"ObjectIdentifier": sid, "ObjectType": kind}


def ace(sid, right):
    return {"PrincipalSID": sid, "PrincipalType": "User", "RightName": right,
            "IsInherited": False}


def synthetic_collection():
    session_default = {"Results": [], "Collected": True, "FailureReason": None}
    computers = []
    for sid, name in ((FRONTEND, "FRONTEND"), (BACKEND, "BACKEND")):
        computers.append({
            "ObjectIdentifier": sid, "Properties": {
                "name": f"{name}.EXAMPLE.TEST", "samaccountname": name + "$",
                "unconstraineddelegation": sid == BACKEND, "enabled": True},
            "Aces": [], "AllowedToDelegate": [], "AllowedToAct": [],
            "LocalGroups": [], "UserRights": [], "HasSIDHistory": [],
            "Sessions": deepcopy(session_default), "PrivilegedSessions": deepcopy(session_default),
            "RegistrySessions": deepcopy(session_default), "Status": None,
        })
    computers[0]["AllowedToDelegate"] = [member(BACKEND)]
    return {
        "users": [
            {"ObjectIdentifier": ALICE, "Properties": {
                "name": "ALICE@EXAMPLE.TEST", "samaccountname": "alice", "hasspn": True,
                "serviceprincipalnames": ["HTTP/frontend.example.test"], "admincount": False,
                "enabled": True, "dontreqpreauth": False, "allowedtodelegate": []},
             "Aces": [], "AllowedToDelegate": [member(BACKEND), member("UNRESOLVED.EXAMPLE.TEST")]},
            {"ObjectIdentifier": BOB, "Properties": {
                "name": "BOB@EXAMPLE.TEST", "samaccountname": "bob", "hasspn": False,
                "dontreqpreauth": True, "enabled": True, "allowedtodelegate": []},
             "Aces": [ace(ALICE, "ForceChangePassword")], "AllowedToDelegate": []},
        ],
        "groups": [{"ObjectIdentifier": GROUP,
                    "Properties": {"name": "APP-READERS@EXAMPLE.TEST", "samaccountname": "APP-READERS"},
                    "Members": [member(BOB, "User")], "Aces": []}],
        "computers": computers,
        "domains": [{"ObjectIdentifier": DOMAIN, "Properties": {"name": "EXAMPLE.TEST"},
                     "Aces": [ace(ALICE, "GetChanges"), ace(ALICE, "GetChangesAll")],
                     "GPOChanges": {"LocalAdmins": [], "RemoteDesktopUsers": [], "DcomUsers": [],
                                    "PSRemoteUsers": [], "AffectedComputers": []},
                     "Trusts": [], "Links": []}],
        "ous": [], "gpos": [], "containers": [],
    }


def write_collection(directory, objects=None):
    objects = synthetic_collection() if objects is None else objects
    directory.mkdir(parents=True, exist_ok=True)
    for kind, data in objects.items():
        if not data:  # The upstream writer skips empty object vectors.
            continue
        meta = {"methods": 0, "type": kind, "count": len(data), "version": 6,
                "collectorversion": COLLECTOR}
        (directory / f"{PREFIX}_{kind}.json").write_text(json.dumps({"data": data, "meta": meta}))
    return directory


@pytest.mark.parametrize("zipped", [False, True], ids=["directory", "zip"])
def test_rusthound_envelope_and_existing_queries(tmp_path, zipped):
    path = write_collection(tmp_path / "collection")
    if zipped:
        archive_path = tmp_path / "collection.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for item in path.glob("*.json"):
                archive.write(item, item.name)
        path = archive_path
    g = load(path)
    data = report.build(g)
    assert len(g.users) == 2 and len(g.computers) == 2
    assert queries.kerberoastable(g)[0]["name"] == "alice"
    assert queries.asreproastable(g)[0]["name"] == "bob"
    assert queries.dcsync_principal_sids(g) == {ALICE}
    assert (BOB, "ForceChangePassword") in g.control_edges[ALICE]
    assert g.member_edges[BOB] == [GROUP]
    assert len(data["collection"]["metadata"]) == 4
    for filename, meta in data["collection"]["metadata"].items():
        assert filename.startswith(PREFIX)
        assert meta["collectorversion"] == COLLECTOR and meta["version"] == 6
        assert meta["methods"] == 0
    for renderer in (report.as_text, report.as_md):
        text = renderer(data)
        assert COLLECTOR in text and "schema=6" in text
    assert "metadata" in json.loads(report.as_json(data))["collection"]


def test_top_level_delegation_is_not_lost_when_property_is_empty(tmp_path, capsys):
    path = write_collection(tmp_path)
    g = load(path)
    result = queries.delegation(g)
    assert result["unconstrained"] == ["BACKEND$"]
    rows = {row["name"]: row for row in result["constrained"]}
    assert set(rows) == {"FRONTEND$", "alice"}
    for row in rows.values():
        assert row["to"] == []  # Target objects cannot reconstruct service-specific SPNs.
        assert row["targets"][0] == {"id": BACKEND, "name": "BACKEND.EXAMPLE.TEST",
                                     "type": "Computer", "resolved": True}
    assert rows["alice"]["targets"][1] == {
        "id": "UNRESOLVED.EXAMPLE.TEST", "name": "UNRESOLVED.EXAMPLE.TEST",
        "type": "Computer", "resolved": False}
    for fmt in ("text", "md"):
        rendered = report.render(g, fmt=fmt)
        assert "target objects: BACKEND.EXAMPLE.TEST" in rendered
        assert "UNRESOLVED.EXAMPLE.TEST [not in collection]" in rendered
    assert cli.main(["deleg", str(path)]) == 0
    assert "target objects: BACKEND.EXAMPLE.TEST" in capsys.readouterr().out


def test_raw_spns_and_target_objects_remain_distinct(tmp_path):
    objects = synthetic_collection()
    objects["users"][0]["Properties"]["allowedtodelegate"] = ["HTTP/backend.example.test"]
    g = load(write_collection(tmp_path, objects))
    row = next(row for row in queries.delegation(g)["constrained"] if row["name"] == "alice")
    assert row["to"] == ["HTTP/backend.example.test"]
    assert row["targets"][0]["id"] == BACKEND
    rendered = report.delegation_targets(row)
    assert "SPNs: HTTP/backend.example.test" in rendered and "target objects:" in rendered


def test_legacy_property_only_delegation_still_works(tmp_path):
    objects = synthetic_collection()
    user = objects["users"][0]
    del user["AllowedToDelegate"]
    user["Properties"]["allowedtodelegate"] = ["HTTP/backend.example.test"]
    row = next(row for row in queries.delegation(load(write_collection(tmp_path, objects)))["constrained"]
               if row["name"] == "alice")
    assert row["to"] == ["HTTP/backend.example.test"] and row["targets"] == []


def test_empty_local_groups_and_default_sessions_do_not_prove_collection(tmp_path):
    g = load(write_collection(tmp_path))
    assert not g.admin_edges
    assert queries.local_admin_of(g, ALICE) == []
    for counts in queries.coverage(g)["local_collections"].values():
        assert counts == {"attempted": 0, "answered": 0, "total": 2}
    warnings = queries.diagnostics(g)
    assert any("meta.methods=0" in warning for warning in warnings)
    assert not any("session results are present" in warning for warning in warnings)


def test_empty_core_type_is_omitted_without_claiming_collection_failure(tmp_path):
    objects = synthetic_collection()
    objects["groups"] = []
    g = load(write_collection(tmp_path, objects))
    assert not (tmp_path / f"{PREFIX}_groups.json").exists()
    warnings = queries.diagnostics(g)
    assert any("groups collection is missing or empty" in warning for warning in warnings)
    assert any("omits empty collections" in warning for warning in warnings)


def test_received_but_unmodeled_data_is_visible(tmp_path):
    objects = synthetic_collection()
    objects["computers"][0]["Sessions"]["Results"] = [{"UserSID": ALICE, "ComputerSID": FRONTEND}]
    objects["computers"][0]["AllowedToAct"] = [member(ALICE, "User")]
    objects["computers"][0]["UserRights"] = [
        {"Privilege": "SeRemoteInteractiveLogonRight", "Results": [member(ALICE, "User")],
         "LocalNames": [], "Collected": True, "FailureReason": None}]
    objects["domains"][0]["GPOChanges"]["LocalAdmins"] = [member(ALICE, "User")]
    objects["domains"][0]["GPOChanges"]["AffectedComputers"] = [member(FRONTEND)]
    objects["certtemplates"] = [{"ObjectIdentifier": "SYNTHETIC-TEMPLATE", "Properties": {"name": "DEMO"}}]
    g = load(write_collection(tmp_path, objects))
    assert not g.admin_edges  # GPOChanges is not a direct LocalGroups observation.
    data = report.build(g)
    filename = f"{PREFIX}_certtemplates.json"
    assert data["collection"]["unhandled_files"] == [filename]
    warnings = "\n".join(data["analysis"]["warnings"])
    for marker in (filename, "session results", "AllowedToAct", "UserRights", "GPOChanges"):
        assert marker in warnings
    assert "SYNTHETIC-TEMPLATE" not in g.by_sid


def test_failure_reason_with_collected_false_is_not_silent(tmp_path):
    # Cross-collector guard; v2.5.12 itself leaves LocalGroups empty.
    objects = synthetic_collection()
    objects["computers"][0]["LocalGroups"] = [
        {"ObjectIdentifier": f"{FRONTEND}-544", "Results": [], "LocalNames": [],
         "Collected": False, "FailureReason": "ACCESS_DENIED"}]
    g = load(write_collection(tmp_path, objects))
    assert any("Collected=false: ACCESS_DENIED" in warning for warning in queries.diagnostics(g))


@pytest.mark.parametrize("field,value,error", [
    ("type", "groups", "meta.type"), ("count", 999, "meta.count"),
    ("count", True, "meta.count"), ("version", "6", "meta.version"),
    ("methods", [], "meta.methods"), ("collectorversion", [], "meta.collectorversion"),
])
def test_metadata_cannot_misdescribe_loaded_data(tmp_path, field, value, error):
    write_collection(tmp_path)
    path = tmp_path / f"{PREFIX}_users.json"
    blob = json.loads(path.read_text())
    blob["meta"][field] = value
    path.write_text(json.dumps(blob))
    with pytest.raises(CollectionError, match=error):
        load(tmp_path)


def test_unknown_schema_warns_without_claiming_compatibility(tmp_path):
    write_collection(tmp_path)
    path = tmp_path / f"{PREFIX}_users.json"
    blob = json.loads(path.read_text())
    blob["meta"]["version"] = 99
    path.write_text(json.dumps(blob))
    assert any("unverified JSON schema versions: [99]" in warning
               for warning in queries.diagnostics(load(tmp_path)))
