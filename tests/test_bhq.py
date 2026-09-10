"""Tests over a tiny synthetic collection exercising each edge type.

Graph:  alice --ForceChangePassword--> bob --MemberOf--> DOMAIN ADMINS
        alice --(GetChanges+GetChangesAll on domain)--> DCSync
        alice --AdminTo--> WS01
        alice has an SPN (kerberoastable); bob has no-preauth (asrep)

        dave --GenericWrite--> carol --GenericAll--> SRVADMINS
        SRVADMINS: custom RID (1622), *zero members*, holds GetChanges +
        GetChangesAll on the domain object.

The second chain is the regression case: the goal is a group nobody named in
advance, that is not Domain Admins, and that has no members — so neither a
hard-coded name list nor a membership-based audit sees it, while its recorded replication grants make it an investigation target.
"""

from __future__ import annotations

import json
import zipfile

import pytest

from bhq import loader, queries, report
from bhq.loader import CollectionError, load

DOM = "S-1-5-21-1-1-1"
ALICE, BOB, ADMIN = f"{DOM}-1001", f"{DOM}-1002", f"{DOM}-500"
CAROL, DAVE = f"{DOM}-1003", f"{DOM}-1004"
DA, WS01 = f"{DOM}-512", f"{DOM}-2001"
SRVADMINS = f"{DOM}-1622"          # custom RID: no pre-written list can hold it


def _write(d):
    (d / "t_users.json").write_text(json.dumps({"data": [
        {"ObjectIdentifier": ALICE, "Properties": {"samaccountname": "alice", "hasspn": True,
            "serviceprincipalnames": ["MSSQLSvc/db"], "admincount": False, "enabled": True}, "Aces": []},
        {"ObjectIdentifier": BOB, "Properties": {"samaccountname": "bob", "dontreqpreauth": True},
            "Aces": [{"PrincipalSID": ALICE, "RightName": "ForceChangePassword"}]},
        {"ObjectIdentifier": ADMIN, "Properties": {"samaccountname": "Administrator", "admincount": True}, "Aces": []},
        {"ObjectIdentifier": CAROL, "Properties": {"samaccountname": "carol"},
            "Aces": [{"PrincipalSID": DAVE, "RightName": "GenericWrite"}]},
        {"ObjectIdentifier": DAVE, "Properties": {"samaccountname": "dave"}, "Aces": []},
    ]}))
    (d / "t_groups.json").write_text(json.dumps({"data": [
        {"ObjectIdentifier": DA, "Properties": {"name": "DOMAIN ADMINS@TEST.LOCAL"},
            "Members": [{"ObjectIdentifier": BOB, "ObjectType": "User"}], "Aces": []},
        {"ObjectIdentifier": SRVADMINS, "Properties": {"name": "SRVADMINS@TEST.LOCAL"},
            "Members": [], "Aces": [{"PrincipalSID": CAROL, "RightName": "GenericAll"}]},
    ]}))
    (d / "t_computers.json").write_text(json.dumps({"data": [
        {"ObjectIdentifier": WS01, "Properties": {"name": "WS01.TEST.LOCAL"},
            "LocalAdmins": {"Collected": True, "Results": [{"ObjectIdentifier": ALICE, "ObjectType": "User"}]},
            "Aces": []},
    ]}))
    (d / "t_domains.json").write_text(json.dumps({"data": [
        {"ObjectIdentifier": DOM, "Properties": {"name": "TEST.LOCAL"}, "Aces": [
            {"PrincipalSID": ALICE, "RightName": "GetChanges"},
            {"PrincipalSID": ALICE, "RightName": "GetChangesAll"},
            {"PrincipalSID": SRVADMINS, "RightName": "GetChanges"},
            {"PrincipalSID": SRVADMINS, "RightName": "GetChangesAll"},
        ]},
    ]}))


def test_load_and_coverage(tmp_path):
    _write(tmp_path)
    g = load(str(tmp_path))
    cov = queries.coverage(g)
    assert cov["users"] == 5 and cov["computers"] == 1
    assert cov["local_collections"]["AdminTo"] == {"attempted": 1, "answered": 1, "total": 1}
    assert cov["local_collections"]["CanRDP"] == {"attempted": 0, "answered": 0, "total": 1}
    assert g.sid_of("alice") == ALICE
    assert g.sid_of("DOMAIN ADMINS") == DA          # short-form match


def test_attempted_but_unanswered_is_not_a_negative(tmp_path):
    """A local group the collector asked about but got nothing back from is
    unknown, not empty — bloodhound.py never fills FailureReason, so a refused
    SAMR query looks exactly like a group with no members."""
    _write(tmp_path)
    (tmp_path / "t_computers.json").write_text(json.dumps({"data": [
        {"ObjectIdentifier": WS01, "Properties": {"name": "WS01.TEST.LOCAL"}, "Aces": [],
         "LocalGroups": [
             {"ObjectIdentifier": f"{WS01}-544", "Name": "ADMINISTRATORS@WS01.TEST.LOCAL",
              "Collected": True, "FailureReason": None, "Results": []},
         ]},
    ]}))
    g = load(str(tmp_path))
    cov = queries.coverage(g)
    assert cov["local_collections"]["AdminTo"] == {"attempted": 1, "answered": 0, "total": 1}
    assert any("came back with no members on 1 of 1 attempted computers" in w
               for w in queries.diagnostics(g))


def test_reported_failure_reason_is_surfaced_not_flattened(tmp_path):
    """When a collector does say why a group came back empty, that reason separates
    "refused" from "genuinely empty" — the whole point of keeping the third state.
    Discarding it at load time would collapse a known cause back into unknown."""
    _write(tmp_path)
    (tmp_path / "t_computers.json").write_text(json.dumps({"data": [
        {"ObjectIdentifier": WS01, "Properties": {"name": "WS01.TEST.LOCAL"}, "Aces": [],
         "LocalGroups": [
             {"ObjectIdentifier": f"{WS01}-544", "Name": "ADMINISTRATORS@WS01.TEST.LOCAL",
              "Collected": True, "FailureReason": "SamrOpenAlias: ACCESS_DENIED",
              "Results": []},
         ]},
    ]}))
    g = load(str(tmp_path))
    assert g.local_failures["AdminTo"][WS01] == "SamrOpenAlias: ACCESS_DENIED"
    warning = next(w for w in queries.diagnostics(g) if "came back with no members" in w)
    assert "SamrOpenAlias: ACCESS_DENIED" in warning
    assert "look identical" not in warning


def test_partially_answered_capability_still_warns(tmp_path):
    """One computer answering does not vouch for the one that stayed silent."""
    _write(tmp_path)
    ws02 = f"{DOM}-2002"
    (tmp_path / "t_computers.json").write_text(json.dumps({"data": [
        {"ObjectIdentifier": WS01, "Properties": {"name": "WS01.TEST.LOCAL"}, "Aces": [],
         "LocalGroups": [{"ObjectIdentifier": f"{WS01}-544", "Collected": True,
                          "Results": [{"ObjectIdentifier": ALICE, "ObjectType": "User"}]}]},
        {"ObjectIdentifier": ws02, "Properties": {"name": "WS02.TEST.LOCAL"}, "Aces": [],
         "LocalGroups": [{"ObjectIdentifier": f"{ws02}-544", "Collected": True, "Results": []}]},
    ]}))
    g = load(str(tmp_path))
    assert queries.coverage(g)["local_collections"]["AdminTo"] == {
        "attempted": 2, "answered": 1, "total": 2}
    assert any("AdminTo came back with no members on 1 of 2 attempted computers" in w
               for w in queries.diagnostics(g))


def test_ou_sharing_a_group_name_is_not_ambiguous(tmp_path):
    """AD commonly holds an OU and a group of the same name. Only the group is a
    principal, so the name must still resolve instead of erroring as ambiguous."""
    _write(tmp_path)
    (tmp_path / "t_ous.json").write_text(json.dumps({"data": [
        {"ObjectIdentifier": "D20D021E-C7AF-4F7D-B2EE-D70A383873E0",
         "Properties": {"name": "SRVADMINS@TEST.LOCAL"}, "Aces": []},
    ]}))
    g = load(str(tmp_path))
    assert g.sid_of("SRVADMINS") == SRVADMINS
    assert g.sid_candidates("SRVADMINS") == {SRVADMINS}


def test_rotated_overflow_file_is_loaded(tmp_path):
    """Collectors start `<prefix>_users_01.json` after 40000 objects of a type;
    the overflow must be loaded, not silently dropped."""
    _write(tmp_path)
    (tmp_path / "t_users_01.json").write_text(json.dumps({"data": [
        {"ObjectIdentifier": f"{DOM}-1005", "Properties": {"samaccountname": "erin"}, "Aces": []},
    ]}))
    g = load(str(tmp_path))
    assert queries.coverage(g)["users"] == 6
    assert g.sid_of("erin") == f"{DOM}-1005"


CE_RIDS = {"544": "AdminTo", "555": "CanRDP", "562": "ExecuteDCOM", "580": "CanPSRemote"}


def _legacy_computer(members):
    return {"ObjectIdentifier": WS01, "Properties": {"name": "WS01.TEST.LOCAL"}, "Aces": [],
            **{field: {"Collected": True, "Results": [{"ObjectIdentifier": members[label],
                                                       "ObjectType": "User"}]}
               for field, label in loader.LOCAL_COLLECTIONS.items()}}


def _ce_computer(members):
    return {"ObjectIdentifier": WS01, "Properties": {"name": "WS01.TEST.LOCAL"}, "Aces": [],
            "LocalGroups": [
                {"ObjectIdentifier": f"{WS01}-{rid}", "Name": f"{label}@WS01.TEST.LOCAL",
                 "Collected": True, "FailureReason": None,
                 "Results": [{"ObjectIdentifier": members[label], "ObjectType": "User"}]}
                for rid, label in CE_RIDS.items()]}


def test_ce_localgroups_layout_matches_legacy(tmp_path):
    """BloodHound CE (JSON v6) files the same local access under `LocalGroups`, keyed
    by well-known RID. Both layouts must produce the same edges and the same coverage,
    across all four capabilities."""
    members = {"AdminTo": ALICE, "CanRDP": BOB, "ExecuteDCOM": CAROL, "CanPSRemote": DAVE}
    results = []
    for build in (_legacy_computer, _ce_computer):
        _write(tmp_path)
        (tmp_path / "t_computers.json").write_text(json.dumps({"data": [build(members)]}))
        g = load(str(tmp_path))
        results.append((queries.coverage(g)["local_collections"],
                        {p: sorted(e) for p, e in g.admin_edges.items()}))
    (legacy_cov, legacy_edges), (ce_cov, ce_edges) = results
    assert ce_cov == legacy_cov
    assert ce_edges == legacy_edges
    for label, principal in members.items():
        assert ce_cov[label] == {"attempted": 1, "answered": 1, "total": 1}
        assert ce_edges[principal] == [(WS01, label)]        # exactly once, no double-count


def test_offline_crackable(tmp_path):
    _write(tmp_path)
    g = load(str(tmp_path))
    assert [k["name"] for k in queries.kerberoastable(g)] == ["alice"]
    assert [a["name"] for a in queries.asreproastable(g)] == ["bob"]


def test_dcsync(tmp_path):
    _write(tmp_path)
    g = load(str(tmp_path))
    assert queries.dcsync_principals(g) == ["SRVADMINS@TEST.LOCAL", "alice"]


@pytest.mark.parametrize("grants, expected", [
    ([(0, ALICE, "GetChanges"), (1, ALICE, "GetChangesAll")], set()),
    ([(0, ALICE, "GetChanges"), (0, BOB, "GetChangesAll")], set()),
    ([(1, ALICE, "GetChanges"), (1, ALICE, "GetChangesAll")], {ALICE}),
    ([(1, ALICE, "DCSync")], {ALICE}),
    ([(0, ALICE, "GetChanges"), (0, ALICE, "GetChangesInFilteredSet")], set()),
], ids=["split-domains", "split-principals", "same-domain", "combined-edge", "filtered-set-only"])
def test_dcsync_requires_matching_domain_and_principal(tmp_path, grants, expected):
    _write(tmp_path)
    domains = [
        {"ObjectIdentifier": DOM, "Properties": {"name": "TEST.LOCAL"}, "Aces": []},
        {"ObjectIdentifier": "S-1-5-21-2-2-2", "Properties": {"name": "OTHER.LOCAL"}, "Aces": []},
    ]
    for index, principal, right in grants:
        domains[index]["Aces"].append({"PrincipalSID": principal, "RightName": right})
    (tmp_path / "t_domains.json").write_text(json.dumps({"data": domains}))
    g = load(tmp_path)
    assert queries.dcsync_principal_sids(g) == expected
    assert {sid for sid, why in queries.high_value_sids(g).items()
            if why == "dcsync-on-domain"} == expected
    assert report.build(g)["dcsync"] == sorted(g.name(sid) for sid in expected)


def test_path_to_da(tmp_path):
    _write(tmp_path)
    g = load(str(tmp_path))
    path, _ = queries.path_to_da(g, ALICE)
    assert path is not None
    names = [g.name(sid) for sid, _ in path]
    labels = [lbl for _, lbl in path]
    assert names[0] == "alice"
    assert "bob" in names
    assert "ForceChangePassword" in labels and "MemberOf" in labels
    assert g.name(path[-1][0]).upper().startswith("DOMAIN ADMINS")


def test_reverse_control_index(tmp_path):
    """The inbound direction: who can write to this object? Without it, "nobody
    can reach SRVADMINS" is unanswerable rather than false."""
    _write(tmp_path)
    g = load(str(tmp_path))
    assert (CAROL, "GenericAll") in g.control_edges_rev[SRVADMINS]
    assert (DAVE, "GenericWrite") in g.control_edges_rev[CAROL]
    assert BOB in g.member_edges_rev[DA]


def test_high_value_is_derived_not_named(tmp_path):
    """A custom group holding DCSync is high-value because of the right it holds,
    not because its name appears in a list."""
    _write(tmp_path)
    g = load(str(tmp_path))
    hv = queries.high_value_sids(g)
    assert hv[SRVADMINS] == "dcsync-on-domain"
    assert hv[DA] == "well-known-high-value-rid"
    assert hv[ADMIN] == "well-known-high-value-rid"
    assert CAROL not in hv and DAVE not in hv


def test_zero_member_high_value_group_is_reported(tmp_path):
    """An empty privileged group is the interesting case, not one to filter out."""
    _write(tmp_path)
    g = load(str(tmp_path))
    rows = {name: (members, why) for name, members, why in queries.high_value_members(g)}
    assert rows["SRVADMINS@TEST.LOCAL"] == ([], "dcsync-on-domain")
    assert rows["DOMAIN ADMINS@TEST.LOCAL"][0] == ["bob"]


def test_path_reaches_custom_dcsync_group(tmp_path):
    """The regression this whole change exists for: two control hops into a custom,
    memberless group that can DCSync. The old name-keyed goal set returned None."""
    _write(tmp_path)
    g = load(str(tmp_path))
    path, _ = queries.path_to_goal(g, DAVE)
    assert path is not None
    assert [g.name(sid) for sid, _ in path] == ["dave", "carol", "SRVADMINS@TEST.LOCAL"]
    assert [lbl for _, lbl in path] == [None, "GenericWrite", "GenericAll"]


def test_who_can_reach_high_value(tmp_path):
    """One backward pass answers it for everyone, including hop counts."""
    _write(tmp_path)
    g = load(str(tmp_path))
    reach = queries.who_can_reach_high_value(g)
    assert reach[DAVE][0] == 2
    assert reach[CAROL][0] == 1
    assert reach[BOB][0] == 1              # MemberOf Domain Admins
    assert ALICE not in reach              # already high-value (holds DCSync itself)
    # chain reads reacher -> goal, each name paired with the right it holds over the next
    assert reach[DAVE][1] == [("dave", "GenericWrite"), ("carol", "GenericAll"),
                              ("SRVADMINS@TEST.LOCAL", "")]


def test_cli_positional_option_hint(capsys):
    from bhq import cli
    assert cli.main(["report", "from", "bob"]) == 2
    assert "collection path first" in capsys.readouterr().err


def test_cli_rejects_missing_collection(tmp_path, capsys):
    from bhq import cli
    with pytest.raises(SystemExit) as exc:
        cli.main(["report", str(tmp_path / "missing")])
    assert exc.value.code == 2
    assert "collection path does not exist" in capsys.readouterr().err


def test_local_admin(tmp_path):
    _write(tmp_path)
    g = load(str(tmp_path))
    la = queries.local_admin_of(g, ALICE)
    assert ("WS01.TEST.LOCAL", "AdminTo") in la


def test_report_formats(tmp_path):
    _write(tmp_path)
    g = load(str(tmp_path))
    # text mentions the kerberoastable account and the control edge
    txt = report.render(g, "alice", fmt="text")
    assert "alice" in txt and "ForceChangePassword" in txt
    # markdown has a table header
    md = report.render(g, "alice", fmt="md")
    assert md.startswith("# BloodHound") and "| account | SPN | admincount |" in md
    # json round-trips and carries the structured findings
    data = json.loads(report.render(g, "alice", fmt="json"))
    assert data["dcsync"] == ["SRVADMINS@TEST.LOCAL", "alice"]
    assert data["path"]["path"][0]["name"] == "alice"
    assert any(k["name"] == "alice" for k in data["kerberoastable"])
    assert "scope" in data["analysis"]
    assert any("attempted on 0/1 computers" in w and "unknown, not absent" in w
               for w in data["analysis"]["warnings"])


def test_missing_empty_and_malformed_collections_are_rejected(tmp_path):
    with pytest.raises(CollectionError, match="does not exist"):
        load(str(tmp_path / "missing"))
    with pytest.raises(CollectionError, match="no recognised"):
        load(str(tmp_path))
    (tmp_path / "bad_users.json").write_text("{not-json")
    with pytest.raises(CollectionError, match="invalid JSON"):
        load(str(tmp_path))


def test_recognised_but_empty_collection_is_rejected(tmp_path):
    (tmp_path / "empty_users.json").write_text('{"data": []}')
    with pytest.raises(CollectionError, match="contain no objects"):
        load(tmp_path)


def test_nested_zip_collection(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    _write(source)
    archive_path = tmp_path / "collection.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for source_file in source.glob("*.json"):
            archive.write(source_file, f"outer/inner/{source_file.name}")
    g = load(str(archive_path))
    assert g.sid_of("alice") == ALICE
    assert queries.coverage(g)["users"] == 5


def test_unsafe_zip_member_is_rejected(tmp_path):
    archive_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escape_users.json", '{"data": []}')
    with pytest.raises(CollectionError, match="unsafe ZIP member"):
        load(archive_path)


def test_duplicate_snapshot_objects_are_rejected(tmp_path):
    _write(tmp_path)
    (tmp_path / "duplicate_users.json").write_text(json.dumps({"data": [
        {"ObjectIdentifier": ALICE, "Properties": {"samaccountname": "alice"}, "Aces": []},
    ]}))
    with pytest.raises(CollectionError, match="duplicate ObjectIdentifier"):
        load(str(tmp_path))


def test_ambiguous_multidomain_short_name_requires_qualification(tmp_path):
    _write(tmp_path)
    other_sid = "S-1-5-21-2-2-2-1001"
    (tmp_path / "other_users.json").write_text(json.dumps({"data": [
        {"ObjectIdentifier": other_sid, "Properties": {
            "samaccountname": "alice", "name": "ALICE@OTHER.LOCAL"
        }, "Aces": []},
    ]}))
    g = load(str(tmp_path))
    assert g.sid_of("alice") is None
    assert g.sid_candidates("alice") == {ALICE, other_sid}
    assert g.sid_of("ALICE@OTHER.LOCAL") == other_sid
    data = report.build(g, "alice")
    assert "ambiguous" in data["error"]
