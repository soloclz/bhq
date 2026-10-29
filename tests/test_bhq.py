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
from pathlib import Path
import re
from urllib.parse import unquote
import zipfile

import pytest

from bhq import cli, loader, queries, report
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


def test_members_cli_includes_primary_group_membership(tmp_path, capsys):
    """`members` must use the normalized membership graph.  Primary-group
    membership is stored on the account, not in the group's Members array."""
    _write(tmp_path)
    path = tmp_path / "t_users.json"
    blob = json.loads(path.read_text())
    blob["data"][0]["PrimaryGroupSID"] = SRVADMINS
    path.write_text(json.dumps(blob))

    from bhq import cli
    assert cli.main(["members", str(tmp_path), "SRVADMINS"]) == 0
    assert capsys.readouterr().out.splitlines() == ["alice"]


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
    txt = report.render(g, fmt="text")
    assert "alice" in txt and "ForceChangePassword" in txt
    # Markdown selects relationships that merit review; JSON retains the graph.
    md = report.render(g, fmt="md")
    assert md.startswith("# BloodHound")
    assert "## Collection" not in md and "## Recorded account settings" not in md
    assert "## Object control" in md and '```text' in md
    assert "GenericAll" in md and "t_groups.json" in md
    assert "## Privileged memberships" in md
    assert "bob --MemberOf--&gt; DOMAIN ADMINS@TEST.LOCAL" in md
    assert "bob (1 hops)" not in md
    # json round-trips and carries the structured findings
    data = json.loads(report.render(g, fmt="json"))
    assert data["dcsync"] == ["SRVADMINS@TEST.LOCAL", "alice"]
    assert any(row['name'] == 'alice' for row in data['da_reachers'])
    assert any(k["name"] == "alice" for k in data["kerberoastable"])
    assert any(row["right"] == "GetChanges" and row["evidence"]["source_file"] == "t_domains.json"
               for row in data["replication_aces"])
    assert any(setting["field"] == "serviceprincipalnames" and setting["evidence"]["source_file"] == "t_users.json"
               for row in data["account_settings"] for setting in row["settings"])
    assert "scope" in data["analysis"]
    assert any("attempted on 0/1 computers" in w and "unknown, not absent" in w
               for w in data["analysis"]["warnings"])


def _markdown_links(markdown):
    return [unquote(target.strip('<>'))
            for target in re.findall(r'\]\(([^)\n]+)\)', markdown)]


def test_report_markdown_cli_resolves_sources_from_output_directory(tmp_path, monkeypatch):
    collection = tmp_path / 'recorded (lab) #1'
    raw = collection / 'nested [raw]'
    raw.mkdir(parents=True)
    _write(raw)
    users = raw / 'round (1) #1_users.json'
    (raw / 't_users.json').rename(users)
    destination = tmp_path / 'reports (review)'
    destination.mkdir()
    output = destination / 'analysis.md'
    monkeypatch.chdir(tmp_path)

    assert cli.main(['report', str(collection.relative_to(tmp_path)), '--format', 'md',
                     '-o', str(output.relative_to(tmp_path))]) == 0
    markdown = output.read_text()
    targets = _markdown_links(markdown)
    assert targets
    assert all(not Path(target).is_absolute() for target in targets)
    monkeypatch.chdir(destination)
    resolved = {Path(target).resolve() for target in targets}
    assert resolved == {path.resolve() for path in raw.glob('*.json')}
    assert all(path.is_file() for path in resolved)


def test_report_markdown_zip_links_survive_temporary_extraction(tmp_path):
    collection = tmp_path / 'source'
    collection.mkdir()
    _write(collection)
    archive_path = tmp_path / 'raw collection (1) #1.zip'
    prefix = 'outer [raw]&<review>/inner (capture)'
    with zipfile.ZipFile(archive_path, 'w') as archive:
        for source in collection.glob('*.json'):
            archive.write(source, f'{prefix}/{source.name}')
    destination = tmp_path / 'reports'
    destination.mkdir()
    output = destination / 'analysis.md'

    assert cli.main(['report', str(archive_path), '--format', 'md', '-o', str(output)]) == 0
    markdown = output.read_text()
    targets = _markdown_links(markdown)
    assert targets
    assert {(destination / target).resolve() for target in targets} == {archive_path.resolve()}
    assert archive_path.is_file()
    assert f'`{prefix}/t_users.json`' in markdown
    assert f'`{prefix}/t_groups.json`' in markdown


def test_report_markdown_links_control_notes_without_changing_other_formats(tmp_path):
    _write(tmp_path)
    users_file = tmp_path / 't_users.json'
    users = json.loads(users_file.read_text())
    description = f'password reference [source: t_users.json:{BOB}:Aces[0]]'
    users['data'][0]['Properties']['description'] = description
    users_file.write_text(json.dumps(users))
    graph = load(tmp_path)
    data = report.build(graph)
    original_json = report.as_json(data)
    original_text = report.as_text(data)
    links = {source.name: f'[{source.name}](raw/{source.name})'
             for source in tmp_path.glob('*.json')}
    markdown = report.as_md(data, source_links=links)
    object_control = markdown.split('## Object control\n', 1)[1].split('\n## ', 1)[0]
    fenced_graph, notes = object_control.split('```text\n', 1)[1].split('\n```', 1)

    assert 'ForceChangePassword → bob' in fenced_graph
    assert '](' not in fenced_graph
    assert _markdown_links(notes)
    assert 'Aces[0]' in notes.replace(r'\[', '[').replace(r'\]', ']')
    credential_text = markdown.split('## Potential credential text\n', 1)[1].split('\n## ', 1)[0]
    assert description in credential_text
    assert _markdown_links(credential_text) == ['raw/t_users.json']
    assert report.as_json(data) == original_json
    assert report.as_text(data) == original_text
    assert _markdown_links(report.as_md(data)) == []


def test_report_markdown_distinguishes_nested_sources_with_same_basename(tmp_path):
    _write(tmp_path)
    users_path = tmp_path / 't_users.json'
    users = json.loads(users_path.read_text())['data']
    users_path.unlink()
    for directory, rows in [('first', users[:1]), ('second', users[1:])]:
        nested = tmp_path / directory
        nested.mkdir()
        (nested / 't_users.json').write_text(json.dumps({'data': rows}))
    output = tmp_path / 'analysis.md'
    markdown = report.render(load(tmp_path), fmt='md', output_path=output)
    user_targets = {(output.parent / target).resolve()
                    for target in _markdown_links(markdown) if target.endswith('t_users.json')}

    assert user_targets == {(tmp_path / 'first/t_users.json').resolve(),
                            (tmp_path / 'second/t_users.json').resolve()}


def test_report_keeps_anomalous_leads_without_routine_directory_baseline(tmp_path):
    _write(tmp_path)
    builtin = 'TEST.LOCAL-S-1-5-32-544'
    groups_file = tmp_path / 't_groups.json'
    groups = json.loads(groups_file.read_text())
    groups['data'][0]['Members'].append({'ObjectIdentifier': ADMIN})
    groups['data'][0]['Aces'] = [{'PrincipalSID': builtin, 'RightName': 'GenericWrite'},
                                 {'PrincipalSID': 'TEST.LOCAL-S-1-5-18', 'RightName': 'Owns'}]
    groups['data'].append({'ObjectIdentifier': builtin, 'Properties': {'name': 'Administrators'},
                           'Members': [{'ObjectIdentifier': ADMIN}], 'Aces': []})
    groups_file.write_text(json.dumps(groups))
    domain_file = tmp_path / 't_domains.json'
    domains = json.loads(domain_file.read_text())
    domains['data'][0]['Aces'] += [{'PrincipalSID': builtin, 'RightName': 'GetChanges'},
                                   {'PrincipalSID': builtin, 'RightName': 'GetChangesAll'}]
    domains['data'][0]['Links'] = [{'GUID': 'GPO', 'IsEnforced': False}]
    domain_file.write_text(json.dumps(domains))
    (tmp_path / 't_gpos.json').write_text(json.dumps({'data': [
        {'ObjectIdentifier': 'GPO', 'Properties': {'name': 'Default Policy'}, 'Aces': []}]}))
    users_file = tmp_path / 't_users.json'
    users = json.loads(users_file.read_text())
    users['data'].append({'ObjectIdentifier': f'{DOM}-4101', 'Properties': {
        'samaccountname': 'adfs_gmsa$', 'hasspn': True,
        'serviceprincipalnames': ['host/federation.test.local'],
        'useraccountcontrol': 4096, 'enabled': True}, 'Aces': []})
    users_file.write_text(json.dumps(users))
    computer_file = tmp_path / 't_computers.json'
    computers = json.loads(computer_file.read_text())
    computers['data'][0]['Sessions'] = {'Collected': True, 'Results': []}
    computers['data'].append({'ObjectIdentifier': f'{DOM}-1000', 'Properties': {
        'name': 'DC01.TEST.LOCAL', 'samaccountname': 'DC01$',
        'unconstraineddelegation': True}, 'PrimaryGroupSID': f'{DOM}-516', 'Aces': []})
    computer_file.write_text(json.dumps(computers))

    data = report.build(load(tmp_path))
    md = report.as_md(data)
    assert data['replication_aces'] and data['extended']['sessions']
    assert 'alice' in md and 'ForceChangePassword' in md
    assert 'adfs_gmsa$' not in md
    assert 'Unconstrained delegation: DC01$' not in md
    assert 'Administrator (1 hops)' not in md
    assert 'Administrators (1 hops)' not in md
    assert 'TEST.LOCAL-S-1-5-18' not in md
    assert 'Recorded replication ACEs' not in md
    assert 'High-value groups without recorded members' not in md
    assert 'Recorded sessions' not in md
    assert 'GPO projected changes and issues' not in md

    computers['data'][0]['Sessions'] = {'Collected': True, 'Results': [
        {'UserSID': BOB, 'ComputerSID': WS01}]}
    computer_file.write_text(json.dumps(computers))
    md = report.render(load(tmp_path), fmt='md')
    assert 'Recorded sessions' in md and 'bob' in md


def test_report_tree_keeps_multistep_object_relationships(tmp_path):
    _write(tmp_path)
    users_file = tmp_path / 't_users.json'
    users = json.loads(users_file.read_text())
    users['data'][3]['Aces'] = [{'PrincipalSID': BOB, 'RightName': 'GenericWrite'}]
    users_file.write_text(json.dumps(users))
    md = report.render(load(tmp_path), fmt='md')
    assert 'alice\n└── ForceChangePassword → bob [1]\n    └── GenericWrite → carol [2]' in md
    for prefix in ['- [1] bob [user]: Source: ', '- [2] carol [user]: Source: ']:
        note = next(line for line in md.splitlines() if line.startswith(prefix))
        assert [Path(target).resolve() for target in _markdown_links(note)] == [users_file.resolve()]


def test_report_control_shows_member_entry_and_summarizes_broad_grants(tmp_path):
    _write(tmp_path)
    alex, jordan = f'{DOM}-1101', f'{DOM}-1102'
    help_desk, support, contractors = (f'{DOM}-1701', f'{DOM}-1702', f'{DOM}-1703')
    broad, domain_users = f'{DOM}-1704', f'{DOM}-513'

    users_file = tmp_path / 't_users.json'
    users = json.loads(users_file.read_text())
    users['data'].extend([
        {'ObjectIdentifier': alex, 'Properties': {'samaccountname': 'alex'}, 'Aces': []},
        {'ObjectIdentifier': jordan, 'Properties': {'samaccountname': 'jordan'},
         'Aces': [{'PrincipalSID': help_desk, 'RightName': 'AllExtendedRights'}]},
    ])
    for index in range(80):
        users['data'].append({
            'ObjectIdentifier': f'{DOM}-{3000 + index}',
            'Properties': {'samaccountname': f'noise{index:02d}'},
            'Aces': [{'PrincipalSID': broad, 'RightName': 'GenericWrite'}],
        })
    users_file.write_text(json.dumps(users))

    groups_file = tmp_path / 't_groups.json'
    groups = json.loads(groups_file.read_text())
    groups['data'].extend([
        {'ObjectIdentifier': help_desk, 'Properties': {'name': 'Help Desk Tier III'},
         'Members': [{'ObjectIdentifier': alex, 'ObjectType': 'User'}], 'Aces': []},
        {'ObjectIdentifier': support, 'Properties': {'name': 'IT Support Managers'},
         'Members': [{'ObjectIdentifier': jordan, 'ObjectType': 'User'}], 'Aces': []},
        {'ObjectIdentifier': contractors, 'Properties': {'name': 'Contractors'},
         'Members': [], 'Aces': [{'PrincipalSID': support, 'RightName': 'GenericWrite'}]},
        {'ObjectIdentifier': broad, 'Properties': {'name': 'Broad Grant'},
         'Members': [], 'Aces': []},
        {'ObjectIdentifier': domain_users, 'Properties': {'name': 'Domain Users'},
         'Members': [{'ObjectIdentifier': alex, 'ObjectType': 'User'}], 'Aces': []},
    ])
    groups_file.write_text(json.dumps(groups))

    data = report.build(load(tmp_path))
    md = report.as_md(data)
    section = md.split('## Object control\n', 1)[1].split('\n## ', 1)[0]
    graph = section.split('```text\n', 1)[1].split('\n```', 1)[0]

    assert re.search(
        r'(?m)^alex\n└── MemberOf → Help Desk Tier III\n'
        r'    └── AllExtendedRights → jordan \[\d+\]\n'
        r'        └── MemberOf → IT Support Managers\n'
        r'            └── GenericWrite → Contractors \[\d+\]$',
        graph,
    )
    assert 'Domain Users' not in graph
    assert 'noise00' not in graph
    assert 'Broad Grant' in section and '80' in section
    assert len(section.splitlines()) < 100
    assert sum(edge['from_id'] == broad and edge['edge'] == 'GenericWrite'
               for edge in data['recorded_edges']) == 80


def test_report_control_broad_only_keeps_summary(tmp_path):
    broad = f'{DOM}-1704'
    (tmp_path / 't_groups.json').write_text(json.dumps({'data': [
        {'ObjectIdentifier': broad, 'Properties': {'name': 'Broad Grant'},
         'Members': [], 'Aces': []},
    ]}))
    (tmp_path / 't_users.json').write_text(json.dumps({'data': [
        {'ObjectIdentifier': f'{DOM}-{3000 + index}',
         'Properties': {'samaccountname': f'noise{index:02d}'},
         'Aces': [{'PrincipalSID': broad, 'RightName': 'GenericWrite'}]}
        for index in range(51)
    ]}))

    data = report.build(load(tmp_path))
    section = report.as_md(data).split('## Object control\n', 1)[1].split('\n## ', 1)[0]
    assert 'Broad Grant: GenericWrite on 51 targets' in section
    assert 'noise00' not in section
    assert len(section.splitlines()) < 10
    assert sum(edge['from_id'] == broad for edge in data['recorded_edges']) == 51


def test_laps_read_does_not_become_computer_identity(tmp_path):
    _write(tmp_path)
    eve = f'{DOM}-1005'
    users_file = tmp_path / 't_users.json'
    users = json.loads(users_file.read_text())
    users['data'].append({'ObjectIdentifier': eve, 'Properties': {'samaccountname': 'eve'}, 'Aces': []})
    users_file.write_text(json.dumps(users))
    computer_file = tmp_path / 't_computers.json'
    computers = json.loads(computer_file.read_text())
    computers['data'][0]['Aces'] = [{'PrincipalSID': eve, 'RightName': 'ReadLAPSPassword'}]
    computer_file.write_text(json.dumps(computers))
    domain_file = tmp_path / 't_domains.json'
    domains = json.loads(domain_file.read_text())
    domains['data'][0]['Aces'] += [
        {'PrincipalSID': WS01, 'RightName': 'GetChanges'},
        {'PrincipalSID': WS01, 'RightName': 'GetChangesAll'}]
    domain_file.write_text(json.dumps(domains))

    g = load(tmp_path)
    assert any(right == 'ReadLAPSPassword' for _, _, right, _ in queries.control_rows(g, eve))
    assert eve not in queries.who_can_reach_high_value(g)
    assert queries.path_to_goal(g, eve)[0] is None
    assert 'ReadLAPSPassword → WS01.TEST.LOCAL' in report.render(g, fmt='md')
    assert 'not its computer-account password' in report.render(g, fmt='md')


def test_report_exhausts_control_graph_and_keeps_alternate_edges(tmp_path):
    _write(tmp_path)
    users_file = tmp_path / "t_users.json"
    users = json.loads(users_file.read_text())
    by_sid = {row["ObjectIdentifier"]: row for row in users["data"]}
    by_sid[CAROL]["Aces"] = [{"PrincipalSID": BOB, "RightName": "GenericWrite"},
                             {"PrincipalSID": BOB, "RightName": "WriteDacl"}]
    by_sid[DAVE]["Aces"] = [{"PrincipalSID": CAROL, "RightName": "GenericAll"}]
    by_sid[ALICE]["Aces"] = [{"PrincipalSID": DAVE, "RightName": "GenericWrite"}]
    by_sid[DAVE]["NewFeature"] = {"Finding": "retained material"}
    users_file.write_text(json.dumps(users))
    groups_file = tmp_path / "t_groups.json"
    groups = json.loads(groups_file.read_text())
    groups["data"][0]["Members"] = [{"ObjectIdentifier": DAVE}]
    groups_file.write_text(json.dumps(groups))

    data = report.build(load(tmp_path))
    da_path = next(row['path'] for row in data['da_reachers'] if row['name'] == 'alice')
    assert [step['name'] for step in da_path] == ['alice', 'bob', 'carol', 'dave', 'DOMAIN ADMINS@TEST.LOCAL']
    alternatives = [row for row in data['recorded_edges'] if row['from_id'] == BOB and row['to_id'] == CAROL]
    assert {row["edge"] for row in alternatives} == {"GenericWrite", "WriteDacl"}
    assert all(row["evidence"][0]["source_file"] == "t_users.json" for row in alternatives)
    assert any(row['from_id'] == DAVE and row['to_id'] == ALICE for row in data['recorded_edges'])
    assert any(row["from_id"] == BOB and row["to_id"] == CAROL for row in data["recorded_edges"])
    assert any(row["value"] == "retained material" for row in data["raw_observations"])
    md = report.as_md(data)
    assert 'alice (4 hops)' in md
    assert 'ForceChangePassword' in md
    assert "retained material" not in md and "NewFeature.Finding" not in md


def test_report_does_not_dump_builtin_descriptions_or_normal_account_flags(tmp_path):
    _write(tmp_path)
    groups_file = tmp_path / "t_groups.json"
    groups = json.loads(groups_file.read_text())
    for index in range(40):
        groups["data"].append({"ObjectIdentifier": f"{DOM}-{100 + index}",
                               "Properties": {"name": f"BUILTIN-{index}",
                                              "description": f"Generic group description {index}"},
                               "Aces": [{"PrincipalSID": DA, "RightName": "GenericAll"}]})
    groups["data"].append({"ObjectIdentifier": f"{DOM}-1700",
                           "Properties": {"name": "APP-OPS", "description": "Review application role"},
                           "Aces": []})
    groups_file.write_text(json.dumps(groups))
    users_file = tmp_path / "t_users.json"
    users = json.loads(users_file.read_text())
    users["data"][0]["Properties"].update(dontreqpreauth=False, trustedtoauth=False,
                                             passwordnotreqd=False, lastlogon=0)
    users_file.write_text(json.dumps(users))
    data = report.build(load(tmp_path))
    md = report.as_md(data)
    assert len([row for row in data["property_clues"] if "description" in row["properties"]]) == 41
    assert "Generic group description" not in md
    assert "Review application role" not in md
    assert "dontreqpreauth=false" not in md and "lastlogon=0" not in md
    assert not any(signal['field'] == 'dontreqpreauth' for row in data['account_findings']
                   if row['account']['id'] == ALICE for signal in row['signals'])
    assert "Recorded ACL control and membership edges" not in md
    assert "## Collection" not in md
    assert len(md) < 15_000


def test_report_rejects_removed_goal_option(tmp_path, capsys):
    _write(tmp_path)
    assert cli.main(["report", str(tmp_path), "--goal", "da"]) == 2
    assert "unexpected argument(s): --goal da" in capsys.readouterr().err


def test_report_rejects_identity_scope(tmp_path, capsys):
    _write(tmp_path)
    assert cli.main(['report', str(tmp_path), '--from', 'alice']) == 2
    assert 'unexpected argument(s): --from alice' in capsys.readouterr().err


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
    with pytest.raises(SystemExit, match='1'):
        cli.main(['path', str(tmp_path), 'alice'])
