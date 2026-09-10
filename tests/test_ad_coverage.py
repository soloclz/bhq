"""Synthetic regressions for AD query coverage and interpretation."""
import json

from bhq import cli, queries, report
from bhq.loader import load
from .test_bhq import _write, DOM, ALICE, BOB, DAVE, DA, SRVADMINS


def replace_collection(path, kind, data):
    (path / f't_{kind}.json').write_text(json.dumps({'data': data}))


def test_gpo_creator_goal_is_not_domain_admins(tmp_path, capsys):
    _write(tmp_path)
    creator = f'{DOM}-520'
    replace_collection(tmp_path, 'groups', [
        {'ObjectIdentifier': creator, 'Properties': {'name': 'GPO CREATORS@TEST.LOCAL'},
         'Members': [{'ObjectIdentifier': DAVE}]},
        {'ObjectIdentifier': DA, 'Properties': {'name': 'RENAMED ADMINS@TEST.LOCAL'}, 'Members': []},
    ])
    g = load(tmp_path)
    assert queries.path_to_goal(g, DAVE)[0][-1][0] == creator
    assert queries.path_to_da(g, DAVE)[0] is None
    assert queries.goal_sids(g, 'da') == {DA: 'domain-admins-group'}
    assert cli.main(['path', str(tmp_path), 'dave', '--goal', 'da']) == 0
    output = capsys.readouterr().out
    assert 'goal: da' in output and 'no recorded path' in output
    assert 'local-admin hop' not in output
    data = report.build(g, 'dave')
    assert data['goal'] == 'high-value'
    assert data['path']['endpoint_reason'] == 'well-known-admin-rid'
    assert 'path_to_da' not in data
    for render in (report.as_text, report.as_md):
        text = render(data)
        assert 'high-value' in text and 'admin-equivalence' not in text


def test_already_at_goal_has_zero_hop_path(tmp_path):
    _write(tmp_path)
    g = load(tmp_path)
    assert queries.path_to_goal(g, ALICE)[0] == [(ALICE, None)]
    assert queries.path_to_da(g, DA)[0] == [(DA, None)]
    assert report.build(g, 'alice')['path']['endpoint_reason'] == 'dcsync-on-domain'
    assert queries.path_to_da(g, ALICE)[0][-1][0] == DA


def test_reachers_respect_selected_goal_and_real_domain_sid(tmp_path):
    _write(tmp_path)
    g = load(tmp_path)
    assert DAVE in queries.who_can_reach_high_value(g)
    assert DAVE not in queries.who_can_reach_high_value(g, 'da')
    assert BOB in queries.who_can_reach_high_value(g, 'da')
    unrelated = 'S-1-5-21-99-99-99-512'
    g._register({'ObjectIdentifier': unrelated, 'Properties': {'name': 'UNRELATED'}}, 'group')
    assert unrelated not in queries.goal_sids(g, 'da')


def test_nested_group_replication_grants_keep_domain_and_provenance(tmp_path):
    _write(tmp_path)
    a, b, nested = (f'{DOM}-{rid}' for rid in (1701, 1702, 1703))
    replace_collection(tmp_path, 'groups', [
        {'ObjectIdentifier': a, 'Properties': {'name': 'GRANT-A'},
         'Members': [{'ObjectIdentifier': nested}]},
        {'ObjectIdentifier': nested, 'Properties': {'name': 'NESTED'},
         'Members': [{'ObjectIdentifier': ALICE}, {'ObjectIdentifier': a}]},  # cycle
        {'ObjectIdentifier': b, 'Properties': {'name': 'GRANT-B'},
         'Members': [{'ObjectIdentifier': ALICE}]},
    ])
    replace_collection(tmp_path, 'domains', [
        {'ObjectIdentifier': DOM, 'Properties': {'name': 'TEST.LOCAL'}, 'Aces': [
            {'PrincipalSID': a, 'RightName': 'GetChanges'},
            {'PrincipalSID': b, 'RightName': 'GetChangesAll'}]},
    ])
    g = load(tmp_path)
    rows = queries.dcsync_findings(g)
    assert len(rows) == 1 and rows[0]['principal_id'] == ALICE
    assert rows[0]['domain_id'] == DOM
    grants = {grant['right']: grant for grant in rows[0]['grants']}
    assert grants['GetChanges']['membership_path'] == [ALICE, nested, a]
    assert grants['GetChangesAll']['membership_path'] == [ALICE, b]
    assert report.build(g)['dcsync_findings'] == rows
    for fmt in ('text', 'md'):
        text = report.render(g, fmt=fmt)
        assert 'GRANT-A:GetChanges' in text and 'GRANT-B:GetChangesAll' in text
    # The same memberships cannot combine grants across domains.
    replace_collection(tmp_path, 'domains', [
        {'ObjectIdentifier': DOM, 'Properties': {'name': 'TEST.LOCAL'},
         'Aces': [{'PrincipalSID': a, 'RightName': 'GetChanges'}]},
        {'ObjectIdentifier': 'S-1-5-21-40-50-60', 'Properties': {'name': 'OTHER.LOCAL'},
         'Aces': [{'PrincipalSID': b, 'RightName': 'GetChangesAll'}]},
    ])
    assert queries.dcsync_findings(load(tmp_path)) == []


def test_primary_group_replication_grants_are_not_lost_or_duplicated(tmp_path):
    _write(tmp_path)
    users = json.loads((tmp_path / 't_users.json').read_text())['data']
    users[1]['PrimaryGroupSID'] = SRVADMINS
    replace_collection(tmp_path, 'users', users)
    g = load(tmp_path)
    assert BOB in queries.dcsync_principal_sids(g)
    assert g.member_edges[BOB].count(SRVADMINS) == 1
    g._add_membership(BOB, SRVADMINS)
    assert g.member_edges_rev[SRVADMINS].count(BOB) == 1
    row = next(r for r in queries.dcsync_findings(g) if r['principal_id'] == BOB)
    assert all(grant['membership_path'] == [BOB, SRVADMINS] for grant in row['grants'])
