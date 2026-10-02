"""Synthetic regressions for AD query coverage and interpretation."""
import json

from bhq import cli, queries, report
from bhq.loader import load
from .test_bhq import _write, DOM, ALICE, BOB, CAROL, DAVE, DA, SRVADMINS


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
    data = report.build(g)
    assert any(row['name'] == 'dave' and row['path'][-1]['name'] == 'GPO CREATORS@TEST.LOCAL'
               for row in data['reachers'])
    assert not any(row['name'] == 'dave' for row in data['da_reachers'])
    assert any(row['id'] == DA and row['domain_admins'] for row in data['targets'])
    assert 'path_to_da' not in data
    for render in (report.as_text, report.as_md):
        text = render(data)
        assert 'high-value' in text and 'admin-equivalence' not in text


def test_already_at_goal_has_zero_hop_path(tmp_path):
    _write(tmp_path)
    g = load(tmp_path)
    assert queries.path_to_goal(g, ALICE)[0] == [(ALICE, None)]
    assert queries.path_to_da(g, DA)[0] == [(DA, None)]
    assert report.build(g)['targets']
    assert queries.goal_sids(g)[ALICE] == 'dcsync-on-domain'
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


def test_gpo_ou_container_acls_are_visible_without_inventing_policy_effects(tmp_path):
    _write(tmp_path)
    for kind in ('gpos', 'ous', 'containers'):
        replace_collection(tmp_path, kind, [
            {'ObjectIdentifier': f'TEST-{kind}', 'Properties': {'name': 'POLICY@TEST.LOCAL'},
             'Aces': [{'PrincipalSID': DAVE, 'RightName': 'GenericAll'}]},
        ])
    g = load(tmp_path)
    targets = {sid for sid, right in g.control_edges[DAVE] if right == 'GenericAll'}
    assert {'TEST-gpos', 'TEST-ous', 'TEST-containers'} <= targets
    assert len(queries.controls(g, DAVE, 1)) == 4  # three policy objects plus carol
    assert not any(sid.startswith('TEST-') for sid in queries.goal_sids(g))
    assert queries.object_details(g, 'TEST-gpos')['source_file'] == 't_gpos.json'


def test_controls_details_links_edges_to_distinct_targets_without_guessing_dn(tmp_path, capsys):
    _write(tmp_path)
    users = json.loads((tmp_path / 't_users.json').read_text())['data']
    next(user for user in users if user['ObjectIdentifier'] == CAROL)['Properties']['distinguishedname'] = (
        'CN=carol,CN=Users,DC=test,DC=local')
    replace_collection(tmp_path, 'users', users)
    replace_collection(tmp_path, 'ous', [
        {'ObjectIdentifier': 'TEST-OU', 'Properties': {
            'name': 'ADCS@TEST.LOCAL', 'distinguishedname': 'OU=ADCS,DC=test,DC=local'},
         'Aces': [{'PrincipalSID': DAVE, 'RightName': 'GenericAll'},
                  {'PrincipalSID': DAVE, 'RightName': 'WriteDacl'}]},
        {'ObjectIdentifier': 'TEST-DUP', 'Properties': {
            'name': 'SRVADMINS@TEST.LOCAL', 'distinguishedname': 'OU=SRVADMINS,DC=test,DC=local'},
         'Aces': [{'PrincipalSID': DAVE, 'RightName': 'GenericAll'}]},
    ])

    assert cli.main(['controls', str(tmp_path), 'dave', '-d', '2']) == 0
    plain = capsys.readouterr().out
    assert 'Objects (control targets)' not in plain
    assert 'dave --GenericAll--> ADCS' in plain

    assert cli.main(['controls', str(tmp_path), 'dave', '-d', '2', '--details']) == 0
    graph, details = capsys.readouterr().out.split('\nObjects (control targets):\n')
    assert graph.count('ADCS@TEST.LOCAL [') == 2
    assert details.count('ObjectIdentifier: TEST-OU') == 1
    assert 'DN: OU=ADCS,DC=test,DC=local' in details
    assert 'DN: CN=carol,CN=Users,DC=test,DC=local' in details
    assert 'DN: (not recorded)' in details  # the group reached from carol has no DN
    assert '[ou]' in details and '[user]' in details
    assert 'ObjectIdentifier: TEST-DUP' in details
    assert 'DN: OU=SRVADMINS,DC=test,DC=local' in details
    assert details.count('SRVADMINS@TEST.LOCAL') == 2  # same name, distinct group and OU

    assert cli.main(['controls', str(tmp_path), 'bob', '-d', '1', '--details']) == 0
    member_only = capsys.readouterr().out
    assert '--MemberOf--> DOMAIN ADMINS' in member_only
    assert 'Objects (control targets):\n(none in the displayed graph)' in member_only


def test_object_lookup_preserves_principal_disambiguation(tmp_path, capsys):
    import pytest
    _write(tmp_path)
    replace_collection(tmp_path, 'ous', [
        {'ObjectIdentifier': 'TEST-OU', 'Properties': {'name': 'SRVADMINS@TEST.LOCAL'}}])
    g = load(tmp_path)
    assert g.sid_of('SRVADMINS') == SRVADMINS  # control commands resolve principals only
    assert set(queries.object_candidates(g, 'srvadmins')) == {SRVADMINS, 'TEST-OU'}
    with pytest.raises(SystemExit):
        cli.main(['object', str(tmp_path), 'srvadmins'])
    assert 'ambiguous object' in capsys.readouterr().err
    assert cli.main(['object', str(tmp_path), 'TEST-OU']) == 0
    output = json.loads(capsys.readouterr().out)
    assert output['object']['Properties']['name'] == 'SRVADMINS@TEST.LOCAL'
    assert cli.main(['objects', str(tmp_path), '--kind', 'ou', '--match', 'srv']) == 0
    assert 'TEST-OU' in capsys.readouterr().out


def test_property_clues_preserve_values_false_flags_and_full_record(tmp_path, capsys):
    _write(tmp_path)
    users = json.loads((tmp_path / 't_users.json').read_text())['data']
    users[0]['Properties'].update(description='Ask the demo helpdesk', homedirectory=r'\\files.example.test\homes',
                                  passwordnotreqd=True, enabled=False, arbitrary_field='kept in object')
    users[1]['Properties'].update(description='', passwordnotreqd=False, enabled=True)
    replace_collection(tmp_path, 'users', users)
    g = load(tmp_path)
    row = next(row for row in queries.property_clues(g) if row['id'] == ALICE)
    assert row['properties'] == {'description': 'Ask the demo helpdesk',
                                'homedirectory': r'\\files.example.test\homes',
                                'passwordnotreqd': True, 'enabled': False}
    assert row['source_file'] == 't_users.json'
    assert not any(row['id'] == BOB for row in queries.property_clues(g))
    assert queries.object_details(g, ALICE)['object']['Properties']['arbitrary_field'] == 'kept in object'
    assert cli.main(['clues', str(tmp_path), '--kind', 'user']) == 0
    output = capsys.readouterr().out
    assert 'Ask the demo helpdesk' in output and 'not verified credentials' in output


def test_report_keeps_all_clues_in_json_without_dumping_routine_text(tmp_path):
    _write(tmp_path)
    replace_collection(tmp_path, 'users', [
        {'ObjectIdentifier': f'{DOM}-{1800+i}', 'Properties': {'name': f'USER-{i}', 'description': f'NOTE-{i}'}}
        for i in range(7)])
    g = load(tmp_path)
    data = report.build(g)
    assert len(data['property_clues']) == 7
    for render in (report.as_text, report.as_md):
        output = render(data)
        assert all(f'NOTE-{i}' not in output for i in range(7))
    assert all(f'NOTE-{i}' in report.as_json(data) for i in range(7))


def test_rbcd_configuration_preserves_principals_without_creating_paths(tmp_path, capsys):
    _write(tmp_path)
    computers = json.loads((tmp_path / 't_computers.json').read_text())['data']
    computers[0]['AllowedToAct'] = [
        {'ObjectIdentifier': DAVE, 'ObjectType': 'User'},
        {'ObjectIdentifier': 'S-1-5-21-99-99-99-1001', 'ObjectType': 'Computer'},
    ]
    replace_collection(tmp_path, 'computers', computers)
    g = load(tmp_path)
    rows = queries.delegation(g)['rbcd']
    assert len(rows) == 1 and rows[0]['target_id'] == computers[0]['ObjectIdentifier']
    assert rows[0]['principals'][0]['name'] == 'dave'
    assert rows[0]['principals'][1]['resolved'] is False
    assert rows[0]['source_file'] == 't_computers.json'
    assert all(label != 'AllowedToAct' for edges in g.control_edges.values() for _, label in edges)
    assert cli.main(['deleg', str(tmp_path)]) == 0
    assert 'not in collection' in capsys.readouterr().out
    for fmt in ('text', 'md'):
        assert 'AllowedToAct on WS01.TEST.LOCAL' in report.render(g, fmt=fmt)


def test_trust_summary_preserves_source_direction_false_unknown_and_flags(tmp_path, capsys):
    _write(tmp_path)
    domains = json.loads((tmp_path / 't_domains.json').read_text())['data']
    domains[0]['Trusts'] = [
        {'TargetDomainSid': 'S-1-5-21-40-50-60', 'TargetDomainName': 'OTHER.LOCAL',
         'TrustDirection': 'Inbound', 'TrustType': 'Forest', 'IsTransitive': False,
         'SidFilteringEnabled': False, 'TrustAttributes': 8},
        {'TargetDomainName': 'UNKNOWN.LOCAL', 'TrustDirection': 99},
    ]
    replace_collection(tmp_path, 'domains', domains)
    g = load(tmp_path)
    rows = queries.trusts(g)
    row = next(r for r in rows if r['trust']['TargetDomainName'] == 'OTHER.LOCAL')
    assert row['source_id'] == DOM and row['trust']['TrustDirection'] == 'Inbound'
    assert row['trust']['SidFilteringEnabled'] is False
    assert row['source_file'] == 't_domains.json'
    assert report.build(g)['trusts'] == rows
    assert cli.main(['trusts', str(tmp_path)]) == 0
    text = capsys.readouterr().out
    assert 'source=TEST.LOCAL' in text and 'TrustDirection="Inbound"' in text
    assert 'SidFilteringEnabled=false' in text and 'SidFilteringEnabled=null' in text
    assert 'TrustDirection=99' in text  # no guessed interpretation of unknown values
    for fmt in ('text', 'md'):
        rendered = report.render(g, fmt=fmt)
        arrow = ' -&gt; ' if fmt == 'md' else ' -> '
        assert f'TEST.LOCAL [{DOM}]{arrow}OTHER.LOCAL [S-1-5-21-40-50-60]' in rendered
        assert f'TEST.LOCAL [{DOM}]{arrow}UNKNOWN.LOCAL' in rendered
        assert 'transitive=false' in rendered and 'SidFilteringEnabled=false' in rendered
        assert 'transitive=null' not in rendered and 'SidFilteringEnabled=null' not in rendered


def test_report_shows_recorded_group_sids_without_trusts(tmp_path):
    _write(tmp_path)
    groups = json.loads((tmp_path / 't_groups.json').read_text())['data']
    enterprise_admins = f'{DOM}-519'
    administrators = 'TEST.LOCAL-S-1-5-32-544'
    groups.extend([
        {'ObjectIdentifier': enterprise_admins,
         'Properties': {'name': 'ENTERPRISE ADMINS@TEST.LOCAL'}, 'Members': []},
        {'ObjectIdentifier': administrators,
         'Properties': {'name': 'ADMINISTRATORS@TEST.LOCAL'},
         'Members': [{'ObjectIdentifier': DA}, {'ObjectIdentifier': enterprise_admins}]},
    ])
    replace_collection(tmp_path, 'groups', groups)

    data = report.build(load(tmp_path))
    assert data['trusts'] == []
    rows = data['admin_group_sids']
    assert {row['group_id'] for row in rows} == {DA, enterprise_admins}
    assert all(row['administrator_memberships'][0]['id'] == administrators for row in rows)
    assert all(row['administrator_memberships'][0]['evidence'][0]['source_file'] == 't_groups.json'
               for row in rows)
    for fmt in ('text', 'md'):
        rendered = report.RENDERERS[fmt](data)
        assert 'Domain and Enterprise Admin group SIDs' in rendered
        assert 'Trust boundaries' not in rendered
        assert f'DOMAIN ADMINS@TEST.LOCAL [{DA}] (RID 512)' in rendered
        assert f'ENTERPRISE ADMINS@TEST.LOCAL [{enterprise_admins}] (RID 519)' in rendered
        assert 'recorded MemberOf ADMINISTRATORS@TEST.LOCAL' in rendered


def test_parent_child_transitivity_is_kept_in_data_but_not_repeated_in_summary(tmp_path):
    _write(tmp_path)
    domains = json.loads((tmp_path / 't_domains.json').read_text())['data']
    domains[0]['Trusts'] = [
        {'TargetDomainSid': 'S-1-5-21-40-50-60', 'TargetDomainName': 'CHILD.TEST.LOCAL',
         'TrustDirection': 'Bidirectional', 'TrustType': 'ParentChild',
         'IsTransitive': True, 'SidFilteringEnabled': False}]
    replace_collection(tmp_path, 'domains', domains)
    data = report.build(load(tmp_path))
    assert data['trusts'][0]['trust']['IsTransitive'] is True
    for fmt in ('text', 'md'):
        rendered = report.RENDERERS[fmt](data)
        assert 'transitive=true' not in rendered
        assert 'SidFilteringEnabled=false' in rendered


def test_empty_trust_and_rbcd_results_remain_scoped(tmp_path, capsys):
    _write(tmp_path)
    assert cli.main(['trusts', str(tmp_path)]) == 0
    assert 'collection scope still applies' in capsys.readouterr().out
    g = load(tmp_path)
    assert queries.delegation(g)['rbcd'] == [] and queries.trusts(g) == []
