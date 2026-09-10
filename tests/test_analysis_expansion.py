"""Synthetic negative and positive cases for conditional offline analysis."""
import json
import zipfile

import pytest

from bhq import cli, report
from bhq.loader import ADCS_TYPES, CollectionError, load
from bhq.analysis import observations, policy, pki, routes, inventory
from .test_bhq import _write, DOM, ALICE, BOB, DAVE, DA, WS01


def read(path, kind):
    return json.loads((path / f't_{kind}.json').read_text())['data']


def write(path, kind, objects):
    (path / f't_{kind}.json').write_text(json.dumps({'data': objects}))


def mutate(path, kind, fn):
    data = read(path, kind)
    fn(data)
    write(path, kind, data)


def member(sid):
    return {'ObjectIdentifier': sid}


def session(user=BOB, computer=WS01, collected=True, failure=None):
    return {'Results': [{'UserSID': user, 'ComputerSID': computer}],
            'Collected': collected, 'FailureReason': failure}


def no_alice_acl(path):
    # Keep only local access from Alice; remove the old direct password-control path.
    mutate(path, 'users', lambda users: users[1].update(Aces=[]))


def test_sessions_retain_methods_partial_results_and_unknown_defaults(tmp_path):
    _write(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(
        Sessions=session(), PrivilegedSessions=session(failure='denied'),
        RegistrySessions={'Collected': True, 'Results': [], 'FailureReason': None}))
    rows = observations.sessions(load(tmp_path))
    assert [r['state'] for r in rows] == ['recorded', 'partial', 'empty-unknown']
    assert rows[1]['failure_reason'] == 'denied'
    assert rows[0]['entries'][0]['user']['id'] == BOB
    assert rows[0]['entries'][0]['evidence']['field'] == 'Sessions.Results[0]'


@pytest.mark.parametrize('node,state', [
    (None, 'missing'), ({'Collected': False, 'Results': []}, 'not-confirmed'),
    (session(collected=False), 'unconfirmed-results'),
    ({'Collected': True, 'Results': [], 'FailureReason': 'denied'}, 'failed'),
])
def test_session_states_do_not_invent_success(tmp_path, node, state):
    _write(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(Sessions=node))
    assert observations.sessions(load(tmp_path))[0]['state'] == state


def test_admin_session_membership_route_retains_proof(tmp_path):
    _write(tmp_path)
    no_alice_acl(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(Sessions=session()))
    result = routes.route(load(tmp_path), ALICE, {DA})
    assert [r['relationship'] for r in result['steps']] == ['AdminTo', 'HasSession', 'MemberOf']
    assert result['steps'][0]['target_state'] == 'host'
    assert all(r['requires'] and r['evidence'] for r in result['steps'])
    assert 'credential material' in ' '.join(result['steps'][1]['requires'])


@pytest.mark.parametrize('node', [session(collected=False), session(failure='partial'),
                                session(computer='OTHER'), session(user='UNKNOWN'),
                                session(user=DA)])
def test_unconfirmed_mismatched_or_unresolved_sessions_do_not_make_routes(tmp_path, node):
    _write(tmp_path)
    no_alice_acl(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(Sessions=node))
    assert routes.route(load(tmp_path), ALICE, {DA})['steps'] is None


def test_remote_login_is_not_host_administration(tmp_path):
    _write(tmp_path)
    no_alice_acl(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(LocalAdmins={'Collected': True, 'Results': []},
        RemoteDesktopUsers={'Collected': True, 'Results': [member(ALICE)]}, Sessions=session()))
    g = load(tmp_path)
    assert routes.route(g, ALICE, {DA})['steps'] is None
    assert routes.route(g, ALICE, {WS01}, 'remote')['steps'][0]['relationship'] == 'CanRDP'


def test_computer_account_control_cannot_jump_to_host_session(tmp_path):
    _write(tmp_path)
    no_alice_acl(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(LocalAdmins={}, Sessions=session(),
        Aces=[{'PrincipalSID': ALICE, 'RightName': 'GenericAll'}]))
    g = load(tmp_path)
    assert routes.route(g, ALICE, {WS01})['steps'][0]['target_state'] == 'principal'
    assert routes.route(g, ALICE, {DA})['steps'] is None


def test_unconfirmed_local_group_cannot_supply_host_state(tmp_path):
    _write(tmp_path)
    no_alice_acl(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(LocalAdmins={'Collected': False, 'Results': [member(ALICE)]}, Sessions=session()))
    assert routes.route(load(tmp_path), ALICE, {DA})['steps'] is None


def test_rbcd_and_constrained_targets_are_conditional_and_resolved(tmp_path):
    _write(tmp_path)
    no_alice_acl(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(LocalAdmins={}, AllowedToAct=[member(DAVE)], Sessions=session()))
    g = load(tmp_path)
    assert routes.route(g, DAVE, {DA})['steps'][0]['relationship'] == 'AllowedToAct'
    mutate(tmp_path, 'users', lambda users: users[0].update(AllowedToDelegate=[member(WS01), member('outside.test')]))
    g = load(tmp_path)
    result = routes.route(g, ALICE, {WS01}, 'host')
    assert result['steps'][0]['relationship'] == 'AllowedToDelegate'
    assert not any(r['target']['id'] == 'outside.test' for r in routes.relationships(g))


def test_sid_history_supplies_grants_not_target_password_or_memberships(tmp_path):
    _write(tmp_path)
    no_alice_acl(tmp_path)
    mutate(tmp_path, 'users', lambda users: users[4].update(HasSIDHistory=[BOB], Properties={'samaccountname': 'dave', 'sidhistory': [ALICE]}))
    g = load(tmp_path)
    assert len(observations.sid_history(g)) == 2
    # BOB's current Domain Admins membership is not in DAVE's historical SID value.
    assert routes.route(g, DAVE, {DA})['steps'] is None
    result = routes.route(g, DAVE, {WS01}, 'host')
    assert [r['relationship'] for r in result['steps']] == ['HasSIDHistory', 'AdminTo']
    assert result['steps'][0]['target_state'] == 'sid'


def test_user_rights_keep_denies_unresolved_names_and_failures(tmp_path):
    _write(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(UserRights=[
        {'Privilege': 'SeDenyRemoteInteractiveLogonRight', 'Results': [member(ALICE)], 'Collected': True, 'LocalNames': ['LOCAL\\unknown']},
        {'Privilege': 'SeBackupPrivilege', 'Results': [], 'Collected': False, 'FailureReason': 'denied'}]))
    rows = observations.user_rights(load(tmp_path))
    assert rows[0]['deny'] is True and rows[0]['local_names'] == ['LOCAL\\unknown']
    assert rows[1]['state'] == 'failed'


def make_policy(path, block=False, enforced=False):
    write(path, 'gpos', [{'ObjectIdentifier': 'GPO', 'Properties': {'name': 'POLICY'}, 'Aces': [{'PrincipalSID': ALICE, 'RightName': 'GenericWrite'}]}])
    write(path, 'ous', [
        {'ObjectIdentifier': 'OU-A', 'Properties': {'name': 'A', 'blocksinheritance': False}, 'Links': [{'GUID': 'GPO', 'IsEnforced': enforced}], 'ChildObjects': [member('OU-B')]},
        {'ObjectIdentifier': 'OU-B', 'Properties': {'name': 'B', 'blocksinheritance': block}, 'ChildObjects': [member(WS01)]},
    ])
    mutate(path, 'computers', lambda c: c[0].update(LocalAdmins={}, Sessions=session()))


@pytest.mark.parametrize('block,enforced,status', [(False, False, 'candidate'), (True, False, 'blocked'),
                                                  (True, True, 'candidate'), (None, False, 'unknown-inheritance')])
def test_policy_inheritance_and_enforcement(tmp_path, block, enforced, status):
    _write(tmp_path)
    no_alice_acl(tmp_path)
    make_policy(tmp_path, block, enforced)
    g = load(tmp_path)
    pol = policy.policy(g)
    assert pol['effects'][0]['inheritance'] == status
    assert len(pol['effects'][0]['evidence']) == 3
    result = routes.route(g, ALICE, {DA})
    assert (result['steps'] is not None) == (status == 'candidate')
    if status == 'candidate':
        assert [r['relationship'] for r in result['steps']] == ['GenericWrite', 'GPOAppliesCandidate', 'HasSession', 'MemberOf']


def test_policy_conflicting_parents_and_cycles_are_visible(tmp_path):
    _write(tmp_path)
    make_policy(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(ContainedBy=member('OU-A')))
    pol = policy.policy(load(tmp_path))
    assert not pol['effects'] and pol['issues'][0]['reason'] == 'conflicting-parents'
    mutate(tmp_path, 'computers', lambda c: c[0].pop('ContainedBy'))
    mutate(tmp_path, 'ous', lambda ous: ous[1]['ChildObjects'].append(member('OU-A')))
    assert any(i['reason'] == 'containment-cycle' for i in policy.policy(load(tmp_path))['issues'])


def test_gpo_changes_projection_does_not_become_direct_observation(tmp_path):
    _write(tmp_path)
    mutate(tmp_path, 'domains', lambda d: d[0].update(GPOChanges={'LocalAdmins': [member(DAVE)], 'AffectedComputers': [member(WS01)]}))
    g = load(tmp_path)
    assert DAVE not in g.admin_edges
    assert routes.route(g, DAVE, {WS01}, 'host')['steps'][0]['relationship'] == 'GPOChanges:AdminTo'


def make_pki(path):
    write(path, 'certtemplates', [{'ObjectIdentifier': 'TEMPLATE', 'Properties': {
        'name': 'LOGIN@TEST.LOCAL', 'authenticationenabled': True, 'enrolleesuppliessubject': True,
        'requiresmanagerapproval': False, 'authorizedsignatures': 0, 'effectiveekus': ['1.3.6.1.5.5.7.3.2']},
        'Aces': [{'PrincipalSID': DA, 'RightName': 'Enroll'}]}])
    write(path, 'enterprisecas', [{'ObjectIdentifier': 'CA', 'Properties': {'name': 'CA@TEST.LOCAL', 'certthumbprint': 'ABC'},
        'EnabledCertTemplates': [member('TEMPLATE'), member('UNKNOWN-TEMPLATE')], 'HostingComputer': WS01,
        'CARegistryData': {'CASecurity': {'Collected': True, 'FailureReason': None,
            'Data': [{'PrincipalSID': BOB, 'RightName': 'Enroll'}]}}}])
    write(path, 'ntauthstores', [{'ObjectIdentifier': 'NTAUTH', 'Properties': {'certthumbprints': ['abc']}}])


def test_adcs_loads_all_six_types_and_supports_adcs_only_zip(tmp_path):
    for kind in ADCS_TYPES:
        write(tmp_path, kind, [{'ObjectIdentifier': kind.upper(), 'Properties': {'name': kind}}])
    archive = tmp_path / 'pki.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        for path in tmp_path.glob('*.json'):
            z.write(path, path.name)
    g = load(archive)
    assert len(g.objects) == 6 and not g.unhandled_files
    assert {g.kind(s) for s in g.by_sid} == set(ADCS_TYPES.values())


def test_adcs_combines_only_selected_subject_grants_and_retains_provenance(tmp_path):
    _write(tmp_path)
    make_pki(tmp_path)
    data = pki.adcs(load(tmp_path), BOB)
    template = data['templates'][0]
    assert template['esc1_template_state'] == 'matched'
    assert template['enrollment'][0]['template_grant_found'] is True
    assert template['enrollment'][0]['ca_grant_found'] is True
    assert template['grants'][0]['membership_path'] == [BOB, DA]
    assert data['cas'][0]['ntauth_thumbprint_matches'][0]['id'] == 'NTAUTH'
    assert data['publications'][1]['resolved'] is False
    anonymous = pki.adcs(load(tmp_path))
    assert anonymous['templates'][0]['enrollment'][0]['ca_grant_found'] is None


@pytest.mark.parametrize('field,value,state', [('requiresmanagerapproval', True, 'not-matched'),
    ('authorizedsignatures', 1, 'not-matched'), ('authorizedsignatures', False, 'unknown'),
    ('authenticationenabled', None, 'unknown'), ('enrolleesuppliessubject', False, 'not-matched')])
def test_adcs_template_conditions_are_three_state(tmp_path, field, value, state):
    _write(tmp_path)
    make_pki(tmp_path)
    mutate(tmp_path, 'certtemplates', lambda t: t[0]['Properties'].update({field: value}))
    assert pki.adcs(load(tmp_path))['templates'][0]['esc1_template_state'] == state


def test_adcs_different_principals_and_partial_ca_security_do_not_combine(tmp_path):
    _write(tmp_path)
    make_pki(tmp_path)
    mutate(tmp_path, 'enterprisecas', lambda cas: cas[0]['CARegistryData']['CASecurity']['Data'][0].update(PrincipalSID=DAVE))
    row = pki.adcs(load(tmp_path), BOB)['templates'][0]['enrollment'][0]
    assert row['template_grant_found'] is True and row['ca_grant_found'] is False
    mutate(tmp_path, 'enterprisecas', lambda cas: cas[0]['CARegistryData']['CASecurity'].update(FailureReason='denied'))
    assert pki.adcs(load(tmp_path), DAVE)['templates'][0]['enrollment'][0]['ca_grant_found'] is False


def test_unpublished_adcs_template_and_autoenroll_are_not_current_enrollment(tmp_path):
    _write(tmp_path)
    make_pki(tmp_path)
    mutate(tmp_path, 'certtemplates', lambda t: t[0]['Aces'][0].update(RightName='AutoEnroll'))
    row = pki.adcs(load(tmp_path), BOB)['templates'][0]
    assert row['enrollment'][0]['template_grant_found'] is False
    mutate(tmp_path, 'enterprisecas', lambda c: c[0].update(EnabledCertTemplates=[]))
    row = pki.adcs(load(tmp_path), BOB)['templates'][0]
    assert row['publication_count'] == 0 and row['enrollment'] == []


def test_all_fields_are_inventory_visible_without_claiming_all_are_analyzed(tmp_path):
    _write(tmp_path)
    mutate(tmp_path, 'users', lambda u: u[0].update(NewFeature={'Nested': [{'Secret': 'keep in raw'}]}))
    g = load(tmp_path)
    rows = inventory.inventory(g)['fields']
    row = next(r for r in rows if r['field'] == 'NewFeature.Nested[].Secret')
    assert row['status'] == 'raw-only' and row['examples'][0]['object_id'] == ALICE
    assert g.by_sid[ALICE]['NewFeature']['Nested'][0]['Secret'] == 'keep in raw'


@pytest.mark.parametrize('command', ['access', 'sessions', 'sid-history', 'user-rights', 'policy', 'adcs', 'coverage'])
def test_new_cli_commands_json_and_text(tmp_path, capsys, command):
    _write(tmp_path)
    make_pki(tmp_path)
    assert cli.main([command, str(tmp_path), '--format', 'json']) == 0
    assert json.loads(capsys.readouterr().out) is not None
    assert cli.main([command, str(tmp_path)]) == 0
    assert 'Recorded input' in capsys.readouterr().out


def test_route_cli_and_report_keep_old_path_separate(tmp_path, capsys):
    _write(tmp_path)
    no_alice_acl(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(Sessions=session()))
    assert cli.main(['route', str(tmp_path), 'alice', '--goal', 'da', '--format', 'json']) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'candidate'
    data = report.build(load(tmp_path), 'alice', 'da')
    assert data['path']['path'] is None and data['candidate_route']['steps']
    assert data['extended']['sessions']
    for render in (report.as_text, report.as_md):
        output = render(data)
        assert 'Conditional route' in output and 'HasSession' in output


def test_deleted_objects_do_not_form_conditional_routes(tmp_path):
    _write(tmp_path)
    mutate(tmp_path, 'users', lambda u: u[1].update(IsDeleted=True))
    assert routes.route(load(tmp_path), ALICE, {DA})['steps'] is None


@pytest.mark.parametrize('field,value', [('Sessions', []), ('UserRights', ['bad']),
    ('AllowedToAct', [{'ObjectIdentifier': []}]), ('GPOChanges', {'AffectedComputers': 'bad'}),
    ('CARegistryData', {'CASecurity': {'Data': 'bad'}})])
def test_malformed_analyzed_fields_report_source_instead_of_crashing(tmp_path, field, value):
    _write(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update({field: value}))
    with pytest.raises(CollectionError, match='t_computers.json'):
        load(tmp_path)


def test_adcs_template_control_is_not_ca_service_enrollment(tmp_path):
    _write(tmp_path)
    make_pki(tmp_path)
    mutate(tmp_path, 'enterprisecas', lambda ca: ca[0].update(CARegistryData={}, Aces=[{'PrincipalSID': BOB, 'RightName': 'GenericAll'}]))
    mutate(tmp_path, 'certtemplates', lambda t: t[0].update(Aces=[{'PrincipalSID': BOB, 'RightName': 'GenericAll'}]))
    row = pki.adcs(load(tmp_path), BOB)['templates'][0]
    assert row['enrollment'][0]['template_grant_found'] is True
    assert row['enrollment'][0]['ca_grant_found'] is False
    assert any('ESC4' in clue for clue in row['clues'])


def test_adcs_read_only_right_is_not_template_control(tmp_path):
    _write(tmp_path)
    make_pki(tmp_path)
    mutate(tmp_path, 'certtemplates', lambda t: t[0].update(Aces=[{'PrincipalSID': BOB, 'RightName': 'ReadLAPSPassword'}]))
    assert not any('ESC4' in c for c in pki.adcs(load(tmp_path), BOB)['templates'][0]['clues'])


def test_issuance_policies_and_certificate_chain_references_are_joined(tmp_path):
    _write(tmp_path)
    make_pki(tmp_path)
    write(tmp_path, 'issuancepolicies', [{'ObjectIdentifier': 'POLICY-OID', 'Properties': {'oid': '1.2.3.4'}, 'GroupLink': member(DA)}])
    write(tmp_path, 'rootcas', [{'ObjectIdentifier': 'ROOT', 'Properties': {'certthumbprint': 'DEF'}}])
    mutate(tmp_path, 'certtemplates', lambda t: t[0]['Properties'].update(issuancepolicies=['1.2.3.4']))
    mutate(tmp_path, 'enterprisecas', lambda ca: ca[0]['Properties'].update(certchain=['def', 'UNKNOWN']))
    data = pki.adcs(load(tmp_path), BOB)
    assert data['templates'][0]['issuance_policy_links'][0]['group']['id'] == DA
    assert data['cas'][0]['chain_matches'][0]['objects'][0]['id'] == 'ROOT'
    assert data['cas'][0]['chain_matches'][1]['objects'] == []


def test_new_nested_fields_are_not_hidden_by_a_known_family(tmp_path):
    _write(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(Sessions={**session(), 'FutureStatus': 'unknown'}))
    rows = inventory.inventory(load(tmp_path))['fields']
    assert next(r for r in rows if r['field'] == 'Sessions.FutureStatus')['status'] == 'raw-only'
    assert next(r for r in rows if r['field'] == 'Sessions.Results[].UserSID')['status'] == 'query-outlet'


def test_null_result_array_remains_invalid_not_empty_success(tmp_path):
    _write(tmp_path)
    mutate(tmp_path, 'computers', lambda c: c[0].update(Sessions={'Collected': True, 'Results': None},
        LocalAdmins={'Collected': True, 'Results': None}))
    g = load(tmp_path)
    assert observations.sessions(g)[0]['state'] == 'invalid'
    assert observations.local_access(g)[0]['state'] == 'invalid'
    assert not any(e['relationship'] == 'AdminTo' for e in routes.relationships(g))


def test_unknown_right_name_is_visible_even_when_ace_shape_is_known(tmp_path):
    _write(tmp_path)
    mutate(tmp_path, 'users', lambda u: u[1]['Aces'].append({'PrincipalSID': ALICE, 'RightName': 'FutureRight'}))
    data = inventory.inventory(load(tmp_path))
    assert data['unmodeled_ace_rights'][0]['right'] == 'FutureRight'
    assert data['unmodeled_ace_rights'][0]['evidence']['object_id'] == BOB
