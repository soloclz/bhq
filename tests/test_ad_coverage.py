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
