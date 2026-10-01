"""One-shot inventory of recorded BloodHound material and derived relationships.

`build()` produces a structured dict; `as_text` / `as_md` / `as_json` render it.
Markdown/JSON are for dropping into `evidence/` and the engagement report; text
is the terminal default.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict, deque

from . import queries
from .loader import CONTROL_RIGHTS, DCSYNC_RIGHTS, Graph
from .analysis import observations, policy, pki, routes, inventory, presentation
from .analysis.common import evidence, ref


def _edge_evidence(g: Graph) -> dict[tuple[str, str, str], list[dict]]:
    sources: dict[tuple[str, str, str], list[dict]] = {}

    def add(source: str, relationship: str, target: str, owner: str, field: str) -> None:
        sources.setdefault((source, relationship, target), []).append(evidence(g, owner, field))

    for obj in g.objects:
        owner = obj['ObjectIdentifier']
        for i, ace in enumerate(obj.get('Aces') or []):
            principal, right = ace.get('PrincipalSID'), ace.get('RightName')
            if principal and right in CONTROL_RIGHTS:
                add(principal, right, owner, owner, f'Aces[{i}]')
        if g.kind(owner) == 'group':
            for i, member in enumerate(obj.get('Members') or []):
                principal = member.get('ObjectIdentifier')
                if principal:
                    add(principal, 'MemberOf', owner, owner, f'Members[{i}]')
        if g.kind(owner) in ('user', 'computer') and obj.get('PrimaryGroupSID'):
            add(owner, 'MemberOf', obj['PrimaryGroupSID'], owner, 'PrimaryGroupSID')
    return sources


def _all_recorded_edges(g: Graph) -> list[dict]:
    """Inventory every indexed ACL/membership relationship, including unresolved sources."""
    provenance = _edge_evidence(g)
    rows = []
    for source, outgoing in g.control_edges.items():
        for target, relationship in outgoing:
            rows.append((source, relationship, target))
    for source, groups in g.member_edges.items():
        rows.extend((source, 'MemberOf', target) for target in groups)
    return [{'from_id': source, 'from': g.name(source), 'from_kind': g.kind(source),
             'to_id': target, 'to': g.name(target), 'to_kind': g.kind(target),
             'from_resolved': source in g.by_sid, 'to_resolved': target in g.by_sid,
             'from_deleted': (g.by_sid.get(source) or {}).get('IsDeleted') is True,
             'to_deleted': (g.by_sid.get(target) or {}).get('IsDeleted') is True,
             'edge': relationship,
             'evidence': provenance.get((source, relationship, target), [])}
            for source, relationship, target in sorted(set(rows))]


def _replication_aces(g: Graph) -> list[dict]:
    rows = []
    for domain in g.domains:
        sid = domain['ObjectIdentifier']
        for i, ace in enumerate(domain.get('Aces') or []):
            if ace.get('RightName') in DCSYNC_RIGHTS and ace.get('PrincipalSID'):
                principal = ace['PrincipalSID']
                rows.append({'domain': ref(g, sid), 'principal': ref(g, principal),
                             'right': ace['RightName'], 'evidence': evidence(g, sid, f'Aces[{i}]'),
                             'principal_live': g.is_live(principal), 'domain_live': g.is_live(sid)})
    return rows


def _account_settings(g: Graph) -> list[dict]:
    """Preserve relevant recorded account settings with field-level provenance."""
    fields = ('admincount', 'enabled', 'passwordnotreqd', 'dontreqpreauth',
              'hasspn', 'serviceprincipalnames', 'pwdlastset', 'lastlogon',
              'unconstraineddelegation', 'allowedtodelegate', 'trustedtoauth', 'haslaps')
    rows = []
    for obj in g.users + g.computers:
        sid = obj['ObjectIdentifier']
        props = obj.get('Properties') or {}
        values = [{'field': field, 'value': props[field],
                   'evidence': evidence(g, sid, f'Properties.{field}')}
                  for field in fields if field in props and props[field] is not None
                  and props[field] != '' and props[field] != []]
        if values:
            rows.append({'account': ref(g, sid), 'settings': values})
    return rows


def _account_findings(g: Graph) -> list[dict]:
    """Group non-routine user settings into review leads with exact sources."""
    rows = []
    for obj in g.users:
        sid = obj['ObjectIdentifier']
        if not g.is_live(sid):
            continue
        props = obj.get('Properties') or {}
        if props.get('enabled') is False:
            continue
        signals = []

        def add(field: str, explanation: str) -> None:
            signals.append({'field': field, 'value': props.get(field),
                            'explanation': explanation,
                            'evidence': evidence(g, sid, f'Properties.{field}')})

        if props.get('hasspn') and (props.get('samaccountname') or '').lower() != 'krbtgt':
            add('serviceprincipalnames' if props.get('serviceprincipalnames') else 'hasspn',
                'SPN account: review the long-term key and service use')
        if props.get('dontreqpreauth') is True:
            add('dontreqpreauth', 'pre-authentication disabled: review the account password')
        if signals:
            rows.append({'account': ref(g, sid), 'enabled': props.get('enabled'),
                         'admincount': props.get('admincount'), 'signals': signals})
    return rows


def _sid_history_carriers(g: Graph) -> dict[str, list[dict]]:
    carriers = defaultdict(list)
    for row in observations.sid_history(g):
        historical = row['historical']['id']
        principal = row['principal']['id']
        if historical and g.is_live(principal):
            carriers[historical].append({'principal': row['principal'], 'evidence': row['evidence']})
    return carriers


def _deleted_domain_grants(g: Graph) -> list[dict]:
    """Significant direct domain ACEs addressed to a deleted principal SID."""
    carriers = _sid_history_carriers(g)
    rows = []
    for domain in g.domains:
        domain_sid = domain['ObjectIdentifier']
        if not g.is_live(domain_sid):
            continue
        by_principal = defaultdict(list)
        for index, ace in enumerate(domain.get('Aces') or []):
            sid, right = ace.get('PrincipalSID'), ace.get('RightName')
            if (sid in g.by_sid and g.kind(sid) in {'user', 'group', 'computer'}
                    and g.by_sid[sid].get('IsDeleted') is True
                    and right in DCSYNC_RIGHTS | queries.DOMAIN_CONTROL_RIGHTS):
                by_principal[sid].append({'right': right,
                                          'evidence': evidence(g, domain_sid, f'Aces[{index}]')})
        for sid, grants in by_principal.items():
            rights = {grant['right'] for grant in grants}
            dcsync = 'DCSync' in rights or {'GetChanges', 'GetChangesAll'} <= rights
            controls_domain = bool(rights & queries.DOMAIN_CONTROL_RIGHTS)
            if dcsync or controls_domain:
                rows.append({'deleted': ref(g, sid), 'domain': ref(g, domain_sid),
                             'grants': grants, 'dcsync_combination': dcsync,
                             'domain_control': controls_domain,
                             'sid_history_carriers': carriers[sid]})
    return sorted(rows, key=lambda row: (row['deleted']['name'], row['domain']['name']))


def _deleted_principal_paths(g: Graph, goals: dict[str, str]) -> list[dict]:
    """Find deleted grant holders that could reach a live goal if their SID is usable.

    Reverse traversal crosses only live objects. The deleted principal is a
    single starting SID; deleted objects never become intermediate identities.
    """
    next_edge = {sid: None for sid in goals if g.is_live(sid)}
    distance = {sid: 0 for sid in next_edge}
    queue = deque(sorted(next_edge))
    while queue:
        target = queue.popleft()
        inbound = list(g.control_edges_rev.get(target, []))
        inbound += [(sid, 'MemberOf') for sid in g.member_edges_rev.get(target, [])]
        for source, relationship in inbound:
            if g.is_live(source) and source not in next_edge:
                next_edge[source] = (target, relationship)
                distance[source] = distance[target] + 1
                queue.append(source)

    provenance = _edge_evidence(g)
    carriers = _sid_history_carriers(g)

    findings = []
    for sid, obj in g.by_sid.items():
        if obj.get('IsDeleted') is not True or g.kind(sid) not in {'user', 'group', 'computer'}:
            continue
        outgoing = list(g.control_edges.get(sid, []))
        outgoing += [(target, 'MemberOf') for target in g.member_edges.get(sid, [])]
        # An ACE addressed to the historical SID may apply through SID history.
        # A deleted account's old MemberOf edge is not inherited that way.
        candidates = [(relationship == 'MemberOf', distance[target] + 1, target, relationship)
                      for target, relationship in outgoing if target in distance]
        if not candidates:
            continue
        old_membership, _, target, relationship = min(candidates)
        steps = []
        source = sid
        while True:
            steps.append({'source': ref(g, source), 'target': ref(g, target),
                          'relationship': relationship,
                          'evidence': provenance.get((source, relationship, target), [])})
            source = target
            continuation = next_edge[target]
            if continuation is None:
                break
            target, relationship = continuation
        reached_goal = source
        incoming = []
        for inbound_source, right in g.control_edges_rev.get(sid, []):
            if g.is_live(inbound_source):
                incoming.append({'source': ref(g, inbound_source), 'relationship': right,
                                 'evidence': provenance.get((inbound_source, right, sid), [])})
        findings.append({'deleted': ref(g, sid), 'target': ref(g, reached_goal),
                         'target_reason': goals[reached_goal], 'steps': steps,
                         'first_step_kind': 'historical-membership' if old_membership else 'ace',
                         'sid_history_carriers': carriers[sid] if not old_membership else [],
                         'incoming_control': incoming})
    return sorted(findings, key=lambda row: (len(row['steps']), row['deleted']['name'], row['deleted']['id']))


def build(g: Graph) -> dict:
    targets = queries.goal_sids(g, 'high-value')
    da_targets = queries.goal_sids(g, 'da')
    data: dict = {
        "collection": queries.coverage(g),
        "analysis": {
            "scope": queries.ANALYSIS_SCOPE,
            "warnings": queries.diagnostics(g),
        },
        "property_clues": queries.property_clues(g),
        "kerberoastable": queries.kerberoastable(g),
        "asreproastable": [a["name"] for a in queries.asreproastable(g)],
        "delegation": queries.delegation(g),
        "trusts": queries.trusts(g),
        "dcsync": queries.dcsync_principals(g),
        "dcsync_findings": queries.dcsync_findings(g),
        "high_value_groups": [
            {"group": grp, "members": members, "why": why}
            for grp, members, why in queries.high_value_members(g)
        ],
        "account_settings": _account_settings(g),
        "account_findings": _account_findings(g),
        "replication_aces": _replication_aces(g),
        "recorded_edges": _all_recorded_edges(g),
        "targets": [{'id': sid, 'name': g.name(sid), 'kind': g.kind(sid),
                     'reason': reason, 'domain_admins': sid in da_targets}
                    for sid, reason in sorted(targets.items())],
        "reachers": [
            {"name": g.name(sid), "hops": hops,
             "path": [{"name": n, "via": via} for n, via in chain]}
            for sid, (hops, chain) in sorted(
                queries.who_can_reach_high_value(g, 'high-value').items(), key=lambda kv: (kv[1][0], g.name(kv[0])))
        ],
        "da_reachers": [
            {"name": g.name(sid), "hops": hops,
             "path": [{"name": n, "via": via} for n, via in chain]}
            for sid, (hops, chain) in sorted(
                queries.who_can_reach_high_value(g, 'da').items(), key=lambda kv: (kv[1][0], g.name(kv[0])))
        ],
        "conditional_reachers": routes.global_goal_routes(g, targets),
        "conditional_da_reachers": routes.global_goal_routes(g, da_targets),
        "deleted_reachers": _deleted_principal_paths(g, targets),
        "deleted_da_reachers": _deleted_principal_paths(g, da_targets),
        "deleted_domain_grants": _deleted_domain_grants(g),
        "extended": {
            "access": observations.local_access(g), "sessions": observations.sessions(g), "sid-history": observations.sid_history(g),
            "user-rights": observations.user_rights(g), "policy": policy.policy(g),
            "adcs": pki.adcs(g), "coverage": inventory.inventory(g),
        },
    }
    data['raw_observations'] = inventory.populated_raw(g, data['extended']['coverage'])
    return data


def _proof(value) -> str:
    if not value:
        return ''
    if isinstance(value, list):
        return ', '.join(_proof(item) for item in value)
    return f"{value.get('source_file')}:{value.get('object_id')}:{value.get('field')}"


def _material_sections(data: dict) -> list[tuple[str, list[str]]]:
    """Keep interpreted observations in the readable report; JSON retains records."""
    ext = data['extended']
    sections = []
    for command, title in [('access', 'Recorded local access'),
                           ('sessions', 'Recorded sessions'),
                           ('sid-history', 'Recorded SID history'),
                           ('user-rights', 'Recorded user rights')]:
        rows = ext[command]
        if command == 'sessions':
            rows = [row for row in rows if row['state'] != 'missing']
        if rows:
            entries = presentation.lines(command, rows)[1:]
            if command == 'sessions':
                entries.insert(0, 'A recorded session does not establish a current session or available credential material.')
            sections.append((title, entries))

    pol = ext['policy']
    if any(pol[key] for key in ('links', 'effects', 'changes', 'issues')):
        sections.append(('GPO scope and projected changes', presentation.lines('policy', pol)[1:]))

    adcs = ext['adcs']
    if any(adcs[key] for key in ('objects', 'cas', 'templates', 'publications', 'issuance_policies')):
        sections.append(('AD CS conditions', presentation.lines('adcs', adcs, True)[1:]))

    coverage = ext['coverage']
    if coverage['unmodeled_ace_rights']:
        sections.append(('ACE rights without a model', [
            f"{row['right']} principal={row['principal_id']} [source: {_proof(row['evidence'])}]"
            for row in coverage['unmodeled_ace_rights']
        ]))
    if coverage['unhandled_files']:
        sections.append(('JSON files outside the loader', coverage['unhandled_files']))
    return sections


def property_clue(row: dict) -> str:
    return (f"{row['kind']} {row['name']} [{row['id']}] "
            f"{json.dumps(row['properties'], ensure_ascii=False)} (source: {row['source_file']})")


def rbcd_finding(row: dict) -> str:
    principals = ", ".join(
        f"{p['name']} [{p['id']}]" + ("" if p["resolved"] else " [not in collection]")
        for p in row["principals"])
    return f"AllowedToAct on {row['target']} [{row['target_id']}]: {principals}"


def trust_finding(row: dict) -> str:
    trust = row["trust"]
    fields = ("TargetDomainName", "TargetDomainSid", "TrustDirection", "TrustType",
              "IsTransitive", "SidFilteringEnabled", "TrustAttributes")
    return (f"source={row['source']} [{row['source_id']}]; " + "; ".join(
        f"{field}={json.dumps(trust.get(field), ensure_ascii=False)}" for field in fields)
        + f" [source: {row['source_file']}]")


def dcsync_finding(row: dict) -> str:
    grants = "; ".join(f"{grant['granted_to']}:{grant['right']}" for grant in row["grants"])
    return f"{row['principal']} -> {row['domain']}; grants: {grants}"


def delegation_targets(row: dict) -> str:
    parts = []
    if row["to"]:
        parts.append("SPNs: " + ", ".join(row["to"]))
    if row.get("targets"):
        parts.append("target objects: " + ", ".join(
            f"{t['name']} [{t['id']}]" if t["resolved"] else f"{t['id']} [not in collection]"
            for t in row["targets"]))
    return "; ".join(parts)


def _reviewable_control_lines(data: dict) -> list[str]:
    """Show control from outside the target set across a notable object boundary."""
    targets = {row['id']: row['reason'] for row in data['targets']}
    grouped = defaultdict(list)
    for edge in data['recorded_edges']:
        if (edge['edge'] == 'MemberOf' or edge['from_id'] in targets
                or not edge['from_resolved'] or not edge['to_resolved']
                or edge['from_deleted'] or edge['to_deleted']):
            continue
        if (edge['to_id'] in targets or edge['to_kind'] in {'domain', 'gpo', 'ou', 'certtemplate', 'enterpriseca'}
                or edge['edge'] in {'ForceChangePassword', 'AddMember', 'AddSelf', 'AddKeyCredentialLink', 'ReadGMSAPassword'}):
            grouped[(edge['from_id'], edge['to_id'])].append(edge)
    lines = []
    for edges in grouped.values():
        first = edges[0]
        reason = targets.get(first['to_id']) or first['to_kind']
        rights = ', '.join(f"{edge['edge']} [source: {_proof(edge['evidence'])}]" for edge in edges)
        lines.append(f"{first['from']} [{first['from_id']}] -> {first['to']} [{first['to_id']}] "
                     f"({reason}): {rights}")
    return lines


_CREDENTIAL_TERM = re.compile(r'\b(?:password|passwd|pwd|passphrase|credential|secret|token|api[_ -]?key)\b', re.I)
_EXPLICIT_SECRET_FIELDS = {'userpassword', 'unixpassword', 'unicodepassword', 'sfupassword'}


def _credential_text_lines(data: dict) -> list[str]:
    lines = []
    for row in data['property_clues']:
        if row['kind'] not in {'user', 'computer', 'group'}:
            continue
        for field, value in row['properties'].items():
            if field not in _EXPLICIT_SECRET_FIELDS and not (
                    field in {'description', 'info'} and _CREDENTIAL_TERM.search(str(value))):
                continue
            excerpt = str(value).replace('\n', ' ').replace('\r', ' ')[:160]
            lines.append(f"{row['kind']} {row['name']} [{row['id']}]: {field}="
                         f"{json.dumps(excerpt, ensure_ascii=False)} [source: {row['source_file']}]"
                         + (' [truncated; inspect object]' if len(str(value)) > 160 else ''))
    return lines


def _unresolved_control_lines(data: dict) -> list[str]:
    """Historical or unknown ACE principals on notable live targets."""
    targets = {row['id'] for row in data['targets']}
    explained_deleted = {row['deleted']['id'] for key in (
        'deleted_reachers', 'deleted_da_reachers', 'deleted_domain_grants')
        for row in data[key]}
    lines = []
    for edge in data['recorded_edges']:
        if edge['edge'] == 'MemberOf' or edge['to_deleted'] or not edge['to_resolved']:
            continue
        if edge['from_resolved'] and not edge['from_deleted']:
            continue
        if edge['from_deleted'] and edge['from_id'] in explained_deleted:
            continue
        if (edge['to_id'] not in targets
                and edge['to_kind'] not in {'domain', 'gpo', 'ou', 'certtemplate', 'enterpriseca'}
                and edge['edge'] not in {'ForceChangePassword', 'AddMember', 'AddSelf',
                                        'AddKeyCredentialLink', 'ReadGMSAPassword'}):
            continue
        state = 'deleted object' if edge['from_deleted'] else 'unresolved principal'
        lines.append(f"{edge['from']} [{edge['from_id']}] ({state}) --{edge['edge']}--> "
                     f"{edge['to']} [{edge['to_id']}] [source: {_proof(edge['evidence'])}]")
    return lines


def _conditional_route_lines(data: dict) -> list[str]:
    lines = []
    seen = set()
    for row in data['conditional_reachers'] + data['conditional_da_reachers']:
        if all(step['relationship'] in CONTROL_RIGHTS | {'MemberOf'}
               and step['source_state'] == step['target_state'] == 'principal'
               for step in row['steps']):
            continue
        key = (row['start']['id'], row['target']['id'],
               tuple((step['relationship'], step['target']['id']) for step in row['steps']))
        if key in seen:
            continue
        seen.add(key)
        path = ' '.join(f"--{step['relationship']}--> {step['target']['name']}"
                        for step in row['steps'])
        lines.append(f"{row['start']['name']} [{row['start']['id']}] {path} "
                     f"[target: {row['target']['id']}; verify each transition in JSON]")
    return lines


def _deleted_route_lines(data: dict) -> list[str]:
    lines, seen = [], set()
    for row in data['deleted_reachers'] + data['deleted_da_reachers']:
        key = (row['deleted']['id'], row['target']['id'])
        if key in seen:
            continue
        seen.add(key)
        path = ' '.join(f"--{step['relationship']}--> {step['target']['name']}"
                        for step in row['steps'])
        carriers = ', '.join(item['principal']['name'] for item in row['sid_history_carriers'])
        inbound = ', '.join(item['source']['name'] + ' --' + item['relationship'] + '-->'
                            for item in row['incoming_control'])
        context = (f"; SID history on: {carriers}" if carriers else '')
        context += (f"; recorded inbound control: {inbound}" if inbound else '')
        lines.append(f"{row['deleted']['name']} [{row['deleted']['id']}] (deleted) {path} "
                     f"[{row['target_reason']}; {len(row['steps'])} edges; {row['first_step_kind']}]"
                     f"{context}; "
                     'edge sources in JSON')
    return lines


def _deleted_domain_grant_lines(data: dict) -> list[str]:
    lines = []
    for row in data['deleted_domain_grants']:
        grants = ', '.join(grant['right'] for grant in row['grants'])
        carriers = ', '.join(item['principal']['name'] for item in row['sid_history_carriers'])
        reason = ', '.join(label for flag, label in (
            (row['dcsync_combination'], 'replication grant combination'),
            (row['domain_control'], 'domain object control')) if flag)
        lines.append(f"{row['deleted']['name']} [{row['deleted']['id']}] (deleted) -> "
                     f"{row['domain']['name']} [{row['domain']['id']}]: {reason}; "
                     f"recorded ACEs: {grants}"
                     + (f"; SID history on: {carriers}" if carriers else '')
                     + '; ACE sources in JSON')
    return lines


def _report_sections(data: dict) -> list[tuple[str, list[str]]]:
    sections = []
    warnings = [item for item in data['analysis']['warnings']
                if 'field paths have no dedicated query outlet' not in item]
    if warnings:
        sections.append(('Input notes', warnings))

    credential_text = _credential_text_lines(data)
    if credential_text:
        sections.append(('Potential credential text', [
            'Recorded text matched credential terms or populated password fields; confirm the value and context.',
            *credential_text,
        ]))
    if data['account_findings']:
        sections.append(('Kerberos account leads', [
            f"{row['account']['name']} [{row['account']['id']}] "
            f"(enabled={row['enabled']}, admincount={row['admincount']}): "
            + '; '.join(f"{signal['explanation']}"
                        f" ({signal['field']}={json.dumps(signal['value'], ensure_ascii=False)})"
                        f" [source: {_proof(signal['evidence'])}]"
                        for signal in row['signals'])
            for row in data['account_findings']
        ]))

    delegation = data['delegation']
    delegation_lines = [f"Unconstrained delegation: {name}" for name in delegation['unconstrained']]
    delegation_lines += [f"Constrained delegation: {row['name']} -> {delegation_targets(row)}"
                         for row in delegation['constrained']]
    delegation_lines += [rbcd_finding(row) + f" [source: {row['source_file']}]"
                         for row in delegation['rbcd']]
    if delegation_lines:
        sections.append(('Delegation settings for review', [
            'A recorded delegation setting identifies a boundary to verify; it does not establish a usable route.',
            *delegation_lines,
        ]))
    if data['trusts']:
        sections.append(('Trust boundaries for review', [
            'Recorded trust direction and filtering need resource-specific access checks.',
            *[trust_finding(row) for row in data['trusts']],
        ]))
    if data['dcsync_findings']:
        sections.append(('DCSync grant combinations', [
            'Grants are combined within each domain through recorded membership; verify effective access and deny ACEs.',
            *[dcsync_finding(row) for row in data['dcsync_findings']],
        ]))
    active_replication = [row for row in data['replication_aces']
                          if row['principal_live'] and row['domain_live']]
    if active_replication:
        sections.append(('Recorded replication ACEs', [
            f"{row['principal']['name']} [{row['principal']['id']}] --{row['right']}--> "
            f"{row['domain']['name']} [{row['domain']['id']}] "
            f"[source: {_proof(row['evidence'])}]"
            for row in active_replication
        ]))
    if data['high_value_groups']:
        empty_groups = [row for row in data['high_value_groups'] if not row['members']]
        if empty_groups:
            sections.append(('High-value groups without recorded members', [
                f"{row['group']} ({row['why']}): review who can change its membership; "
                'an empty Members list is limited by collection scope.'
                for row in empty_groups
            ]))
    control_lines = _reviewable_control_lines(data)
    if control_lines:
        sections.append(('Object control for review', [
            'Recorded ACL edges from outside the investigation-target set; confirm effective rights and the operation on each object type.',
            *control_lines,
        ]))
    historical_lines = _unresolved_control_lines(data)
    if historical_lines:
        sections.append(('Historical or unresolved ACL principals', [
            'These ACEs do not establish an active principal; check the SID and collection scope.',
            *historical_lines,
        ]))
    deleted_routes = _deleted_route_lines(data)
    if deleted_routes:
        sections.append(('Deleted principals with recorded paths to important targets', [
            'Historical chains only. An ACE may matter through SID history; old membership requires restored, effective membership. Verify current rights.',
            *deleted_routes,
        ]))
    deleted_domain_grants = _deleted_domain_grant_lines(data)
    if deleted_domain_grants:
        sections.append(('Deleted principals with significant domain grants', [
            'Direct ACEs remain recorded on a live domain object; verify any SID-history token and effective rights.',
            *deleted_domain_grants,
        ]))
    for key, title in [('da_reachers', 'Principals reaching Domain Admins'),
                       ('reachers', 'Principals reaching high-value targets')]:
        rows = data[key]
        if key == 'reachers':
            da_paths = {(row['name'], tuple((step['name'], step['via']) for step in row['path']))
                        for row in data['da_reachers']}
            rows = [row for row in rows
                    if (row['name'], tuple((step['name'], step['via']) for step in row['path'])) not in da_paths]
        if rows:
            path_lines = [
                f"{row['name']} ({row['hops']} hops): "
                + ' '.join(f"{step['name']}" + (f" --{step['via']}-->" if step['via'] else '')
                           for step in row['path'])
                for row in rows
            ]
            sections.append((title, [
                'Recorded ACL and membership path; verify effective rights and each operation.',
                *path_lines,
            ]))
    conditional_lines = _conditional_route_lines(data)
    if conditional_lines:
        sections.append(('Conditional routes to high-value targets', [
            'One minimum-transition candidate per starting principal; verify every prerequisite and source in JSON.',
            *conditional_lines,
        ]))
    sections.extend(_material_sections(data))
    return sections


def as_text(data: dict) -> str:
    lines = []
    for title, entries in _report_sections(data):
        lines.extend([f"== {title} ==", *('  ' + item for item in entries), ''])
    return '\n'.join(lines).rstrip() + '\n'


def as_md(data: dict) -> str:
    from html import escape

    lines = ['# BloodHound offline analysis', '']
    for title, entries in _report_sections(data):
        lines.extend([f"## {escape(title, quote=False)}", ''])
        lines.extend('- ' + escape(item.replace('\n', '\\n'), quote=False)
                     for item in entries)
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'


def as_json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


RENDERERS = {"text": as_text, "md": as_md, "json": as_json}


def render(g: Graph, fmt: str = "text") -> str:
    return RENDERERS[fmt](build(g))
