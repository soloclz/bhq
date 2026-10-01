"""One-shot inventory of recorded BloodHound material and derived relationships.

`build()` produces a structured dict; `as_text` / `as_md` / `as_json` render it.
Markdown/JSON are for dropping into `evidence/` and the engagement report; text
is the terminal default.
"""

from __future__ import annotations

import json

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
    return [{'from_id': source, 'from': g.name(source), 'to_id': target,
             'to': g.name(target), 'edge': relationship,
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
                             'right': ace['RightName'], 'evidence': evidence(g, sid, f'Aces[{i}]')})
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


def _recorded_reachability(g: Graph, start: str) -> tuple[list[dict], list[dict], dict[str, tuple[str, str] | None]]:
    provenance = _edge_evidence(g)
    parents: dict[str, tuple[str, str] | None] = {start: None}
    distances = {start: 0}
    edges = []
    emitted = set()
    for depth, source, relationship, target in queries.control_rows(g, start, max_depth=None):
        key = (source, relationship, target)
        if key not in emitted:
            emitted.add(key)
            edges.append({'depth': depth + 1, 'from_id': source, 'from': g.name(source),
                          'to_id': target, 'to': g.name(target), 'edge': relationship,
                          'evidence': provenance.get(key, [])})
        if target not in parents:
            parents[target] = (source, relationship)
            distances[target] = depth + 1
    nodes = [{'id': sid, 'name': g.name(sid), 'kind': g.kind(sid), 'hops': distances[sid],
              'first_parent': parents[sid][0], 'via': parents[sid][1]}
             for sid in parents if sid != start]
    return nodes, edges, parents


def _path_from_parents(g: Graph, parents: dict, target: str) -> list[dict]:
    chain = []
    current = target
    while parents[current] is not None:
        source, relationship = parents[current]
        chain.append({'id': current, 'name': g.name(current), 'kind': g.kind(current), 'via': relationship})
        current = source
    chain.append({'id': current, 'name': g.name(current), 'kind': g.kind(current), 'via': None})
    return list(reversed(chain))


def build(g: Graph, start_name: str | None = None) -> dict:
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
        "from": start_name,
        "extended": {
            "access": observations.local_access(g), "sessions": observations.sessions(g), "sid-history": observations.sid_history(g),
            "user-rights": observations.user_rights(g), "policy": policy.policy(g),
            "adcs": pki.adcs(g), "coverage": inventory.inventory(g),
        },
    }
    data['raw_observations'] = inventory.populated_raw(g, data['extended']['coverage'])
    if start_name:
        sid = g.sid_of(start_name)
        if not sid:
            candidates = g.sid_candidates(start_name)
            if candidates:
                choices = ", ".join(f"{g.qualified_name(s)} [{s}]" for s in sorted(candidates))
                data["error"] = f"principal is ambiguous: {start_name}; use a qualified name or SID ({choices})"
            else:
                data["error"] = f"principal not found: {start_name}"
            return data
        data['selected_adcs'] = pki.adcs(g, sid)
        nodes, edges, parents = _recorded_reachability(g, sid)
        data['control_reachability'] = nodes
        data['controls'] = edges
        data['goal_paths'] = [
            {'target': ref(g, target), 'reason': reason, 'domain_admins': target in da_targets,
             'path': _path_from_parents(g, parents, target)}
            for target, reason in sorted(targets.items()) if target in parents
        ]
        data['candidate_reachability'] = routes.reachable(g, sid, targets)
        candidates = data['candidate_reachability']['goal_routes']
        best = min(candidates, key=lambda row: len(row['steps']), default=None)
        data['candidate_route'] = {
            'start': ref(g, sid), 'target_state': 'principal',
            'goals': [ref(g, target) for target in sorted(targets)],
            'steps': best['steps'] if best else None,
            'status': 'candidate' if best else 'no-modeled-route',
            'limitations': data['candidate_reachability']['limitations'],
        }
        path, goals = queries.path_to_goal(g, sid, 'high-value')
        data["path"] = {
            "goals": goals,
            "endpoint_reason": targets.get(path[-1][0]) if path else None,
            "path": [{"name": g.name(s), "kind": g.kind(s), "via": lbl} for s, lbl in path] if path else None,
        }
        data["local"] = [{"computer": n, "right": r} for n, r in queries.local_admin_of(g, sid)]
    return data


def _proof(value) -> str:
    if not value:
        return ''
    if isinstance(value, list):
        return ', '.join(_proof(item) for item in value)
    return f"{value.get('source_file')}:{value.get('object_id')}:{value.get('field')}"


def _material_sections(data: dict) -> list[tuple[str, list[str]]]:
    """All populated analyzer results, followed by unmodeled recorded values."""
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
            sections.append((title, presentation.lines(command, rows)[1:] + [
                'record: ' + json.dumps(row, ensure_ascii=False, sort_keys=True)
                for row in rows
            ]))

    pol = ext['policy']
    if any(pol[key] for key in ('links', 'effects', 'changes', 'issues')):
        details = [f"{family}: {json.dumps(row, ensure_ascii=False, sort_keys=True)}"
                   for family in ('links', 'effects', 'changes', 'issues') for row in pol[family]]
        sections.append(('Recorded GPO and policy material', presentation.lines('policy', pol)[1:] + details))

    adcs = ext['adcs']
    if any(adcs[key] for key in ('objects', 'cas', 'templates', 'publications', 'issuance_policies')):
        families = ('objects', 'cas', 'templates', 'publications', 'issuance_policies')
        details = [f"{family}: {json.dumps(row, ensure_ascii=False, sort_keys=True)}"
                   for family in families for row in adcs[family]]
        sections.append(('Recorded AD CS material', presentation.lines('adcs', adcs, True)[1:] + details))
        if 'selected_adcs' in data:
            selected = data['selected_adcs']
            selected_details = [f"{family}: {json.dumps(row, ensure_ascii=False, sort_keys=True)}"
                                for family in families for row in selected[family]]
            sections.append(('AD CS for selected identity',
                             presentation.lines('adcs', selected, True)[1:] + selected_details))

    raw = data['raw_observations']
    if raw:
        sections.append(('Populated fields without a dedicated query', [
            f"{row['object']['name']} [{row['object']['id']}] {row['field']}="
            f"{json.dumps(row['value'], ensure_ascii=False)} [source: {_proof(row['evidence'])}]"
            for row in raw
        ]))
    coverage = ext['coverage']
    raw_fields = [row for row in coverage['fields'] if row['status'] == 'raw-only']
    if raw_fields:
        sections.append(('Field paths without a dedicated query', [
            f"{row['kind']}.{row['field']}: {row['object_count']} objects; "
            f"examples: {_proof(row['examples'])}" for row in raw_fields
        ]))
    if coverage['unmodeled_ace_rights']:
        sections.append(('ACE rights without a model', [
            f"{row['right']} principal={row['principal_id']} [source: {_proof(row['evidence'])}]"
            for row in coverage['unmodeled_ace_rights']
        ]))
    if coverage['unhandled_files']:
        sections.append(('JSON files outside the loader', coverage['unhandled_files']))
    return sections


def _from_sections(data: dict) -> list[tuple[str, list[str]]]:
    if not data.get('from') or data.get('error'):
        return []
    sections = []
    sections.append(('Recorded paths to high-value targets', [
        f"{row['target']['name']} [{row['target']['id']}] "
        f"({'Domain Admins' if row['domain_admins'] else row['reason']}): "
        + ' '.join((f"--{step['via']}--> " if step['via'] else '') + step['name']
                   for step in row['path'])
        for row in data['goal_paths']
    ] or ['(no recorded ACL/membership path to a loaded target)']))

    sections.append(('All reachable ACL control and membership edges', [
        f"hop {row['depth']}: {row['from']} [{row['from_id']}] "
        f"--{row['edge']}--> {row['to']} [{row['to_id']}] "
        f"[source: {_proof(row['evidence'])}]"
        for row in data['controls']
    ] or ['(no outbound recorded edges)']))

    candidate = data['candidate_reachability']
    if candidate['states']:
        sections.append(('All reachable conditional states', [
            f"{row['target']['name']} [{row['target']['id']}] [{row['state']}] "
            f"({row['hops']} hops)" for row in candidate['states']
        ]))
    if candidate['edges']:
        sections.append(('All reachable conditional transitions', [
            f"{row['source']['name']} [{row['source_state']}] --{row['relationship']}--> "
            f"{row['target']['name']} [{row['target_state']}] "
            f"[source: {_proof(row['evidence'])}] "
            f"[requires: {'; '.join(row['requires']) or '(none)'}]"
            for row in candidate['edges']
        ]))
    if candidate['goal_routes']:
        sections.append(('Conditional routes to high-value targets', [
            f"{row['target']['name']} [{row['target']['id']}] ({row['reason']}): "
            + ' '.join(step['relationship'] + '→' + step['target']['name']
                       for step in row['steps'])
            for row in candidate['goal_routes']
        ]))
    if data['local']:
        sections.append(('Local access for selected identity', [
            f"{row['computer']}: {row['right']}" for row in data['local']
        ]))
    return sections


def _coverage_line(c: dict) -> str:
    return f"users={c['users']}  groups={c['groups']}  computers={c['computers']}"


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


def _collector_lines(c: dict) -> list[str]:
    declarations = {
        (m.get("collectorversion", "unknown"), str(m.get("version", "unknown")),
         str(m.get("methods", "unknown"))) for m in c.get("metadata", {}).values()
    }
    return [f"input declares: {collector}; schema={version}; methods={methods}"
            for collector, version, methods in sorted(declarations)]


def _local_coverage_line(c: dict) -> str:
    counts = "  ".join(
        f"{label}={value['attempted']}/{value['answered']}"
        for label, value in c["local_collections"].items()
    )
    return f"local groups attempted/answered of {c['computers']}:  {counts}"


def _report_sections(data: dict) -> list[tuple[str, list[str]]]:
    collection = data['collection']
    sections = []
    scope = [
        _coverage_line(collection),
        *_collector_lines(collection),
        *[f"{kind}: {count} file(s)" for kind, count in sorted(collection['files'].items())],
        *[f"{file}: {json.dumps(meta, ensure_ascii=False, sort_keys=True)}"
          for file, meta in sorted(collection['metadata'].items())],
    ]
    if collection['computers']:
        scope.append(_local_coverage_line(collection))
    sections.append(('Collection', scope))
    sections.append(('Collection and analysis limits',
                     data['analysis']['warnings'] or ['No runtime collection warning.']))

    sections.append(('Recorded property clues',
                     [property_clue(row) for row in data['property_clues']] or
                     ['(no selected populated properties)']))
    roast = [f"Kerberoastable: {json.dumps(row, ensure_ascii=False)}"
             for row in data['kerberoastable']]
    roast += [f"AS-REP roastable: {name}" for name in data['asreproastable']]
    sections.append(('Roasting settings', roast or ['(no matching recorded settings)']))

    if data['account_settings']:
        sections.append(('Recorded account settings', [
            f"{row['account']['name']} [{row['account']['id']}] "
            f"{setting['field']}={json.dumps(setting['value'], ensure_ascii=False)} "
            f"[source: {_proof(setting['evidence'])}]"
            for row in data['account_settings'] for setting in row['settings']
        ]))

    delegation = data['delegation']
    delegation_lines = [f"Unconstrained delegation: {name}" for name in delegation['unconstrained']]
    delegation_lines += [f"Constrained delegation: {row['name']} -> {delegation_targets(row)}"
                         for row in delegation['constrained']]
    delegation_lines += [rbcd_finding(row) + f" [source: {row['source_file']}]"
                         for row in delegation['rbcd']]
    sections.append(('Recorded delegation', delegation_lines or ['(no populated delegation setting)']))
    if data['trusts']:
        sections.append(('Recorded trusts', [trust_finding(row) for row in data['trusts']]))
    if data['dcsync_findings']:
        sections.append(('Recorded DCSync grant combinations', [
            dcsync_finding(row) + ' | ' + json.dumps(row, ensure_ascii=False)
            for row in data['dcsync_findings']
        ]))
    if data['replication_aces']:
        sections.append(('Recorded replication ACEs', [
            f"{row['principal']['name']} [{row['principal']['id']}] --{row['right']}--> "
            f"{row['domain']['name']} [{row['domain']['id']}] "
            f"[source: {_proof(row['evidence'])}]"
            for row in data['replication_aces']
        ]))
    if data['high_value_groups']:
        sections.append(('High-value group membership', [
            f"{row['group']} ({row['why']}): {', '.join(row['members']) or '(empty)'}"
            for row in data['high_value_groups']
        ]))
    if data['recorded_edges']:
        sections.append(('Recorded ACL control and membership edges', [
            f"{row['from']} [{row['from_id']}] --{row['edge']}--> "
            f"{row['to']} [{row['to_id']}] [source: {_proof(row['evidence'])}]"
            for row in data['recorded_edges']
        ]))
    if data['targets']:
        sections.append(('Investigation targets', [
            f"{row['name']} [{row['id']}] — "
            f"{'Domain Admins' if row['domain_admins'] else row['reason']}"
            for row in data['targets']
        ]))
    for key, title in [('da_reachers', 'Principals reaching Domain Admins'),
                       ('reachers', 'Principals reaching high-value targets')]:
        if data[key]:
            sections.append((title, [
                f"{row['name']} ({row['hops']} hops): "
                + ' '.join(f"{step['name']}" + (f" --{step['via']}-->" if step['via'] else '')
                           for step in row['path'])
                for row in data[key]
            ]))
    if data.get('from'):
        if data.get('error'):
            sections.append((f"Selected identity: {data['from']}", [data['error']]))
        else:
            sections.extend((f"From {data['from']}: {title}", rows)
                            for title, rows in _from_sections(data))
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


def render(g: Graph, start_name: str | None = None, fmt: str = "text") -> str:
    return RENDERERS[fmt](build(g, start_name))
