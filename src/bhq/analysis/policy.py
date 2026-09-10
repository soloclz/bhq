"""Recorded policy scope and projected local-group changes, not resultant policy."""
from collections import defaultdict, deque
from .common import evidence, identifier, ref
from ..loader import LOCAL_COLLECTIONS


def policy(g):
    children, parents, sources = defaultdict(set), defaultdict(set), defaultdict(list)
    for obj in g.objects:
        sid = obj['ObjectIdentifier']
        parent = identifier(obj.get('ContainedBy'))
        if parent:
            parents[sid].add(parent)
            sources[(parent, sid)].append(evidence(g, sid, 'ContainedBy'))
        for i, child in enumerate(obj.get('ChildObjects') or []):
            child = identifier(child)
            if child:
                parents[child].add(sid)
                sources[(sid, child)].append(evidence(g, sid, f'ChildObjects[{i}]'))
    issues = []
    for child, candidates in sorted(parents.items()):
        if len(candidates) != 1:
            issues.append({'object': ref(g, child), 'reason': 'conflicting-parents', 'parents': sorted(candidates)})
            continue
        parent = next(iter(candidates))
        if g.kind(parent) in ('domain', 'ou', 'container'):
            children[parent].add(child)
        else:
            issues.append({'object': ref(g, child), 'reason': 'unresolved-or-invalid-parent', 'parents': [parent]})
    links, effects, changes = [], [], []
    for obj in g.objects:
        scope = obj['ObjectIdentifier']
        for i, link in enumerate(obj.get('Links') or []):
            if not isinstance(link, dict):
                issues.append({'object': ref(g, scope), 'reason': 'invalid-link', 'raw': link})
                continue
            gpo = link.get('GUID')
            link_ev = evidence(g, scope, f'Links[{i}]')
            links.append({'gpo': ref(g, gpo), 'scope': ref(g, scope), 'raw': link, 'evidence': link_ev})
            queue = deque([(scope, [scope], 'candidate', [link_ev])])
            while queue:
                parent, path, inherited_status, proof = queue.popleft()
                for child in sorted(children[parent]):
                    if child in path:
                        issues.append({'object': ref(g, child), 'reason': 'containment-cycle', 'path': path + [child]})
                        continue
                    status = inherited_status
                    block = (g.by_sid.get(child, {}).get('Properties') or {}).get('blocksinheritance')
                    if link.get('IsEnforced') is not True and g.kind(child) == 'ou':
                        if block is True:
                            status = 'blocked' if link.get('IsEnforced') is False else 'unknown-enforcement'
                        elif block is not False and status == 'candidate':
                            status = 'unknown-inheritance'
                    chain = path + [child]
                    trail = proof + sources[(parent, child)]
                    if g.kind(child) in ('computer', 'user'):
                        effects.append({'gpo': ref(g, gpo), 'scope': ref(g, scope), 'target': ref(g, child),
                                        'inheritance': status, 'containment_path': chain, 'evidence': trail,
                                        'requires': ['confirm link enabled and policy section enabled',
                                                     'security and WMI filtering', 'SYSVOL content and actual policy application']})
                    if g.kind(child) in ('domain', 'ou', 'container'):
                        queue.append((child, chain, status, trail))
        node = obj.get('GPOChanges')
        if isinstance(node, dict) and any(node.values()):
            changes.append({'scope': ref(g, scope), 'affected_computers': [ref(g, identifier(v)) for v in node.get('AffectedComputers') or []],
                            'groups': {right: [ref(g, identifier(v)) for v in node.get(field) or []]
                                       for field, right in LOCAL_COLLECTIONS.items()},
                            'raw': node, 'evidence': evidence(g, scope, 'GPOChanges')})
    return {'links': links, 'effects': effects, 'changes': changes, 'issues': issues}
