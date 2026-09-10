"""Source references and membership helpers shared by analyzers."""
from collections import deque


def ref(g, sid):
    return {'id': sid, 'name': g.qualified_name(sid), 'kind': g.kind(sid),
            'resolved': sid in g.by_sid}


def evidence(g, owner, field):
    return {'source_file': g.object_sources.get(owner), 'object_id': owner, 'field': field}


def identifier(value):
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        sid = value.get('ObjectIdentifier')
        return sid if isinstance(sid, str) and sid else None
    return None


def membership(g, sid):
    """One recorded membership path per group, including PrimaryGroupSID."""
    paths, queue = {sid: [sid]}, deque([sid])
    while queue:
        current = queue.popleft()
        for group in g.member_edges.get(current, []):
            if group not in paths:
                paths[group] = paths[current] + [group]
                queue.append(group)
    return paths


def collection_state(value):
    """Retain contradictory partial results; never coerce unknown to false."""
    if value is None:
        return 'missing'
    if not isinstance(value, dict) or not isinstance(value.get('Results'), list):
        return 'invalid'
    if value.get('FailureReason'):
        return 'partial' if value['Results'] else 'failed'
    if value.get('Collected') is not True:
        return 'unconfirmed-results' if value['Results'] else 'not-confirmed'
    return 'recorded' if value['Results'] else 'empty-unknown'
