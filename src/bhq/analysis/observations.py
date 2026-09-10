"""Expose recorded sessions, SID history, local access and user rights."""
from .common import collection_state, evidence, identifier, ref
from ..loader import LOCAL_COLLECTIONS, LOCAL_GROUP_RIDS, rid_of

SESSION_FIELDS = ('Sessions', 'PrivilegedSessions', 'RegistrySessions')


def sessions(g):
    rows = []
    for obj in g.computers:
        owner = obj['ObjectIdentifier']
        for field in SESSION_FIELDS:
            node = obj.get(field)
            state = collection_state(node)
            entries = []
            for i, entry in enumerate(((node or {}).get('Results') or []) if isinstance(node, dict) else []):
                computer = entry.get('ComputerSID') if isinstance(entry, dict) else None
                user = entry.get('UserSID') if isinstance(entry, dict) else None
                consistent = bool(computer == owner and user and g.kind(user) in ('user', '?'))
                entries.append({'computer': ref(g, computer), 'user': ref(g, user),
                                'consistent': consistent, 'raw': entry,
                                'evidence': evidence(g, owner, f'{field}.Results[{i}]')})
            rows.append({'computer': ref(g, owner), 'method': field, 'state': state,
                         'collected': node.get('Collected') if isinstance(node, dict) else None,
                         'failure_reason': node.get('FailureReason') if isinstance(node, dict) else None,
                         'entries': entries, 'evidence': evidence(g, owner, field)})
    return rows


def local_access(g):
    rows = []
    for obj in g.computers:
        owner = obj['ObjectIdentifier']
        fields = []
        if 'LocalGroups' in obj:
            for i, node in enumerate(obj.get('LocalGroups') or []):
                if isinstance(node, dict):
                    right = LOCAL_GROUP_RIDS.get(rid_of(str(node.get('ObjectIdentifier') or '')))
                    fields.append((f'LocalGroups[{i}]', right, node))
        else:
            fields = [(f, right, obj[f]) for f, right in LOCAL_COLLECTIONS.items() if f in obj]
        for field, right, node in fields:
            state = collection_state(node)
            # Legacy bare lists have entries but no collection status.
            entries = node if isinstance(node, list) else (node.get('Results') or []) if isinstance(node, dict) else []
            rows.append({'computer': ref(g, owner), 'right': right,
                         'state': 'unconfirmed-results' if isinstance(node, list) and entries else state,
                         'principals': [ref(g, identifier(x)) for x in entries], 'raw': node,
                         'evidence': evidence(g, owner, field)})
    return rows


def sid_history(g):
    rows = []
    for obj in g.objects:
        owner = obj['ObjectIdentifier']
        for field, values in [('HasSIDHistory', obj.get('HasSIDHistory')),
                              ('Properties.sidhistory', (obj.get('Properties') or {}).get('sidhistory'))]:
            for i, value in enumerate(values or []):
                rows.append({'principal': ref(g, owner), 'historical': ref(g, identifier(value)),
                             'raw': value, 'evidence': evidence(g, owner, f'{field}[{i}]')})
    return rows


def user_rights(g):
    rows = []
    for obj in g.computers:
        owner = obj['ObjectIdentifier']
        for i, node in enumerate(obj.get('UserRights') or []):
            if not isinstance(node, dict):
                rows.append({'computer': ref(g, owner), 'state': 'invalid', 'raw': node,
                             'evidence': evidence(g, owner, f'UserRights[{i}]')})
                continue
            privilege = node.get('Privilege')
            rows.append({'computer': ref(g, owner), 'privilege': privilege,
                         'deny': privilege.startswith('SeDeny') if isinstance(privilege, str) else None,
                         'state': collection_state(node), 'principals': [ref(g, identifier(x)) for x in node.get('Results') or []],
                         'local_names': node.get('LocalNames'), 'raw': node,
                         'evidence': evidence(g, owner, f'UserRights[{i}]')})
    return rows
