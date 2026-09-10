"""Compact command summaries; JSON retains the complete analysis and evidence."""
import json


def name(item):
    return str(item.get('name') or item.get('id') or '(unknown)')


def proof(row):
    ev = row.get('evidence') or {}
    if isinstance(ev, list):
        ev = ev[0] if ev else {}
    return f" [{ev.get('source_file')}:{ev.get('object_id')}:{ev.get('field')}]"


def lines(command, data):
    out = ['Recorded input only; unknown values and conditional findings do not establish effective access.']
    if command == 'access':
        for row in data:
            principals = ', '.join(name(p) for p in row['principals'])
            out.append(f"{name(row['computer'])} {row['right'] or '(unmodeled local group)'}: {row['state']} {principals}" + proof(row))
    elif command == 'sessions':
        for row in data:
            users = ', '.join(name(e['user']) + ('' if e['consistent'] else ' [inconsistent]') for e in row['entries'])
            out.append(f"{name(row['computer'])} {row['method']}: {row['state']} ({len(row['entries'])} entries) {users}" + proof(row))
            if row['failure_reason']:
                out.append('  FailureReason: ' + str(row['failure_reason']))
    elif command == 'sid-history':
        for row in data:
            out.append(f"{name(row['principal'])} -> historical SID {name(row['historical'])}" + proof(row))
        out.append('Historical SID grants are not the historical account credential or its current group memberships.')
    elif command == 'user-rights':
        for row in data:
            principals = ', '.join(name(p) for p in row.get('principals', []))
            out.append(f"{name(row['computer'])}: {row.get('privilege', '(unknown)')} {row['state']} {principals}" + proof(row))
            if row.get('local_names'):
                out.append('  unresolved local names: ' + json.dumps(row['local_names'], ensure_ascii=False))
        out.append('Assignments may be GPO-derived; effective logon rights require deny-right and token evaluation.')
    elif command == 'policy':
        for link in data['links']:
            out.append(f"link {name(link['gpo'])} -> {name(link['scope'])} enforced={link['raw'].get('IsEnforced')}" + proof(link))
        for row in data['effects']:
            out.append(f"scope {name(row['gpo'])} -> {name(row['target'])}: {row['inheritance']}" + proof(row))
        for row in data['changes']:
            targets = ', '.join(name(p) for p in row['affected_computers']) or '(no recorded affected computers)'
            for right, principals in row['groups'].items():
                if principals:
                    out.append(f"projected {right}: {', '.join(name(p) for p in principals)} -> {targets}" + proof(row))
        for issue in data['issues']:
            out.append('issue: ' + json.dumps(issue, ensure_ascii=False))
        out.append('Candidate scope excludes confirmed inheritance blocks; verify link state, filtering, policy content and application.')
    elif command == 'adcs':
        for ca in data['cas']:
            out.append(f"CA {name(ca['ca'])}; hosting computer={name(ca['hosting_computer'])}; NTAuth thumbprint matches={len(ca['ntauth_thumbprint_matches'])}" + proof(ca))
        for row in data['templates']:
            out.append(f"template {name(row['template'])}: ESC1 template conditions={row['esc1_template_state']}; recorded publications={row['publication_count']}" + proof(row))
            out.append('  checks: ' + json.dumps(row['esc1_template_checks'], ensure_ascii=False))
            for enrollment in row['enrollment']:
                out.append(f"  {name(enrollment['ca'])}: selected subject template grant={enrollment['template_grant_found']}; CA grant={enrollment['ca_grant_found']}")
            out.extend('  ' + clue for clue in row['clues'])
        for row in data['objects']:
            for grant in row['grants']:
                out.append(f"grant {name(grant['principal'])} --{grant['right']}--> {name(row['object'])}" + proof(grant))
        for row in data['publications']:
            if not row['resolved']:
                out.append(f"unresolved publication: {name(row['ca'])} -> {name(row['template'])}" + proof(row))
        for row in data['issuance_policies']:
            out.append(f"issuance policy {name(row['policy'])} oid={row['oid']} -> {name(row['group'])}" + proof(row))
        out.extend(data['limitations'])
    elif command == 'coverage':
        for row in data['fields']:
            out.append(f"{row['status']} {row['kind']} {row['field']}: {row['object_count']} objects -> {row['outlet']}")
        for row in data['unmodeled_ace_rights']:
            out.append(f"unmodeled ACE right: {row['right']} principal={row['principal_id']}" + proof(row))
        for filename in data['unhandled_files']:
            out.append('unhandled file: ' + filename)
        out.extend(data['limitations'])
    elif command == 'route':
        out.append(f"{name(data['start'])}: {data['status']} (target state: {data['target_state']})")
        for row in data['steps'] or []:
            out.append(f"{name(row['source'])} [{row['source_state']}] --{row['relationship']}--> {name(row['target'])} [{row['target_state']}]" + proof(row))
            out.extend('  requires: ' + item for item in row['requires'])
        if data['steps'] == []:
            out.append('Already at the requested target state; zero transitions.')
        out.extend(data['limitations'])
    if len(out) == 1:
        out.append('(no matching recorded entries; collection scope still applies)')
    return out
