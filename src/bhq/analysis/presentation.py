"""Compact command summaries; JSON retains the complete analysis and evidence."""
import json


def name(item):
    return str(item.get('name') or item.get('id') or '(unknown)')


def proof(row):
    ev = row.get('evidence') or {}
    if isinstance(ev, list):
        ev = ev[0] if ev else {}
    return f" [{ev.get('source_file')}:{ev.get('object_id')}:{ev.get('field')}]"


def _candidate_names(row):
    names = []
    for item in row.get('candidates', []):
        value = name(item)
        if value not in names:
            names.append(value)
    return names


def lines(command, data, details=False):
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
        subject = name(data['principal']) if data.get('principal') else '(none; configuration only)'
        out.append(f"AD CS assessment subject: {subject}")
        out.append('ESC states: candidate is a recorded condition set, not a verified attack path.')
        for row in data['esc_summary']:
            candidates = ', '.join(_candidate_names(row))
            suffix = f"; candidates: {candidates}" if candidates else ''
            out.append(f"{row['esc']} {row['state']}: {row['method']}{suffix}")
            if row['state'] in {'candidate', 'configuration-candidate', 'unknown', 'not-observable'}:
                out.append(f"  verify: {row['verify']}")
        for ca in data['cas']:
            out.append(f"CA {name(ca['ca'])}; hosting computer={name(ca['hosting_computer'])}; NTAuth thumbprint matches={len(ca['ntauth_thumbprint_matches'])}" + proof(ca))
        for row in data['templates']:
            relevant = any(a['state'] in {'candidate', 'configuration-candidate'} for a in row['esc_assessment'])
            relevant = relevant or any(e['template_grant_found'] is True for e in row['enrollment'])
            if not details and not relevant:
                continue
            out.append(f"template {name(row['template'])}: ESC1 template conditions={row['esc1_template_state']}; recorded publications={row['publication_count']}" + proof(row))
            out.append('  checks: ' + json.dumps(row['esc1_template_checks'], ensure_ascii=False))
            for enrollment in row['enrollment']:
                out.append(f"  {name(enrollment['ca'])}: selected subject template grant={enrollment['template_grant_found']}; CA grant={enrollment['ca_grant_found']}")
            out.extend('  ' + clue for clue in row['clues'])
        if details or data.get('principal'):
            for row in data['objects']:
                for grant in row['grants']:
                    out.append(f"grant {name(grant['principal'])} --{grant['right']}--> {name(row['object'])}" + proof(grant))
        else:
            out.append('All-principal grants omitted from text output; use --all-grants or --format json.')
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


def markdown(command, data, details=False):
    if command != 'adcs':
        title = command.replace('-', ' ').title()
        body = '\n'.join(lines(command, data, details))
        return f"# {title}\n\n```text\n{body}\n```"
    subject = name(data['principal']) if data.get('principal') else '(none; configuration only)'
    out = ['# AD CS offline assessment', '', f'**Selected subject:** `{subject}`', '',
           'Recorded conditions are leads for validation, not verified attack paths.', '',
           '## ESC summary', '', '| ESC | state | candidates | detection basis | next validation |',
           '|---|---|---|---|---|']
    for row in data['esc_summary']:
        candidates = '<br>'.join(f'`{value}`' for value in _candidate_names(row)) or '—'
        cells = [row['esc'], row['state'], candidates, row['method'], row['verify']]
        out.append('| ' + ' | '.join(str(cell).replace('|', '\\|') for cell in cells) + ' |')
    out += ['', '## CA and relevant templates', '']
    for ca in data['cas']:
        out.append(f"- **CA `{name(ca['ca'])}`** — host `{name(ca['hosting_computer'])}`; "
                   f"NTAuth thumbprint matches: {len(ca['ntauth_thumbprint_matches'])}{proof(ca)}")
    for row in data['templates']:
        relevant = any(a['state'] in {'candidate', 'configuration-candidate'} for a in row['esc_assessment'])
        relevant = relevant or any(e['template_grant_found'] is True for e in row['enrollment'])
        if not details and not relevant:
            continue
        out.append(f"- Template `{name(row['template'])}` — ESC1 template conditions: "
                   f"`{row['esc1_template_state']}`; recorded publications: `{row['publication_count']}`{proof(row)}")
        for enrollment in row['enrollment']:
            out.append(f"  - `{name(enrollment['ca'])}`: selected-subject template grant "
                       f"`{enrollment['template_grant_found']}`; CA grant `{enrollment['ca_grant_found']}`")
    if details or data.get('principal'):
        out += ['', '## Relevant recorded grants', '']
        for row in data['objects']:
            for grant in row['grants']:
                out.append(f"- `{name(grant['principal'])}` —{grant['right']}→ `{name(row['object'])}`{proof(grant)}")
    else:
        out += ['', 'All-principal grants are omitted. Use `--all-grants` or `--format json` for complete records.']
    out += ['', '## Analysis limits', '']
    out.extend(f'- {item}' for item in data['limitations'])
    return '\n'.join(out)
