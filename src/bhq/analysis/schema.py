"""Validate containers consumed by analyzers; retain unknown fields unchanged."""

def validate(obj, source):
    # Import lazily: the loader calls this after defining CollectionError.
    from ..loader import CollectionError
    owner = obj.get('ObjectIdentifier', '?')

    def require(value, expected, field):
        if value is not None and not isinstance(value, expected):
            raise CollectionError(f'{source}: {owner}: {field} must be {expected.__name__} or null')

    def records(value, field):
        require(value, list, field)
        for i, entry in enumerate(value or []):
            require(entry, dict, f'{field}[{i}]')
            if entry is None:
                raise CollectionError(f'{source}: {owner}: {field}[{i}] must be an object')
        return value or []

    for field in ('Properties', 'ContainedBy', 'GPOChanges', 'CARegistryData', 'GroupLink'):
        require(obj.get(field), dict, field)
    for field in ('Aces', 'Members', 'LocalGroups', 'UserRights', 'Links', 'ChildObjects',
                  'AllowedToAct', 'AllowedToDelegate', 'EnabledCertTemplates', 'HttpEnrollmentEndpoints', 'Trusts'):
        for i, entry in enumerate(records(obj.get(field), field)):
            for key in ('ObjectIdentifier', 'GUID', 'PrincipalSID', 'RightName', 'Privilege'):
                require(entry.get(key), str, f'{field}[{i}].{key}')
            if field in ('LocalGroups', 'UserRights'):
                records(entry.get('Results'), f'{field}[{i}].Results')
    for field in ('Sessions', 'PrivilegedSessions', 'RegistrySessions'):
        node = obj.get(field)
        require(node, dict, field)
        for i, entry in enumerate(records((node or {}).get('Results'), field + '.Results')):
            for key in ('UserSID', 'ComputerSID'):
                require(entry.get(key), str, f'{field}.Results[{i}].{key}')
    for field in ('LocalAdmins', 'RemoteDesktopUsers', 'DcomUsers', 'PSRemoteUsers'):
        node = obj.get(field)
        if isinstance(node, list):
            records(node, field)
        else:
            require(node, dict, field)
            records((node or {}).get('Results'), field + '.Results')
    for field in ('LocalAdmins', 'RemoteDesktopUsers', 'DcomUsers', 'PSRemoteUsers', 'AffectedComputers'):
        records((obj.get('GPOChanges') or {}).get(field), 'GPOChanges.' + field)
    security = (obj.get('CARegistryData') or {}).get('CASecurity')
    require(security, dict, 'CARegistryData.CASecurity')
    records((security or {}).get('Data'), 'CARegistryData.CASecurity.Data')
    for field in ('HasSIDHistory',):
        require(obj.get(field), list, field)
    for field in ('sidhistory', 'effectiveekus', 'ekus', 'certthumbprints', 'certchain',
                  'unresolvedpublishedtemplates', 'issuancepolicies'):
        require((obj.get('Properties') or {}).get(field), list, 'Properties.' + field)
