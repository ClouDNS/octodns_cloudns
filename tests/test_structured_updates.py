"""Offline regressions for updates to MX and SRV records.

`_apply_update` used to compare the API's plain `record` string with the
octoDNS value objects in `to_delete`, so obsolete MX and SRV values were never
deleted: an update created the new value beside the old one, and a later run
with nothing to create failed with "Update produced no API operations".
"""

from copy import deepcopy
from unittest.mock import Mock

import pytest
from octodns.record import Record, Update
from octodns.zone import Zone

from octodns_cloudns import ClouDNSClient, ClouDNSProvider

OLD_MX = {'preference': 1, 'exchange': 'old.example.net.'}
NEW_MX = {'preference': 1, 'exchange': 'new.example.net.'}
BACKUP_MX = {'preference': 10, 'exchange': 'backup.example.net.'}
OLD_SRV = {'priority': 0, 'weight': 0, 'port': 443, 'target': 'old.example.net.'}
NEW_SRV = {'priority': 0, 'weight': 1, 'port': 443, 'target': 'new.example.net.'}


def mx_row(row_id, host, preference, exchange):
    return dict(id=row_id, host=host, type='MX', ttl='3600', status=1,
                priority=str(preference), record=exchange.rstrip('.'))


def srv_row(row_id, host, value):
    return dict(id=row_id, host=host, type='SRV', ttl='3600', status=1,
                priority=str(value['priority']), weight=str(value['weight']),
                port=str(value['port']), record=value['target'].rstrip('.'))


def provider_with(zone, rows):
    provider = ClouDNSProvider('test', 'id', 'password')
    provider._client = Mock(spec=ClouDNSClient)
    provider._apply_create = Mock()
    provider._zone_records[zone.name] = rows
    return provider


def record(zone, name, _type, values):
    return Record.new(zone, name, {'type': _type, 'ttl': 3600, 'values': values})


def created_values(provider):
    provider._apply_create.assert_called_once()
    return provider._apply_create.call_args.args[0].new.values


@pytest.mark.parametrize('existing_values, expect_create', [
    pytest.param([OLD_MX, BACKUP_MX], True, id='replace-exchange'),
    pytest.param([OLD_MX, NEW_MX, BACKUP_MX], False, id='leftover-from-earlier-run'),
])
def test_mx_update_deletes_the_obsolete_exchange_only(existing_values, expect_create):
    zone = Zone('example.com.', [])
    rows = {
        '1': mx_row('1', '', **OLD_MX),
        '2': mx_row('2', '', **BACKUP_MX),
        '3': mx_row('3', 'other', **OLD_MX),
        '4': mx_row('4', '', 20, OLD_MX['exchange']),
    }
    if not expect_create:
        rows['5'] = mx_row('5', '', **NEW_MX)
    provider = provider_with(zone, rows)
    existing = record(zone, '', 'MX', existing_values)
    desired = record(zone, '', 'MX', [NEW_MX, BACKUP_MX])
    before = deepcopy((existing.data, desired.data))

    provider._apply_update(Update(existing, desired))

    provider._client.record_delete.assert_called_once_with('example.com', '1')
    if expect_create:
        assert [(v.preference, v.exchange) for v in created_values(provider)] == [
            (1, 'new.example.net.')
        ]
    else:
        provider._apply_create.assert_not_called()
    assert (existing.data, desired.data) == before


@pytest.mark.parametrize('existing_values, expect_create', [
    pytest.param([OLD_SRV], True, id='replace-target'),
    pytest.param([OLD_SRV, NEW_SRV], False, id='leftover-from-earlier-run'),
])
def test_srv_update_deletes_the_obsolete_target_only(existing_values, expect_create):
    zone = Zone('example.com.', [])
    name = '_autodiscover._tcp'
    rows = {
        '1': srv_row('1', name, OLD_SRV),
        '2': srv_row('2', '_other._tcp', OLD_SRV),
        '3': srv_row('3', name, dict(OLD_SRV, port=8443)),
    }
    if not expect_create:
        rows['4'] = srv_row('4', name, NEW_SRV)
    provider = provider_with(zone, rows)
    existing = record(zone, name, 'SRV', existing_values)
    desired = record(zone, name, 'SRV', [NEW_SRV])

    provider._apply_update(Update(existing, desired))

    provider._client.record_delete.assert_called_once_with('example.com', '1')
    if expect_create:
        assert [v.target for v in created_values(provider)] == ['new.example.net.']
    else:
        provider._apply_create.assert_not_called()
