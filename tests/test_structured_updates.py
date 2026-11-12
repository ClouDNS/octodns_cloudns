"""Offline regressions for updates to MX and SRV records.

`_apply_update` used to compare the API's plain `record` string with the
octoDNS value objects in `to_delete`, so obsolete MX and SRV values were never
deleted: an update created the new value beside the old one, and a later run
with nothing to create failed with "Update produced no API operations".
"""

from copy import deepcopy
from unittest.mock import Mock
from urllib.parse import parse_qs

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
    return provider._apply_create.call_args[0][0].new.values


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


@pytest.mark.parametrize('record_type,old,field,replacement', [
    ('MX', OLD_MX, 'preference', 20),
    ('MX', OLD_MX, 'exchange', 'other.example.net.'),
    ('SRV', OLD_SRV, 'priority', 20),
    ('SRV', OLD_SRV, 'weight', 10),
    ('SRV', OLD_SRV, 'port', 8443),
    ('SRV', OLD_SRV, 'target', 'other.example.net.'),
])
@pytest.mark.parametrize('trailing_dot', [False, True])
def test_each_mx_srv_field_distinguishes_retained_row(
        record_type, old, field, replacement, trailing_dot):
    zone = Zone('example.com.', [])
    name = 'mail' if record_type == 'MX' else '_probe._tcp'
    retained = dict(old, **{field: replacement})
    def row(row_id, value):
        result = (mx_row(row_id, name, **value) if record_type == 'MX'
                  else srv_row(row_id, name, value))
        if trailing_dot:
            result['record'] += '.'
        return result
    rows = {'1': row('1', old), '2': row('2', retained)}
    rows['3'] = dict(rows['1'], id='3', type='TXT')
    provider = provider_with(zone, rows)
    existing = record(zone, name, record_type, [old, retained])
    desired = record(zone, name, record_type, [retained])
    before = deepcopy((existing.data, desired.data, rows))
    provider._apply_update(Update(existing, desired))
    provider._client.record_delete.assert_called_once_with('example.com', '1')
    provider._apply_create.assert_not_called()
    assert (existing.data, desired.data, rows) == before


def test_naptr_partial_matcher_cannot_select_retained_value_for_deletion():
    zone = Zone('example.com.', [])
    old = dict(order=10, preference=20, flags='S', service='SIP+D2U',
               regexp='', replacement='old.example.net.')
    retained = dict(old, replacement='retained.example.net.')
    rows = {
        str(i): dict(id=str(i), host='naptr', type='NAPTR', ttl='3600',
                     order='10', pref='20', flag='S', params='SIP+D2U',
                     regexp='', replace=value['replacement'], record='')
        for i, value in enumerate([old, retained], 1)
    }
    provider = provider_with(zone, rows)
    existing = record(zone, 'naptr', 'NAPTR', [old, retained])
    obsolete = {record(zone, 'naptr', 'NAPTR', [old]).values[0]}
    # NAPTR's legacy matcher compares only order, preference and flags. It is
    # insufficient for value deletion; preserve the pre-PR selection behavior.
    selected = provider._rows_to_delete(existing, list(rows.values()), obsolete)
    assert selected == []


@pytest.mark.parametrize('record_type,old,new,retained', [
    ('MX', OLD_MX, NEW_MX, BACKUP_MX),
    ('SRV', OLD_SRV, NEW_SRV, dict(OLD_SRV, port=8443)),
])
def test_structured_update_mock_api_converges(
        requests_mock, record_type, old, new, retained):
    provider = ClouDNSProvider('test', 'id', 'password')
    name = 'mail' if record_type == 'MX' else '_probe._tcp'

    def api_row(row_id, value):
        return (mx_row(row_id, name, **value) if record_type == 'MX'
                else srv_row(row_id, name, value))

    rows = {'1': api_row('1', old), '2': api_row('2', retained)}
    retained_before = deepcopy(rows['2'])
    requests_mock.post('https://api.cloudns.net/dns/records.json',
                       json=lambda request, context: deepcopy(rows))
    requests_mock.post('https://api.cloudns.net/dns/get-zone-info.json',
                       json={'status': 'Success'})

    def delete(request, context):
        body = parse_qs(request.text)
        assert body['record-id'] == ['1']
        del rows['1']
        return {'status': 'Success'}

    def create(request, context):
        body = parse_qs(request.text)
        rows['3'] = {
            field: body[field][0]
            for field in ('host', 'ttl', 'record', 'priority')
        }
        rows['3'].update(id='3', type=body['record-type'][0], status=1)
        if record_type == 'SRV':
            rows['3'].update(weight=body['weight'][0], port=body['port'][0])
        return {'status': 'Success'}

    requests_mock.post('https://api.cloudns.net/dns/delete-record.json', json=delete)
    requests_mock.post('https://api.cloudns.net/dns/add-record.json', json=create)
    zone = Zone('example.com.', [])
    desired = record(zone, name, record_type, [new, retained])
    zone.add_record(desired)
    before = deepcopy(desired.data)
    plan = provider.plan(zone)
    assert len(plan.changes) == 1
    assert all(request.url.endswith('/dns/records.json')
               for request in requests_mock.request_history)
    provider.apply(plan)
    assert rows['2'] == retained_before
    assert rows['3']['record'].rstrip('.') == (
        new['exchange'] if record_type == 'MX' else new['target']
    ).rstrip('.')
    assert desired.data == before
    assert provider.plan(zone) is None
    assert sum('delete-record' in request.url
               for request in requests_mock.request_history) == 1
    assert sum('add-record' in request.url
               for request in requests_mock.request_history) == 1
