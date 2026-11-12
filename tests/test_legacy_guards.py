"""0.0.19 fail-loud guards; synthetic rows, no live DNS writes."""

from copy import deepcopy
from unittest.mock import Mock, call

import pytest
from octodns.provider import ProviderException
from octodns.provider.plan import Plan
from octodns.record import Create, Delete, Record, Update
from octodns.zone import Zone

from octodns_cloudns import ClouDNSClient, ClouDNSClientException, ClouDNSProvider


def fixture(record_type='A', values=None, rows=None):
    zone = Zone('example.com.', [])
    provider = ClouDNSProvider('test', 'id', 'password')
    provider._client = Mock(spec=ClouDNSClient)
    name = ('_probe._tcp' if record_type == 'SRV' else
            '_443._tcp' if record_type == 'TLSA' else 'www')
    existing = Record.new(zone, name, {
        'type': record_type, 'ttl': 300,
        'values': values or ['192.0.2.1'],
    })
    provider._zone_records[zone.name] = rows if rows is not None else {
        '1': dict(id='1', host=name, type=record_type, ttl='300',
                  record='192.0.2.1', status=1),
    }
    return provider, existing


def update(existing, values):
    return Update(existing, Record.new(existing.zone, existing.name, {
        'type': existing._type, 'ttl': existing.ttl, 'values': values,
    }))


@pytest.mark.parametrize('record_type,values', [
    ('A', ['192.0.2.1']),
    ('CAA', [dict(flags=0, tag='issue', value='ca.example')]),
    ('LOC', [dict(lat_degrees=42, lat_minutes=0, lat_seconds=0,
                  lat_direction='N', long_degrees=23, long_minutes=0,
                  long_seconds=0, long_direction='E', altitude=1, size=1,
                  precision_horz=1, precision_vert=1)]),
])
def test_unmatched_delete_fails_without_writes(record_type, values):
    provider, existing = fixture(record_type, values, rows={})
    with pytest.raises(ProviderException, match='Delete matched no active API rows'):
        provider._apply_delete(Delete(existing))
    assert provider._client.mock_calls == []


def test_full_name_type_delete_preserves_inactive_and_unrelated_rows():
    provider, existing = fixture()
    rows = provider._zone_records[existing.zone.name]
    for row_id, changes in [
        ('2', {'status': 0}), ('3', {'status': '0'}),
        ('4', {'host': 'other'}), ('5', {'type': 'TXT'}),
        ('6', {'status': '1'}),
    ]:
        rows[row_id] = dict(rows['1'], id=row_id, **changes)
    before = deepcopy((existing.data, rows))
    provider._apply_delete(Delete(existing))
    assert provider._client.record_delete.call_args_list == [
        call('example.com', '1'), call('example.com', '6'),
    ]
    assert (existing.data, rows) == before


@pytest.mark.parametrize('status', [0, '0'])
def test_inactive_only_delete_fails_without_deleting_or_reactivating(status):
    provider, existing = fixture()
    provider._zone_records[existing.zone.name]['1']['status'] = status
    with pytest.raises(ProviderException, match='no active API rows'):
        provider._apply_delete(Delete(existing))
    assert provider._client.mock_calls == []


@pytest.mark.parametrize('operation', ['update', 'delete'])
def test_tlsa_value_operations_fail_with_diagnostic(operation):
    if 'TLSA' not in Record._CLASSES:
        pytest.skip('TLSA is unavailable in this octoDNS version')
    value = dict(certificate_usage=3, selector=1, matching_type=1,
                 certificate_association_data='01' * 32)
    provider, existing = fixture('TLSA', [value])
    change = (Delete(existing) if operation == 'delete' else update(
        existing, [dict(value, certificate_association_data='02' * 32)]))
    with pytest.raises(ProviderException, match='TLSA .* is not supported'):
        getattr(provider, '_apply_' + operation)(change)
    assert provider._client.mock_calls == []


@pytest.mark.parametrize('case', ['delete', 'tlsa', 'partial-removal'])
def test_guard_preflight_prevents_earlier_plan_writes_and_clears_cache(case):
    provider, existing = fixture(values=['192.0.2.1', '192.0.2.2'])
    if case == 'delete':
        bad = Delete(Record.new(existing.zone, 'missing', {
            'type': 'A', 'ttl': 300, 'value': '192.0.2.99',
        }))
    elif case == 'tlsa':
        if 'TLSA' not in Record._CLASSES:
            pytest.skip('TLSA is unavailable in this octoDNS version')
        bad = Delete(Record.new(existing.zone, '_443._tcp', {
            'type': 'TLSA', 'ttl': 300, 'value': dict(
                certificate_usage=3, selector=1, matching_type=1,
                certificate_association_data='01' * 32),
        }))
    else:
        # One obsolete value matches, one does not; a create must not hide it.
        bad = update(existing, ['192.0.2.3'])
    create = Create(Record.new(existing.zone, 'new', {
        'type': 'A', 'ttl': 300, 'value': '192.0.2.10',
    }))
    before = deepcopy(existing.data)
    with pytest.raises(ProviderException):
        provider._apply(Plan(existing.zone, existing.zone,
                             [create, Delete(existing), bad], True))
    assert provider._client.mock_calls == []
    assert provider._zone_records == {}
    assert existing.data == before


def test_unmatched_ns_removal_does_not_add_replacement_and_report_success():
    provider, existing = fixture('NS', ['old.example.net.'], rows={
        '1': dict(id='1', host='www', type='NS', ttl='300', status=1,
                  record='old.example.net'),
    })
    with pytest.raises(ProviderException, match='Update removals matched no active API rows'):
        provider._apply_update(update(existing, ['new.example.net.']))
    assert provider._client.mock_calls == []


@pytest.mark.parametrize('has_active', [True, False])
@pytest.mark.parametrize('record_type,old,new,fields', [
    ('TXT', 'old;value', 'new;value', {}),
    ('MX', dict(preference=10, exchange='old.example.net.'),
     dict(preference=10, exchange='new.example.net.'),
     dict(priority='10', record='old.example.net')),
    ('SRV', dict(priority=10, weight=1, port=443, target='old.example.net.'),
     dict(priority=10, weight=1, port=443, target='new.example.net.'),
     dict(priority='10', weight='1', port='443', record='old.example.net')),
])
def test_backported_value_deletion_preserves_inactive_rows(
        record_type, old, new, fields, has_active):
    if record_type == 'TXT':
        fields['record'] = old
        old, new = old.replace(';', r'\;'), new.replace(';', r'\;')
    provider, existing = fixture(record_type, [old])
    rows = provider._zone_records[existing.zone.name]
    rows['1'].update(fields)
    if not has_active:
        rows['1']['status'] = 0
    rows['2'] = dict(rows['1'], id='2', status='0')
    rows['3'] = dict(rows['1'], id='3', status=0)
    before = deepcopy((existing.data, rows))
    desired = update(existing, [new])
    desired_before = deepcopy(desired.new.data)
    if has_active:
        provider._apply_update(desired)
        provider._client.record_delete.assert_called_once_with('example.com', '1')
        provider._client.record_create.assert_called_once()
    else:
        with pytest.raises(ProviderException, match='no active API rows'):
            provider._apply_update(desired)
        assert provider._client.mock_calls == []
    assert (existing.data, rows) == before
    assert desired.new.data == desired_before


def test_replace_all_with_no_rows_fails_instead_of_adding_duplicates():
    value = dict(flags=0, tag='issue', value='old.example')
    provider, existing = fixture('CAA', [value], rows={})
    # Legacy unhashable values use replace-all; the same guard applies to it.
    provider._records_are_same = Mock(return_value=[])
    with pytest.raises(ProviderException, match='no active API rows'):
        provider._apply_update(update(existing, [dict(value, value='new.example')]))
    assert provider._client.mock_calls == []


def test_replace_all_preserves_inactive_rows():
    value = dict(flags=0, tag='issue', value='old.example')
    provider, existing = fixture('CAA', [value])
    provider._records_are_same = Mock(return_value=[
        {'id': '1', 'status': 1}, {'id': '2', 'status': 0},
    ])
    provider._apply_create = Mock()
    change = update(existing, [dict(value, value='new.example')])
    before = deepcopy((existing.data, change.new.data))
    provider._apply_update(change)
    provider._client.record_delete.assert_called_once_with('example.com', '1')
    provider._apply_create.assert_called_once_with(change)
    assert (existing.data, change.new.data) == before


def test_replace_all_partial_match_fails_before_any_deletes():
    old = dict(flags=0, tag='issue', value='old.example')
    retained = dict(old, value='retained.example')
    provider, existing = fixture('CAA', [old, retained])
    # Initial rrset and first value match, but the other old value does not.
    provider._records_are_same = Mock(side_effect=[
        [{'id': '1'}], [{'id': '1'}], [],
    ])
    with pytest.raises(ProviderException, match='no active API rows'):
        provider._apply_update(update(existing, [retained]))
    assert provider._client.mock_calls == []


@pytest.mark.parametrize('problem', [{'status': 'unknown'}, {'id': ''}])
def test_invalid_later_row_prevents_all_deletes(problem):
    provider, existing = fixture()
    rows = provider._zone_records[existing.zone.name]
    rows['2'] = dict(rows['1'], **problem)
    with pytest.raises(ProviderException, match='invalid status or ID'):
        provider._apply_delete(Delete(existing))
    assert provider._client.mock_calls == []


def test_api_delete_failure_propagates_without_retry_and_clears_cache():
    provider, existing = fixture()
    provider._client.record_delete.side_effect = ClouDNSClientException('failed')
    with pytest.raises(ClouDNSClientException, match='failed'):
        provider._apply(Plan(existing.zone, existing.zone, [Delete(existing)], True))
    provider._client.record_delete.assert_called_once_with('example.com', '1')
    provider._client.record_create.assert_not_called()
    assert provider._zone_records == {}


def test_duplicate_matcher_rows_delete_each_id_only_once():
    provider, existing = fixture()
    row = provider._zone_records[existing.zone.name]['1']
    provider._records_are_same = Mock(return_value=[row, row])
    provider._apply_delete(Delete(existing))
    provider._client.record_delete.assert_called_once_with('example.com', '1')
