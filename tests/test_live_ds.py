"""Explicitly opted-in DS delegation checks on an isolated ClouDNS master zone.

Only collision-checked UUID names and their IDs are eligible for writes.
Credentials come exclusively from environment variables and are never logged.
"""

import os
import json
import tempfile
import time
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import pytest
from octodns.provider import ProviderException
from octodns.record import Record
from octodns.zone import Zone

from octodns_cloudns import ClouDNSClientException, ClouDNSProvider


ENABLED = (os.environ.get('CLOUDNS_DS_TEST') == '1'
           and os.environ.get('CLOUDNS_AUTH_PASSWORD')
           and os.environ.get('CLOUDNS_TEST_DOMAIN')
           and os.environ.get('CLOUDNS_SUB_AUTH_ID'))
pytestmark = pytest.mark.skipif(
    not ENABLED, reason='DS live tests require explicit opt-in and credentials')


class LiveZone:
    def __init__(self):
        self.domain = os.environ['CLOUDNS_TEST_DOMAIN'].rstrip('.')
        self.provider = ClouDNSProvider(
            'live-ds', os.environ['CLOUDNS_SUB_AUTH_ID'],
            os.environ['CLOUDNS_AUTH_PASSWORD'], sub_auth=True)
        self.client = self.provider._client
        self.client._calls_interval = .3
        self.prefix = 'octodns-it-ds-' + uuid4().hex
        self.names, self.owned, self.writes = set(), set(), []
        self.baseline = deepcopy(self.rows())
        self.audit_path = Path(tempfile.gettempdir()) / (self.prefix + '.json')
        self.checkpoint()
        self.request = self.client._request
        self.client._request = self.guarded_request

    def checkpoint(self):
        # Local recovery checkpoint, never committed or attached to reports.
        # Contains test names/IDs and zone rows, but no authentication data.
        descriptor = os.open(str(self.audit_path),
                             os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(dict(domain=self.domain, baseline=self.baseline,
                           names=sorted(self.names), owned=sorted(self.owned)), stream)

    def name(self, kind):
        host = ('_probe._tcp.' + self.prefix if kind == 'SRV'
                else '_443._tcp.' + self.prefix if kind == 'TLSA'
                else self.prefix + '-' + kind.lower())
        assert not any(row['host'] == host for row in self.baseline.values())
        self.names.add(host)
        self.checkpoint()
        return host

    def guarded_request(self, endpoint, params=None):
        params = dict(params or {})
        assert params.get('domain-name') == self.domain
        if endpoint in ('dns/records', 'dns/get-zone-info'):
            return self.request(endpoint, params)
        if endpoint == 'dns/add-record':
            assert params['host'] in self.names
        elif endpoint in ('dns/mod-record', 'dns/delete-record',
                          'dns/change-record-status'):
            record_id = str(params['record-id'])
            assert record_id in self.owned and record_id not in self.baseline
            if endpoint == 'dns/mod-record':
                assert params['host'] in self.names
        else:
            raise AssertionError('Unexpected endpoint: ' + endpoint)
        # No write retries: after an ambiguous outcome teardown reads the rows.
        self.writes.append(endpoint)
        result = self.request(endpoint, params)
        if endpoint == 'dns/add-record':
            self.owned.add(str(result['data']['id']))
            self.checkpoint()
        return result

    def rows(self):
        # Only idempotent reads are retried by the live harness.
        for attempt in range(3):
            try:
                return self.client.zone_records(self.domain)
            except ClouDNSClientException:
                if attempt == 2:
                    raise
                time.sleep(1)

    def record(self, kind, host, values, ttl=300):
        return Record.new(Zone(self.domain + '.', []), host,
                          dict(type=kind, ttl=ttl, values=values))

    def seed(self, kind, host, values, status=1):
        for value in self.record(kind, host, values).values:
            result = self.client.record_create(
                self.domain, kind, host, [value], rrset_ttl=300)
            record_id = str(result['data']['id'])
            if status == 0:
                self.client._request('dns/change-record-status', {
                    'domain-name': self.domain, 'record-id': record_id, 'status': 0})

    def desired(self, kind, host, values, ttl=300):
        self.provider._zone_records.clear()
        desired = Zone(self.domain + '.', [])
        self.provider.populate(desired)
        desired.add_record(Record.new(desired, host, dict(
            type=kind, ttl=ttl, values=values)), replace=True)
        return desired

    def cleanup(self):
        # Discover own rows even if add-record's response was lost. Never adopt
        # a baseline ID or any row whose name was not reserved by this test.
        remaining = self.rows()
        for record_id, row in sorted(remaining.items(),
                                     key=lambda item: item[1]['type'] != 'DS'):
            if row['host'] in self.names and record_id not in self.baseline:
                self.owned.add(str(record_id))
                self.checkpoint()
                try:
                    self.client.record_delete(self.domain, record_id)
                except ClouDNSClientException:
                    # Do not repeat an ambiguous write. Accept only verified
                    # absence; otherwise leave a recovery checkpoint and fail.
                    if str(record_id) in self.rows():
                        raise
        after = self.rows()
        changed = [record_id for record_id, row in self.baseline.items()
                   if after.get(record_id) != row]
        extras = set(after) - set(self.baseline)
        assert not changed, 'Baseline IDs changed: {}'.format(changed)
        assert not extras, 'Unexpected remaining IDs: {}'.format(sorted(extras))


@pytest.fixture
def live():
    zone = LiveZone()
    try:
        yield zone
    finally:
        zone.cleanup()


def test_live_ds_delegation_combined_plan(live):
    """Create NS+DS together, replace NS while signed, then delete both."""
    value = dict(key_tag=12345, algorithm=13, digest_type=2, digest='ab' * 32)
    host = live.name('DS')
    provider = live.provider

    def sync(ns_values, ds_values):
        provider._zone_records.clear()
        desired = Zone(live.domain + '.', [])
        provider.populate(desired)
        for record in list(desired.records):
            if record.name == host and record._type in ('NS', 'DS'):
                desired.remove_record(record)
        for kind, values in [('NS', ns_values), ('DS', ds_values)]:
            if values:
                desired.add_record(Record.new(desired, host, dict(
                    type=kind, ttl=300, values=values)))
        plan = provider.plan(desired)
        assert plan is not None
        assert all(c.record.name == host and c.record._type in ('NS', 'DS')
                   for c in plan.changes)
        provider.apply(plan)
        assert provider.plan(desired) is None
        return {key: row for key, row in live.rows().items()
                if row['host'] == host}

    created = sync(['ns1.example.net.'], [value])
    assert {r['type'] for r in created.values()} == {'NS', 'DS'}
    ds_id = next(key for key, row in created.items() if row['type'] == 'DS')
    replaced = sync(['ns2.example.net.'], [value])
    assert replaced[ds_id] == created[ds_id]
    assert {r['record'].rstrip('.') for r in replaced.values()
            if r['type'] == 'NS'} == {'ns2.example.net'}
    assert sync([], []) == {}


def test_live_ds_delegation_missing_preflights_entire_plan(live):
    host = live.name('DS')
    auxiliary = live.name('aux')
    provider = live.provider
    desired = Zone(live.domain + '.', [])
    provider.populate(desired)
    desired.add_record(Record.new(desired, host, dict(
        type='DS', ttl=300, values=[dict(key_tag=12345, algorithm=13,
                                       digest_type=2, digest='ab' * 32)])))
    desired.add_record(Record.new(desired, auxiliary, dict(
        type='A', ttl=300, value='192.0.2.200')))
    before = live.rows()
    count = len(live.writes)
    with pytest.raises(ProviderException, match='active NS delegation'):
        provider.apply(provider.plan(desired))
    assert len(live.writes) == count
    assert live.rows() == before
    assert provider._zone_records == {}
