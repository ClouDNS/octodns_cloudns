"""Explicitly opted-in 0.0.19 checks on an isolated ClouDNS master zone.

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
from octodns.provider.plan import Plan
from octodns.record import Create, Delete, Record, Update
from octodns.zone import Zone

from octodns_cloudns import ClouDNSClientException, ClouDNSProvider


ENABLED = (os.environ.get('CLOUDNS_0019_TEST') == '1'
           and os.environ.get('CLOUDNS_AUTH_PASSWORD')
           and os.environ.get('CLOUDNS_TEST_DOMAIN')
           and os.environ.get('CLOUDNS_SUB_AUTH_ID'))
pytestmark = pytest.mark.skipif(
    not ENABLED, reason='0.0.19 live tests require explicit opt-in and credentials')


class LiveZone:
    def __init__(self):
        self.domain = os.environ['CLOUDNS_TEST_DOMAIN'].rstrip('.')
        self.provider = ClouDNSProvider(
            'live-0019', os.environ['CLOUDNS_SUB_AUTH_ID'],
            os.environ['CLOUDNS_AUTH_PASSWORD'], sub_auth=True)
        self.client = self.provider._client
        self.client._calls_interval = .3
        self.prefix = 'octodns-it-019-' + uuid4().hex
        self.names, self.owned, self.writes = set(), set(), []
        self.baseline = deepcopy(self.client.zone_records(self.domain))
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

    def assert_guard(self, change, message):
        self.provider._zone_records.clear()
        before = deepcopy(self.rows())
        count = len(self.writes)
        auxiliary = self.name('aux')
        create = Create(self.record('A', auxiliary, ['192.0.2.200']))
        with pytest.raises(ProviderException, match=message):
            self.provider._apply(Plan(
                change.existing.zone, change.existing.zone, [create, change], True))
        assert len(self.writes) == count
        assert self.rows() == before
        assert self.provider._zone_records == {}

    def cleanup(self):
        # Discover own rows even if add-record's response was lost. Never adopt
        # a baseline ID or any row whose name was not reserved by this test.
        remaining = self.rows()
        for record_id, row in remaining.items():
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


OLD_MX = dict(preference=10, exchange='old.example.net.')
NEW_MX = dict(preference=10, exchange='new.example.net.')
KEEP_MX = dict(preference=20, exchange='old.example.net.')
OLD_SRV = dict(priority=10, weight=1, port=443, target='old.example.net.')
NEW_SRV = dict(priority=10, weight=2, port=443, target='new.example.net.')
KEEP_SRV = dict(priority=10, weight=1, port=8443, target='old.example.net.')
TLSA = dict(certificate_usage=3, selector=1, matching_type=1,
            certificate_association_data='01' * 32)


@pytest.mark.parametrize('kind,old,new,keep', [
    ('TXT', r'old\;value&+%#', r'new\;value&+%#', r'keep\;value'),
    ('MX', OLD_MX, NEW_MX, KEEP_MX),
    ('SRV', OLD_SRV, NEW_SRV, KEEP_SRV),
])
def test_live_value_update_converges(live, kind, old, new, keep):
    host = live.name(kind)
    live.seed(kind, host, [old, keep])
    initial = live.rows()
    old_record = live.record(kind, host, [old])
    live.provider._zone_records[old_record.zone.name] = initial
    obsolete = str(live.provider._records_are_same(old_record)[0]['id'])
    retained = next(row for row in initial.values()
                    if row['host'] == host and str(row['id']) != obsolete)
    desired = live.desired(kind, host, [new, keep])
    wanted = deepcopy(next(r for r in desired.records if r.name == host).data)
    count = len(live.writes)
    plan = live.provider.plan(desired)
    assert len(plan.changes) == 1
    assert plan.changes[0].existing.name == host
    assert len(live.writes) == count  # planning is read-only
    live.provider.apply(plan)
    assert live.writes[count:] == ['dns/delete-record', 'dns/add-record']
    after = live.rows()
    assert obsolete not in after
    assert after[str(retained['id'])] == retained
    assert next(r for r in desired.records if r.name == host).data == wanted
    assert live.provider.plan(desired) is None


def test_live_tlsa_ttl_and_value_guards(live):
    host = live.name('TLSA')
    live.seed('TLSA', host, [TLSA])
    initial = next(row for row in live.rows().values() if row['host'] == host)
    desired = live.desired('TLSA', host, [TLSA], ttl=3600)
    count = len(live.writes)
    plan = live.provider.plan(desired)
    assert len(plan.changes) == 1 and len(live.writes) == count
    live.provider.apply(plan)
    assert live.writes[count:] == ['dns/mod-record']
    after = live.rows()[str(initial['id'])]
    assert str(after['ttl']) == '3600'
    assert {k: v for k, v in initial.items() if k != 'ttl'} == {
        k: v for k, v in after.items() if k != 'ttl'}
    assert live.provider.plan(desired) is None
    existing = live.record('TLSA', host, [TLSA], ttl=3600)
    replacement = live.record('TLSA', host, [dict(
        TLSA, certificate_association_data='02' * 32)], ttl=3600)
    live.assert_guard(Update(existing, replacement), 'TLSA value update')
    live.assert_guard(Delete(existing), 'TLSA delete')


def test_live_missing_delete_and_partial_removal_preflight(live):
    host = live.name('A')
    missing = live.record('A', host, ['192.0.2.1'])
    live.assert_guard(Delete(missing), 'Delete matched no active API rows')
    live.seed('A', host, ['192.0.2.1'])
    stale = live.record('A', host, ['192.0.2.1', '192.0.2.99'])
    replacement = live.record('A', host, ['192.0.2.2'])
    live.assert_guard(Update(stale, replacement), 'Update removals matched no active API rows')


@pytest.mark.parametrize('kind,old,new', [
    ('A', '192.0.2.1', '192.0.2.2'),
    ('TXT', r'old\;value', r'new\;value'),
    ('MX', OLD_MX, NEW_MX), ('SRV', OLD_SRV, NEW_SRV),
])
def test_live_delete_preserves_inactive_and_guards_inactive_only(live, kind, old, new):
    host = live.name(kind)
    live.seed(kind, host, [old])
    live.seed(kind, host, [new], status=0)
    rows = live.rows()
    inactive = next(row for row in rows.values()
                    if row['host'] == host and str(row['status']) == '0')
    existing = live.record(kind, host, [old, new])
    count = len(live.writes)
    live.provider._apply(Plan(existing.zone, existing.zone, [Delete(existing)], True))
    assert live.writes[count:] == ['dns/delete-record']
    assert live.rows()[str(inactive['id'])] == inactive
    inactive_only = live.record(kind, host, [new])
    live.assert_guard(Delete(inactive_only), 'Delete matched no active API rows')
    live.assert_guard(Update(inactive_only, live.record(kind, host, [old])),
                      'Update removals matched no active API rows')
