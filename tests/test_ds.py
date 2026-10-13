"""Synthetic DS API fixtures; all requests are intercepted, never live DNS."""

from copy import deepcopy
from unittest.mock import Mock
from urllib.parse import parse_qs

import pytest
from octodns.provider import ProviderException
from octodns.record import Record, Update
from octodns.zone import Zone

from octodns_cloudns import ClouDNSClient, ClouDNSClientException, ClouDNSProvider
from octodns_cloudns.ds import DsCodec, operations


V1 = dict(key_tag=12345, algorithm=13, digest_type=2, digest="ab" * 32)
V2 = dict(key_tag=23456, algorithm=13, digest_type=2, digest="cd" * 32)
V3 = dict(key_tag=34567, algorithm=8, digest_type=2, digest="ef" * 32)


def record(values=(V1,), ttl=300, name="child", zone=None):
    return Record.new(
        zone or Zone("example.com.", []),
        name,
        dict(type="DS", ttl=ttl, values=deepcopy(values)),
    )


def row(value=V1, record_id="1", ttl=300, name="child", **metadata):
    return dict(
        id=record_id,
        host=name,
        type="DS",
        ttl=str(ttl),
        status=1,
        key_tag=str(value["key_tag"]),
        algorithm=str(value["algorithm"]),
        digest_type=str(value["digest_type"]),
        record=value["digest"].upper(),
        **metadata,
    )


@pytest.mark.parametrize(
    "value",
    [
        V1,
        V2,
        V3,
        dict(V1, digest_type=1, digest="12" * 20),
        dict(V1, digest_type=4, digest="12" * 48),
    ],
)
def test_codec_roundtrip(value):
    api = row(value)
    before = deepcopy(api)
    assert DsCodec.from_row(api) == value
    assert DsCodec.fields(record([value]).values[0]) == {
        "key_tag": value["key_tag"],
        "algorithm": value["algorithm"],
        "digest_type": value["digest_type"],
        "record": value["digest"],
    }
    assert api == before


@pytest.mark.parametrize(
    "field,bad",
    [
        ("key_tag", "-1"),
        ("key_tag", "65536"),
        ("algorithm", "256"),
        ("algorithm", "invalid"),
        ("digest_type", "-1"),
        ("record", "GG" * 32),
        ("record", "ab"),
        ("record", None),
        ("record", "abc"),
    ],
)
def test_invalid_rows_fail(field, bad):
    api = row()
    api[field] = bad
    with pytest.raises(ProviderException, match="DS value"):
        DsCodec.from_row(api)


def test_missing_field_fails():
    api = row()
    del api["key_tag"]
    with pytest.raises(ProviderException):
        DsCodec.from_row(api)


def test_structured_comparison_and_id_fallback():
    api = row(note="operator note", failover="0")
    del api["id"]
    rows = {"listing-id": api, "other": row(V2, "other", name="other")}
    before = deepcopy(rows)
    assert operations(rows, record()) == []
    assert operations(rows, record(ttl=3600)) == [
        ("mod", "listing-id", DsCodec.fields(V1))
    ]
    assert rows == before


def test_rollover_retains_equal_ids_and_updates_replacement():
    rows = {"1": row(), "2": row(V2, "2")}
    assert operations(rows, record([V1, V3], ttl=3600)) == [
        ("mod", "1", DsCodec.fields(V1)),
        ("mod", "2", DsCodec.fields(V3)),
    ]
    assert operations(rows, record([V1, V2, V3])) == [("add", None, DsCodec.fields(V3))]
    assert operations(rows, record([V2])) == [("delete", "1", None)]


def test_inactive_rows_are_preserved_and_not_populated():
    provider = ClouDNSProvider("test", "id", "password")
    inactive = row(V2, "2")
    inactive["status"] = 0
    rows = {"1": row(), "2": inactive}
    provider._zone_records["example.com."] = rows
    zone = Zone("example.com.", [])
    provider.populate(zone)
    assert next(iter(zone.get("child", "DS"))).values == record().values
    assert operations(rows, record(), deleting=True) == [("delete", "1", None)]


def test_preflight_does_not_partially_write():
    provider = ClouDNSProvider("test", "id", "password")
    provider._client = Mock(spec=ClouDNSClient)
    provider._zone_records["example.com."] = {
        "1": row(),
        "2": dict(row(V2, "2"), record="bad"),
    }
    with pytest.raises(ProviderException):
        provider._apply_ds(Update(record(), record([V3])))
    assert provider._client.mock_calls == []


def test_geodns_rejected_before_write():
    with pytest.raises(ProviderException, match="GeoDNS"):
        operations({"1": row(**{"geodns-location": "5"})}, record())


class Api:
    def __init__(self, requests_mock, rows):
        self.rows = deepcopy(rows)
        self.writes = []
        self.next_id = 100
        self.fail = None
        self.read_error = False
        self.ambiguous_add = False
        for endpoint in [
            "records",
            "get-zone-info",
            "add-record",
            "mod-record",
            "delete-record",
        ]:
            requests_mock.post(
                f"https://api.cloudns.net/dns/{endpoint}.json", json=self.request
            )

    def request(self, request, context):
        endpoint = request.path.split("/")[-1].removesuffix(".json")
        body = {
            k: v[0] for k, v in parse_qs(request.text, keep_blank_values=True).items()
        }
        assert body.pop("auth-id") == "fake-id"
        assert body.pop("auth-password") == "fake-password"
        assert body.pop("domain-name") == "example.com"
        if endpoint == "records":
            if self.read_error:
                return {"status": "Failed", "statusDescription": "Access denied"}
            assert body == {"include-notes": "1"}
            return deepcopy(self.rows) or []
        if endpoint == "get-zone-info":
            return {"status": "Success"}
        self.writes.append((endpoint, deepcopy(body)))
        if endpoint == self.fail:
            return {"status": "Failed", "statusDescription": "Synthetic failure"}
        if endpoint == "delete-record":
            del self.rows[body["record-id"]]
        elif endpoint == "mod-record":
            record_id = body.pop("record-id")
            self.rows[record_id].update(body)
        else:
            assert body.pop("record-type") == "DS"
            record_id = str(self.next_id)
            self.next_id += 1
            self.rows[record_id] = dict(body, id=record_id, type="DS")
            if self.ambiguous_add:
                from requests import Timeout

                raise Timeout("Synthetic lost response after successful write")
        return {"status": "Success"}


def provider():
    result = ClouDNSProvider("test", "fake-id", "fake-password")
    result._client._calls_interval = 0
    return result


def desired(values=(V1,), ttl=300):
    zone = Zone("example.com.", [])
    if values:
        zone.add_record(record(values, ttl, zone=zone))
    return zone


@pytest.mark.parametrize(
    "old,new,ttl,expected",
    [
        ([], [V1], 300, ["add-record"]),
        ([V1], [], 300, ["delete-record"]),
        ([V1], [V2], 300, ["mod-record"]),
        ([V1], [V1], 3600, ["mod-record"]),
        ([V1, V2], [V1, V2], 3600, ["mod-record", "mod-record"]),
        ([V1], [V1, V2], 300, ["add-record"]),
        ([V1, V2], [V2], 300, ["delete-record"]),
        ([V1, V2], [V1, V3], 3600, ["mod-record", "mod-record"]),
        ([V1], [V2, V3], 3600, ["add-record", "mod-record"]),
        ([V1, V2], [V3], 3600, ["mod-record", "delete-record"]),
        ([V1], [V1], 300, []),
    ],
)
def test_mock_http_plan_apply_plan(requests_mock, old, new, ttl, expected):
    rows = {str(i): row(v, str(i)) for i, v in enumerate(old, 1)}
    rows["unrelated"] = row(V3, "unrelated", name="other")
    rows["txt"] = dict(
        id="txt", host="child", type="TXT", ttl="300", record="unchanged", status=1
    )
    api = Api(requests_mock, rows)
    p = provider()
    zone = desired(new, ttl)
    # Include unrelated existing records in desired so the full zone sync keeps them.
    zone.add_record(record([V3], name="other", zone=zone))
    zone.add_record(
        Record.new(zone, "child", dict(type="TXT", ttl=300, value="unchanged"))
    )
    before = deepcopy([r.data for r in sorted(zone.records)])
    plan = p.plan(zone)
    if expected:
        assert plan is not None
        existing_before = deepcopy([r.data for r in sorted(plan.existing.records)])
        p.apply(plan)
        assert [r.data for r in sorted(plan.existing.records)] == existing_before
    else:
        assert plan is None
    assert [name for name, _ in api.writes] == expected
    assert api.rows["unrelated"] == rows["unrelated"]
    assert api.rows["txt"] == rows["txt"]
    assert [r.data for r in sorted(zone.records)] == before
    assert p.plan(zone) is None
    assert [name for name, _ in api.writes] == expected
    # The same desired objects are safe to share with a second target.
    assert provider().plan(zone) is None
    for i, v in enumerate(old, 1):
        if v in new:
            assert api.rows[str(i)]["record"].lower() == v["digest"]


def test_duplicate_and_mixed_ttl_drift_repaired(requests_mock):
    api = Api(
        requests_mock, {"1": row(), "2": row(V2, "2", ttl=3600), "3": row(V1, "3")}
    )
    p = provider()
    zone = desired([V1, V2])
    plan = p.plan(zone)
    assert len(plan.changes) == 1
    p.apply(plan)
    assert [op for op, _ in api.writes] == ["mod-record", "delete-record"]
    assert set(api.rows) == {"1", "2"}
    assert p.plan(zone) is None


def test_mod_preserves_supported_metadata(requests_mock):
    api = Api(requests_mock, {"1": row(note="operator note", failover="0")})
    p = provider()
    p.apply(p.plan(desired([V2], ttl=3600)))
    assert api.rows["1"]["note"] == "operator note"
    assert api.rows["1"]["status"] == 1
    assert api.rows["1"]["failover"] == "0"
    assert "note" not in api.writes[0][1]
    assert "status" not in api.writes[0][1]


@pytest.mark.parametrize(
    "endpoint,values",
    [("add-record", [V1, V2]), ("mod-record", [V2]), ("delete-record", [])],
)
def test_api_write_failure_propagates_and_clears_cache(requests_mock, endpoint, values):
    api = Api(requests_mock, {"1": row()})
    api.fail = endpoint
    p = provider()
    zone = desired(values)
    plan = p.plan(zone)
    before = deepcopy([r.data for r in plan.desired.records])
    with pytest.raises(ClouDNSClientException, match="Synthetic failure"):
        p.apply(plan)
    assert p._zone_records == {}
    assert [r.data for r in plan.desired.records] == before
    api.fail = None
    p.apply(p.plan(zone))
    assert p.plan(zone) is None


def test_read_failure_is_not_missing_zone(requests_mock):
    api = Api(requests_mock, {})
    api.read_error = True
    with pytest.raises(ClouDNSClientException, match="Access denied"):
        provider().plan(desired())
    assert api.writes == []


def test_ambiguous_add_is_not_retried_and_readback_converges(requests_mock):
    api = Api(requests_mock, {})
    api.ambiguous_add = True
    p = provider()
    zone = desired()
    with pytest.raises(ClouDNSClientException, match="Timeout"):
        p.apply(p.plan(zone))
    assert len(api.writes) == 1
    assert p._zone_records == {}
    assert p.plan(zone) is None


def test_yaml_documentation_example():
    from pathlib import Path
    import yaml

    data = yaml.safe_load(Path("docs/ds-example.yaml").read_text())
    assert len(Record.new(Zone("example.com.", []), "child", data["child"]).values) == 2


@pytest.mark.parametrize(
    "value",
    [
        dict(V1, key_tag=12346),
        dict(V1, algorithm=8),
        dict(V1, digest_type=4, digest="ab" * 48),
        dict(V1, digest="aa" * 32),
    ],
)
def test_comparison_uses_all_four_fields(value):
    assert operations({"1": row()}, record([value])) == [
        ("mod", "1", DsCodec.fields(value))
    ]


def test_client_ds_serialization():
    assert ClouDNSClient.fields_from_row(row()) == DsCodec.fields(V1)
    assert ClouDNSClient.fields_from_value("DS", record().values[0]) == DsCodec.fields(
        V1
    )


def test_create_with_matching_rows_does_not_duplicate(requests_mock):
    from octodns.record import Create

    api = Api(requests_mock, {"1": row()})
    p = provider()
    p._apply_create(Create(record()))
    assert api.writes == []


def test_partial_rollover_failure_recovers_without_duplicate_add(requests_mock):
    api = Api(requests_mock, {"1": row(note="keep")})
    api.fail = "mod-record"
    p = provider()
    zone = desired([V2, V3], ttl=3600)
    with pytest.raises(ClouDNSClientException):
        p.apply(p.plan(zone))
    assert [op for op, _ in api.writes] == ["add-record", "mod-record"]
    assert api.rows["1"]["record"].lower() == V1["digest"]
    api.fail = None
    p.apply(p.plan(zone))
    assert [op for op, _ in api.writes] == ["add-record", "mod-record", "mod-record"]
    assert api.rows["1"]["note"] == "keep"
    assert p.plan(zone) is None


def test_invalid_ds_preflights_entire_plan(requests_mock):
    from octodns.provider.plan import Plan
    from octodns.record import Create

    api = Api(requests_mock, {"1": dict(row(), record="not hex")})
    p = provider()
    existing = Zone("example.com.", [])
    zone = desired([V2])
    a = Record.new(zone, "a", dict(type="A", ttl=300, value="192.0.2.1"))
    plan = Plan(existing, zone, [Create(a), Update(record(), record([V2]))], True)
    with pytest.raises(ProviderException):
        p.apply(plan)
    assert api.writes == []
    assert p._zone_records == {}


@pytest.mark.parametrize("ttl", [None, "not a TTL"])
def test_invalid_row_ttl_fails_before_operations(ttl):
    api = row()
    api["ttl"] = ttl
    with pytest.raises(ProviderException, match="TTL"):
        operations({"1": api}, record(ttl=3600))
