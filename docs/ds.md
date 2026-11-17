# DS records (0.1.0)

Requires Python >=3.10 and octoDNS >=1.22.0. This feature is developed as
`0.1.0.dev0`; install the main development branch for evaluation.
The maintenance line also provides DS support starting with 0.0.20. No 0.1.0
release is published by this change.

DS records are stored in a **hosted parent DNS zone**, delegating to a signed
child zone. The provider does not enable DNSSEC signing, generate DNSSEC keys,
or publish DS records through the domain registrar API.

Use the usual `octodns_cloudns.ClouDNSProvider` configuration and place this
in the YAML zone file for `example.com.`:

```yaml
child:
  - type: NS
    ttl: 3600
    values:
      - ns1.example.net.
      - ns2.example.net.
  - type: DS
    ttl: 3600
    values:
      - key_tag: 12345
        algorithm: 13
        digest_type: 2
        digest: abababababababababababababababababababababababababababababababab
      - key_tag: 23456
        algorithm: 13
        digest_type: 2
        digest: cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
```

The digests are illustrative. Replace all four fields with the child's actual
DS data. `child` means `child.example.com.`; an empty name means the zone apex.
A machine-readable copy is in [ds-example.yaml](ds-example.yaml).

ClouDNS requires an active NS delegation at the same owner name as each DS
record. Apex NS records do not satisfy a child delegation. The provider creates
NS before DS, deletes DS before NS, and adds replacement NS values before
removing old values. A missing delegation or removal of the last active NS while
DS records remain is rejected before any plan writes. Inactive DS rows are
preserved; remove them manually before removing their NS delegation.

ClouDNS `key_tag`, `algorithm`, `digest_type` and `record` map respectively to
octoDNS `key_tag`, `algorithm`, `digest_type` and `digest`. Numeric strings are
converted to integers, and hexadecimal digest case is normalized. Comparison
uses a tuple of all four fields; it never compares a structured value with a
raw API string. Invalid active DS rows fail safely, even during lenient planning.

Equal values retain their record IDs. Changed values use `dns/mod-record` on
remaining IDs, surplus values use `dns/add-record`, and obsolete rows use
`dns/delete-record`. Adds run before modifications and deletions. TTL changes
modify each affected row without recreating it; values and TTL may change in
the same run. Duplicate active rows and inconsistent row TTLs are repaired when
the name/type is managed. Other names and types remain outside the DS operation
bucket. Existing, desired and cached API rows are not mutated by reconciliation.

Inactive DS rows are excluded from the published set and preserved. Desiring
that value creates a separate active row; it does not reactivate the inactive
row. GeoDNS DS rows fail safely. `mod-record` sends the full DS value and TTL,
while omitting status, notes and failover fields to preserve server metadata.
The existing TTL metadata probes support omission semantics; DS value changes
and DS metadata are covered by synthetic mock HTTP responses. Guarded live
delegation tests are available in `tests/test_live_ds.py`; they require explicit
`CLOUDNS_DS_TEST=1`, test-zone and sub-user credential environment variables.
On 2026-11-17, Python 3.12.14 / octoDNS 1.22.0 passed both delegation live tests
on 1wpvsox.com. All four original API rows were unchanged and temporary rows
were removed.

For a staged rollover, first add the new DS alongside the old DS. Keep both
until the DNSSEC rollover procedure and cache expiry permit removal, then
remove the old DS from YAML. A single-value replacement modifies the existing
ID; the provider does not infer DNSSEC rollover timing or validate child keys.

Offline tests cover codec validation, CRUD, multiple values, ID retention,
TTL drift, API failures, shared desired state and plan/apply/plan convergence.
There is no transaction rollback. On an error the cache is cleared, the error
propagates, and writes are not blindly retried. Start a fresh plan to reconcile
partial or ambiguous outcomes.

References: [ClouDNS add-record](https://www.cloudns.net/wiki/article/58/),
[mod-record](https://www.cloudns.net/wiki/article/60/),
[octoDNS DS model](https://github.com/octodns/octodns/blob/main/octodns/record/ds.py),
[DS scope #14](https://github.com/ClouDNS/octodns_cloudns/issues/14),
[0.1.0 roadmap #25](https://github.com/ClouDNS/octodns_cloudns/issues/25).
