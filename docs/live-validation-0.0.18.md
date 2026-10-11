# Live validation for 0.0.18

Performed on 2026-10-11 against a user-provided isolated ClouDNS master zone,
using a dedicated API sub-user. Python 3.12 and octoDNS 1.22.0 were used with
PR #28's implementation. No account credentials are included in this report.

## Static type read-back

A temporary record with a unique name was created for each of these types:
A, AAAA, ALIAS, CNAME, DNAME, NS, PTR, TXT, SPF, MX, SRV, SSHFP, CAA, NAPTR,
TLSA and LOC. TTL 300 and 3600 were confirmed to be allowed by the account.

Each record was read back, converted into an octoDNS record, and passed through
`ClouDNSProvider._apply_update()` as a TTL-only change from 300 to 3600. The API
row was then read back again. All 16 checks passed: TTL became 3600, and every
other returned field compared equal, including the record ID and raw value
fields. Each temporary record was deleted in a `finally` block.

The checks confirmed SSHFP's `fptype` write parameter and `fp_type` read field,
and LOC's dashed write parameters and underscored read fields. TXT included
`&`, `+`, `%`, `#`, `;` and a trailing dot; the raw API value survived unchanged.

After cleanup, the four pre-existing rows matched the initial snapshot exactly,
and no temporary records remained.

## End-to-end plan/apply

Two temporary A records with distinct values were created at the same unique
name with TTL 300. The desired zone included every existing managed record and
changed only this RRset's TTL to 3600. The initial plan contained exactly one
Update and sent no write requests. Applying it sent two `dns/mod-record` calls,
with no add/delete calls and no mutation of the desired record. Both API record
IDs remained present with TTL 3600. A fresh plan then returned no changes.

Both temporary rows were deleted. All pre-existing API rows again matched the
initial snapshot exactly.

## Existing integration suite

All four gated tests in `TestClouDNSIntegration` passed with the same sub-user:
invalid TTL rejection, valid create/delete, TTL modification with ID/value/metadata
read-back, and a missing-domain error. TTL 120 was absent from this account's
allowed TTL list and was rejected as expected.

Offline verification on the same implementation: 86 tests passed and the four
integration tests were skipped when not explicitly enabled. The five existing
GitHub CI matrix jobs were green before this documentation-only update.

## Scope limits

The original type sweep used active, static records with default metadata.
Additional metadata probes verified inactive status, notes and failover
preservation during TTL-only modifications. GeoDNS was not tested and remains
rejected. Single-value changes retain their metadata guards; TTL-only probes do
not establish preservation semantics for changing values.

NS was tested at a temporary child name, leaving the zone's root NS records
untouched. ALIAS was also tested at a temporary child name, which ClouDNS accepts;
the octoDNS conversion used `lenient=True` because octoDNS restricts ALIAS to the
zone root. This validates the modification fields, not root ALIAS planning.
Root NS and root ALIAS TTL row selection are covered by offline tests.

The existing unit fixtures are synthetic. This report records live assertions,
not captured production data or a claim to repair the legacy value reconciliation
path. Combined TTL/value changes and the limitations documented in CHANGELOG.md
remain unchanged.

## Reproducing metadata checks

`tests/test_live_metadata.py` provides 14 opt-in checks: all seven non-empty
combinations of inactive status, notes and failover for both A and AAAA records.
The test account needs an isolated master zone, record-note access and at least
one available failover check. It uses Ping monitoring with both event handlers
set to monitoring-only, a one-hour check period and notifications disabled.

Set `CLOUDNS_METADATA_TEST=1`, `CLOUDNS_TEST_DOMAIN`, `CLOUDNS_AUTH_PASSWORD` and
`CLOUDNS_SUB_AUTH_ID` (or `CLOUDNS_AUTH_ID`) in the process environment, then run:

```sh
python -m pytest tests/test_live_metadata.py -q
```

Do not pass `--disable-network` to explicitly enabled live checks. Ordinary CI
uses that flag and skips all integration checks. The live test only modifies
uniquely named rows it creates, deactivates any temporary failover check before
record deletion, and asserts that the complete initial row snapshot is restored.
The instantaneous monitoring `status` is excluded from the settings comparison;
all returned configuration fields, including monitoring `state`, must match.
GeoDNS and automatic failover event execution are outside these tests.
