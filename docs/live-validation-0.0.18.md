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

## Metadata follow-up

All fourteen distinct provider-path combinations below achieved a successful
result across the initial run and targeted reruns on 2026-10-11:

| Inactive | Note | Failover | A | AAAA |
| --- | --- | --- | --- | --- |
| No | No | Yes | Passed | Passed |
| No | Yes | No | Passed | Passed |
| No | Yes | Yes | Passed | Passed |
| Yes | No | No | Passed | Passed |
| Yes | No | Yes | Passed on rerun | Passed |
| Yes | Yes | No | Passed | Passed |
| Yes | Yes | Yes | Passed | Passed |

Each test used `ClouDNSProvider._apply_update()` to change TTL 300 to 3600.
All returned record fields other than TTL had to remain equal. Notes included
Cyrillic, special characters and a newline and were also compared through the
separate get-record-note endpoint. Failover configuration and monitoring state
were compared through failover-settings; only the instantaneous monitoring
outcome was excluded. No notifications or automatic DNS event handlers were
enabled.

The API returns record notes under the singular `note` key. Record listing now
explicitly requests `include-notes=1`, and the value-update guard recognizes both
`note` and the legacy synthetic `notes` spelling.

Early failover setup attempts returned a quota limit of 0. Later activation
succeeded, allowing the complete combination matrix to be exercised.

One initial provider test for an inactive A record with failover failed. Its
original diagnostic was not retained when that run was interrupted, so the cause
remains unknown. The same case passed two independent fresh-record reruns with
no reproduced metadata change. The final targeted run, covering that case and
the four unfinished combinations, passed all five tests and saved a JUnit report.
The initial matrix run therefore had an unclassified failure; this report records
the successful outcomes across runs and retains that uncertainty for review.

Cleanup restored the four original rows after the API probe sweep and after each
completed provider test. One temporary row/check from the interrupted run was
explicitly cleaned up before rerunning. No temporary records or checks remain.

Offline verification of the final implementation: 140 passed, 18 opted-in live
checks skipped. All five CI matrix configurations passed.

## GeoDNS follow-up

On 2026-10-11, a separate dedicated sub-user was used with a user-provided
GeoDNS-capable zone containing 30 existing records. Only collision-checked UUID
names were created or modified; no existing record IDs were eligible for writes.
The final run of `tests/test_live_geo.py` passed all six parameterized cases,
covering 24 temporary records across DEFAULT, EUR, BG and US-1 (default,
continent, country and subregion).

Records were created using `geodns-code`. Two modification paths were probed:
TTL 300 to 3600 without a location parameter, then TTL back to 300 with the
original numeric `geodns-location` explicitly supplied. Both TTLs were checked
against the account's available TTL list before creation.

| Type | Regional rows when location is omitted | Explicit location, all four rows |
| --- | --- | --- |
| A | All three move to DEFAULT | All non-TTL fields preserved |
| AAAA | All three move to DEFAULT | All non-TTL fields preserved |
| ALIAS | All three move to DEFAULT | All non-TTL fields preserved |
| CNAME | All three rejected; rows unchanged | All non-TTL fields preserved |
| SRV | All three move to DEFAULT | All non-TTL fields preserved |
| NAPTR | All three move to DEFAULT | All non-TTL fields preserved |

The DEFAULT row accepted the location-omitting modification for every type.
The three CNAME regional writes returned `There is another record for the same
host.` Successful location-omitting writes preserved IDs and value fields, but
changed the location ID, name and code to DEFAULT. The explicit-location path
preserved every returned non-TTL field, including structured SRV/NAPTR values.

For each type, a TTL-only provider update against cached test rows was rejected
before any write; read-back confirmed the rows were unchanged by that attempt.
Six additional offline regressions verify that DEFAULT and regional GeoDNS rows
block an entire plan before an unrelated Create can run.

These results justify retaining the GeoDNS guard in 0.0.18. Passing the original
location explicitly is necessary for safe API modification. It does not repair
the provider's existing model: offline reproduction confirmed that populate
flattens different locations into a static RRset, and the GeoDNS create serializer
uses default values instead of location-specific values. Location mapping and
complete read/plan/apply convergence belong to 0.1.0.

An initial probe selected unsupported TTL 7200 and was corrected. A subsequent
run encountered API read timeouts, including an ambiguous deletion response;
four remaining temporary A rows were reconciled by read-back and removed before
the final run. No automatic retry of an ambiguous write was used. The test now
checks allowed TTLs, uses a 60-second read timeout only for live probes, recovers
ambiguous creates by their collision-checked UUID names, and reports baseline
differences by ID rather than exposing unrelated zone contents.

The final six-case run passed in 753 seconds and saved a JUnit report. After each
case, all 30 original rows matched the initial snapshot exactly and no temporary
rows remained. This is API control-plane validation, not geographically distributed
DNS response testing or a claim that GeoDNS synchronization is implemented.

To reproduce, set `CLOUDNS_GEO_TEST=1`, `CLOUDNS_GEO_TEST_DOMAIN`,
`CLOUDNS_SUB_AUTH_ID` and `CLOUDNS_AUTH_PASSWORD`, then run:

```sh
python -m pytest tests/test_live_geo.py -x -vv -s --tb=short
```

The probe intentionally demonstrates location-omission behavior on its own rows
before restoring their locations and deleting them. ALIAS uses a child name and
lenient octoDNS conversion to avoid any change to root records.

Latest offline verification: 146 passed, 24 opted-in live checks skipped.

## Scope limits

The original type sweep used active, static records with default metadata.
Additional metadata probes verified inactive status, notes and failover
preservation during TTL-only modifications. GeoDNS API behavior was tested as
described above; provider updates remain rejected. Single-value changes retain
their metadata guards; TTL-only probes do
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
GeoDNS is exercised separately by `tests/test_live_geo.py`. Automatic failover
event execution is outside these tests.
