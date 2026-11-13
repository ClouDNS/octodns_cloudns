# Live validation for 0.0.19

Performed on 2026-11-13 against the maintainer-provided isolated master zone
using its dedicated API sub-user. The provider implementation was
`c34bdac3118ea0ed857eef4fde7f1db3027937dd`, with Python 3.12.14 and octoDNS 1.22.0.
No authentication data or unrelated zone contents are included in this report.

## Final result

`tests/test_live_0019.py`: **9 passed in 111.95 seconds**.

| Checks | Cases | Result |
| --- | --- | --- |
| TXT, MX and SRV value updates | 3 | Old value removed, replacement created, retained row and desired state unchanged, empty second plan |
| TLSA TTL and unsupported value paths | 1 | TTL 300 to 3600 used mod-record and preserved ID/all other fields; empty second plan; value update/delete rejected before any write |
| Missing delete and partial removal | 1 | Clear errors before an earlier Create could run; zone contents unchanged |
| Active/inactive deletion boundary for A, TXT, MX and SRV | 4 | Only active row deleted; inactive row remained exactly unchanged; inactive-only delete/update rejected before writes |

The TXT case includes semicolons and `&`, `+`, `%`, `#`. MX values share an
exchange but differ in preference; SRV values share a target but differ in port.
Each positive value update issued exactly one delete and one add, preserving
the retained row's ID and all its returned fields. Planning issued no writes.
The TLSA TTL-only case issued exactly one mod-record, with no add/delete.

The final run created 19 distinct temporary API rows across nine collision-checked
UUID namespaces. Each case restored its initial snapshot. An independent final
API read compared equal to all nine recovery snapshots: all four original rows
were unchanged, and no temporary rows remained.

## Safety and a recovered API failure

The harness rejects writes outside the exact zone, reserved temporary names,
and temporary IDs. Baseline IDs can never be written. Unknown endpoints,
including zone creation/deletion, are rejected. Direct guard tests put a Create
before the failing operation to verify plan preflight prevents partial writes.

An initial run passed the TXT update/read-back/empty-plan check, then received
HTTP 503 during cleanup and stopped. Read-back confirmed one temporary TXT row
remained. Its exact UUID name, type and ID were checked before an explicit
cleanup attempt; subsequent read-back confirmed removal, four remaining original
rows, and no change to any other row. This was a cleanup/API failure, not a
fully successful initial test run.

The harness now writes mode-0600 recovery checkpoints in the local temporary
directory, containing reserved names/IDs and baseline rows, without credentials.
They are neither committed nor included in this report. Cleanup discovers own
rows by reserved names even if a create response is lost. An ambiguous delete
is never blindly repeated: read-back must establish absence or the test fails
and leaves the checkpoint for explicit recovery. Only idempotent reads have
bounded retries in the harness. The provider's write retry behavior is unchanged.

The subsequent complete nine-case run passed, including every cleanup check.

## Reproduction

Set `CLOUDNS_0019_TEST=1`, `CLOUDNS_TEST_DOMAIN`, `CLOUDNS_SUB_AUTH_ID` and
`CLOUDNS_AUTH_PASSWORD` for a dedicated isolated master zone, then run:

```sh
python -m pytest tests/test_live_0019.py -x -vv --tb=short
```

Do not use `--disable-network` for explicitly authorized live checks. Ordinary
CI leaves this opt-in disabled and skips all nine cases. No credential is
embedded in the test module.

## Scope limits

These are API control-plane assertions, not authoritative-DNS propagation or
GeoDNS tests. They validate the agreed 0.0.19 guards and TXT/MX/SRV backports,
not the complete #25 reconciliation rewrite. TLSA value update/delete remain
unsupported with a clear diagnostic. Other legacy matchers and simultaneous
TTL/value limitations remain documented in CHANGELOG.md.

Inactive values remain visible to the legacy populate path. Therefore an
inactive-only removal fails explicitly and requires operator review; an empty
second plan is asserted for successful active TXT/MX/SRV and TLSA TTL updates,
not claimed for inactive-only removal. Offline tests additionally cover the
old replace-all fallback, duplicate IDs and invalid IDs/statuses.

After adding the opt-in module, the local offline run passed 198 tests with
33 skipped on Python 3.12 / octoDNS 1.22.0. No provider implementation change
was needed as a result of the live validation.
