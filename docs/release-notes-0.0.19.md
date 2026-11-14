0.0.19 is a focused patch release built from v0.0.18. It retains Python >=3.6,
octoDNS >=0.9.17 and requests >=2.27.0; DS support, dependency increases and the
reconciliation rewrite remain separate 0.1.0 work.

- Fix removal of escaped TXT values and obsolete MX/SRV values (PRs #32, #44).
- Fail explicitly on deletes without active matching API rows and unmatched
  value removals; preflight these guards before plan writes.
- Replace incidental TLSA value update/delete crashes with clear diagnostics.
  TLSA TTL-only updates remain supported; full TLSA value reconciliation is
  not added by this patch.
- Preserve inactive rows during value removals and full-name/type deletion.
  Inactive-only matches fail explicitly; no inactive-row purge option is added.
- Preserve shared desired records and dependency compatibility.

Validation: all five compatibility configurations passed. Nine live checks
passed against an isolated master zone, verifying API read-back, empty second
plans for supported updates, guard preflight and inactive preservation. All 19
temporary rows from the successful final run were removed, and all four original
rows remained unchanged. An initial cleanup HTTP 503 was recovered by explicit
read-back and cleanup; the complete rerun passed.

Limits: other legacy value matchers, GeoDNS reconciliation, inactive-aware
populate, combined TTL/value changes and transactional rollback remain outside
this patch. Issue #25 stays open for the 0.1.0 work.

See [the live validation report](https://github.com/ClouDNS/octodns_cloudns/blob/v0.0.19/docs/live-validation-0.0.19.md)
and [the changelog](https://github.com/ClouDNS/octodns_cloudns/blob/v0.0.19/CHANGELOG.md).
The publication workflow verifies GitHub/PyPI package hashes and installation
from PyPI. Original contributors to the TXT and MX/SRV fixes are credited in
PRs #32 and #44 and the release preparation history.
