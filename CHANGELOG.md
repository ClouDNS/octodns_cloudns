# Changelog

## 0.1.0 — unreleased

- Add DS support for hosted DNS zones with structured value conversion, multiple
  values, ID-preserving CRUD and simultaneous TTL/value updates. Repair duplicate
  active DS rows and inconsistent TTLs; preserve inactive rows and metadata.
- Validate DS operations before any plan writes, propagate API errors, invalidate
  the cache on failure, and avoid mutating shared desired/existing records.
- Require Python >=3.10 and octoDNS >=1.22.0 as agreed in #25. Add minimum-version
  and current-version CI checks, offline DS regression tests and YAML docs (#14).
- Mark this feature branch as 0.1.0.dev0; DS is not part of the 0.0.19 patch.
  Existing non-DS reconciliation limitations below remain until the #25 rewrite.

## 0.0.18 — 2026-10-11

- Apply TTL-only changes with `dns/mod-record` for every API row of the managed
  name/type, including structured record types. Preserve IDs and raw value fields;
  do not delete or recreate rows for a TTL-only change.
- Validate TTL-only operations before any plan writes, fail on zero operations,
  and clear cached records after successful or failed applies.
- Avoid mutating desired records during legacy value updates. CNAME, ALIAS and
  DNAME value updates use `mod-record` instead of crashing on a missing `values`.
- Send form-encoded POST requests with bounded timeouts. Remove credential-bearing
  URL logging, the unused Bearer header, response-body logging and import-time
  logging configuration. Do not retry ambiguous writes automatically.
- Propagate API read errors except the explicit missing-domain response. Treat
  an empty list as an existing empty zone. Explicitly request record notes with
  `include-notes=1`, and recognize the live API response field `note`.
- Remove the exposed credential example and fixed account/domain defaults from
  integration tests. Integration requires explicit opt-in and environment values;
  CI unit tests have network access disabled.
- Keep the existing Python and octoDNS dependency floors. The floor bump belongs
  to 0.1.0.

### Known limits and release gates

- A change affecting both TTL and values is rejected before plan writes. Apply
  value changes and TTL changes in separate runs until 0.1.0.
- TTL-only changes preserve inactive status, record notes and failover settings.
  GeoDNS rows remain rejected. Single-value changes still reject inactive, noted
  or monitored rows because metadata preservation during value changes was not
  tested. GeoDNS is not repaired by this release.
  Live GeoDNS probes confirmed that omitting the location from `mod-record`
  resets regional rows to DEFAULT or rejects CNAME writes. Explicit locations
  preserve fields, but the existing GeoDNS read/create mapping still needs repair.
- The legacy multi-value update/delete path still has known matching and removal
  defects, notably CAA/LOC/TLSA and structured values; these remain tracked in #25.
  An explicit failure does not make that legacy path fully convergent.
- Existing per-client rate limiting remains unchanged; shared-IP limiting belongs
  to 0.1.0. There is no transactional rollback after a partial API failure.
- Live TTL read-back passed for all 16 supported static record types on an
  isolated test zone on 2026-10-11, including SSHFP/LOC write-field names. See
  `docs/live-validation-0.0.18.md` for scope and limitations. Unit fixtures remain
  synthetic; they are not claimed to be captured live responses.
- Removing a public credential does not revoke it. Confirm rotation/revocation
  with its owner separately (issue #23).
