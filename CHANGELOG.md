# Changelog

## 0.0.19 — unreleased

- Fix escaped TXT value removal during updates: normalize octoDNS's escaped
  semicolons before comparing obsolete values with raw API rows (PR #32).
- Fix obsolete MX and SRV value removal during updates using their complete
  structured matchers. Preserve retained values and isolate matching by name,
  type and every MX/SRV value field. Keep the legacy behavior for other types,
  including NAPTR's partial matcher (PR #44).
- Preserve the Python >=3.6, octoDNS >=0.9.17 and requests >=2.27.0 dependency
  floors from 0.0.18. DS support and the 0.1.0 rewrite are not included.

### Release gates

- This branch is not ready to tag or publish. Integrate istr's focused #25 D7
  guards and regression tests for zero-match deletes and unsupported TLSA
  update/delete operations before release; they are not implemented here.
- Verify #25 D8's inactive-row preservation boundary, including full-name/type
  deletion. The inherited legacy delete path does not enforce that boundary.
- Run the compatibility matrix, check wheel/sdist metadata, and validate writes
  with read-back and an empty second plan in an explicitly configured isolated
  test zone. No live DNS validation has been performed for this release yet.
- Value changes can now delete obsolete TXT/MX/SRV rows that older versions
  left behind. Review plans before applying. Existing legacy limitations below,
  including partial-apply risks and simultaneous TTL/value rejection, remain.

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
