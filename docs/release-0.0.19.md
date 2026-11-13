# 0.0.19 preparation and validation

Status: **unreleased; D7 guards and inactive-row deletion protection implemented**.
Prepared on 2026-11-12. Live validation completed on 2026-11-13; see
[live-validation-0.0.19.md](live-validation-0.0.19.md).

## Source and scope

Base: v0.0.18, `869f7a4a6b049a2cb985fd86fdefd197538c0fc5`.

Backported with upstream commit references; original contributors are credited:

- `184aa605460e4ba37caaeffd2f41eb739dc98bd7`: escaped TXT removal, PR #32.
- `35a845af2de692c5064e5db9305a4f29eaf87904`: MX/SRV removal, PR #44.
- `5be407816a2a1cb896070c1cb3d65f1c5578d6cc`: constrain structured deletion
  matching to MX/SRV and preserve the NAPTR boundary, PR #44.

Both MX/SRV commits are required. No DS code, 0.1.0 dependency changes, or the
0.0.18-specific publication workflow/script are included. The package metadata
continues to require Python >=3.6, octoDNS >=0.9.17 and requests >=2.27.0.

Additional tests exercise MX/SRV plan/apply/read-back through a synthetic HTTP
API, retain unchanged rows, check desired-state immutability, and require an
empty second plan. New backported mock assertions use tuple indexing so they do
not require Python 3.8's call_args.args/kwargs properties.

After confirming that istr's public branches contained no D7 implementation,
the maintainer authorized implementation here. Deletes without active matches
now raise ProviderException, and unsupported TLSA value updates/deletes produce
an explicit diagnostic. The existing TLSA TTL-only path remains supported.
Legacy value updates validate every obsolete value before deleting or creating
anything, including when other removals match or additions would succeed. The
guards run across the plan before zone creation or other writes, and are also
enforced on direct _apply_update/_apply_delete calls.

Value removals and full-name/type deletes preserve inactive rows (status 0 or
"0"), deduplicate IDs, and reject invalid active-row IDs/statuses. An inactive-only
match is a loud failure, not a successful no-op. No purge option was added.
Regression tests cover partial matches, the replace-all fallback, state
immutability, cache cleanup, and API error propagation without retry.

## Local verification

All runs used `python -m pytest tests/ --disable-network -q`. This matrix
records the guard implementation before adding the nine opted-in live cases.

| Python | octoDNS | Passed | Skipped |
| --- | --- | --- | --- |
| 3.8.20 | 0.9.17 | 190 | 32 |
| 3.8.20 | 1.10.0 | 198 | 24 |
| 3.10.22 | 1.3.0 | 198 | 24 |
| 3.10.22 | 1.22.0 | 198 | 24 |
| 3.12.14 | 1.22.0 | 198 | 24 |

The Python 3.8 / octoDNS 0.9.17 run also passed with requests pinned to its
minimum 2.27.0. Skips are opt-in live/integration tests and record types missing
from older octoDNS versions. Python 3.6 was not executed; its metadata floor is
preserved, not newly certified by these runs.

CI uses Ubuntu 22.04 to retain Python 3.8 availability. The initial remote run
on ubuntu-latest failed during setup-python because that label now selected
Ubuntu 26.04, for which Python 3.8 was unavailable; no test ran in that failure.

Wheel and sdist built successfully with `python -m build`; `twine check` passed
for both. These are preparation artifacts, not approved release artifacts.
The dependency metadata and packaged provider are checked separately.

## Live verification

All nine dedicated live checks passed on Python 3.12 / octoDNS 1.22.0, including
TXT/MX/SRV convergence, TLSA TTL-only and explicit value-operation errors,
zero-match/partial-removal preflight, and inactive-row preservation for four
types. The final run created and removed 19 temporary rows; all four baseline
rows remained unchanged. An initial cleanup HTTP 503 and its verified recovery
are documented in the live report. Current local offline verification is
198 passed, 33 skipped (the nine extra skips are the opted-in live module).

## Remaining release gates

1. Approve the final commit and rebuild/verify its artifacts before creating the
   tag, GitHub release, or PyPI publication. Never use main's publication script
   unchanged: it is pinned to 0.0.18 and that release's hashes.

Successful backports do not add transactional rollback, fix other structured
record matchers, or support simultaneous TTL/value changes. Errors can still
follow partial writes in legacy paths. Review production plans: obsolete
TXT/MX/SRV rows previously left behind can now be deleted.
The legacy populate path still exposes inactive values; inactive-aware read-side
convergence is outside this guard patch. Inactive-only removals therefore fail
and require operator review rather than deleting or reactivating those rows.
