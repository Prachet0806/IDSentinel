# IDSentinel Correctness Invariants

This document defines the formal correctness invariants that IDSentinel must uphold. Every implementation decision must be verified against these invariants.

---

## Invariant Definitions

| ID | Invariant | Enforcement Point | Status |
|----|-----------|-------------------|--------|
| **I1** | Invalid authoritative source → no reconciliation | `SourceValidator` + `CSVParser` header check | Implemented, tested |
| **I2** | Empty HR source → no reconciliation | `SourceValidator` (`allowEmpty=false`) | Implemented, tested |
| **I3** | Empty target → no reconciliation unless `--allow-empty-target` | `CLI` + `SourceValidator` | Implemented, tested |
| **I4** | Duplicate identity → no reconciliation | `SourceValidator` (`maxDuplicateRows=0`) | Implemented, tested |
| **I5** | Dry-run → zero persistent side effects | `CLI` (skips lock, `store.init()`, all writes) | Implemented, tested |
| **I6** | Invalid configuration → process refuses to start | `Config::loadConfig()` → `Result<Config>` | Implemented, tested |
| **I7** | Policy configuration determines finding severity | `Reconciler` constructor | Implemented, tested |
| **I8** | Evidence is immutable | `finding_evidence` + `trg_evidence_no_update/delete` | Implemented, tested |
| **I9** | Status changes are separately auditable | `finding_status` + `finding_status_history` + `trg_status_audit` | Implemented, tested |
| **I10** | Every successful run has verifiable completion | `completeRun()` checks `sqlite3_changes()`; run-not-found is an error | Implemented, tested |
| **I11** | Failed/abandoned runs cannot masquerade as successful | `RunStatus::Abandoned` for stale `RUNNING` on startup | Implemented, tested |
| **I12** | CI builds and executes actual test suite | `BUILD_TESTING=ON` + `ctest -C` matrix (Release/Debug × 3 OS) | Implemented |
| **I13** | Clean checkout produces reproducible dependency graph | Pinned baseline in `vcpkg.json`, `vcpkg-configuration.json`, workflows | Implemented |
| **I14** | Documented CLI behavior matches implementation | `README` + `test_cli.cpp` integration tests | Implemented, tested |

---

## Invariant Enforcement Rules

### Source Validation (I1-I4)
- **Schema**: Every source must have required columns (`id`, `name`, `department`); header rows map by name (order-independent), headerless sources parse positionally
- **Non-empty**: Both HR and target sources must contain at least one valid identity
- **No duplicates**: Duplicate `id` values fail validation by default (`maxDuplicateRows=0`, configurable)
- **Malformed threshold**: Configurable ratio of malformed rows allowed (default: 5%)
- **Size sanity**: Target/HR size ratio outside [0.1, 10.0] warns; optional min/max size bounds warn

### Configuration (I6)
- All config values validated at startup; `loadConfig()` returns `Result<Config>`
- Missing/invalid numeric values (timeout, sizes, retries) → hard error
- Malformed HMAC key → hard error (fail closed)
- Unknown enum strings (severity, log level/format) fall back to documented defaults (`MEDIUM`/`INFO`/`JSON`) — see known gap below

### Policy (I7)
- `PolicyConfig` from config/environment must be passed to `Reconciler`
- Severities covered: orphan, missing, and attribute-drift findings
- Severity mapping: `CRITICAL` > `HIGH` > `MEDIUM` > `LOW`

### Dry-Run (I5)
- `--dry-run` must skip ALL database initialization
- No lock acquisition, schema creation, directory creation, or file creation
- Only in-memory computation and logging

### Persistence (I8-I11)
- **Immutable evidence**: `finding_evidence` table with `BEFORE UPDATE/DELETE` guard triggers
- **Mutable status**: Separate `finding_status` table with full audit trail
- **Run lifecycle**: `RUNNING` → `SUCCESS` | `FAILED` | `ABANDONED`
- **Stale detection**: On startup, ANY `RUNNING` run (crashed predecessor) → `ABANDONED`
- **Completion proof**: `completeRun()` on a nonexistent run returns `RUN_NOT_FOUND`
- **Single writer**: Exclusive `<db>.lock` refuses concurrent runs

### Transport (supporting I1)
- Only HTTPS feed URLs are fetched; redirects restricted to HTTPS
- Responses beyond `max_response_mb` are rejected; transient failures retried with backoff
- Logged URLs are redacted (no userinfo, query, or fragment)

### CI/CD (I12-I13)
- `BUILD_TESTING=ON` in all CI builds
- vcpkg baseline pinned to specific commit SHA
- CMake toolchain file explicitly provided
- All tests executed in CI matrix

### Documentation (I14)
- Every CLI command in README must exist and work
- Configuration examples must match actual parser
- No documented feature that isn't implemented

---

## Known Gaps

- **I6 (enum fallback)**: unknown `severity`/`level`/`format` strings silently fall back to defaults instead of hard-erroring. Numeric, required, and HMAC-key values already fail closed. Tightening enums to hard errors is a deliberate follow-up (it changes `parseSeverity`/`parseLogLevel`/`parseLogFormat` contracts and their tests).

---

## Verification Checklist

Each PR must verify:

- [ ] All invariants still hold
- [ ] New code has corresponding tests
- [ ] CI passes on all platforms
- [ ] README updated for any user-facing changes
- [ ] No silent fallbacks for security/compliance inputs