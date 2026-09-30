# IDSentinel

**A Resilient, Audit-Ready Identity Reconciliation Engine (C++23)**

IDSentinel is a C++23 identity reconciliation engine that compares an **authoritative HR identity feed** against a **target system snapshot**, detects compliance gaps (orphan/missing accounts, attribute drift), and persists **immutable, audit-grade evidence** to a SQLite governance ledger.

---

## Features

* **Hybrid Connectivity** — Network-first HR feed ingestion (HTTPS-only via libcurl) with automatic local CSV fallback
* **Fail-Closed Validation** — Schema, emptiness, duplicate-ID, malformed-row (5%), and size-sanity checks gate every run
* **TLS Verification** — Certificate validation always on; redirects restricted to HTTPS; configurable CA bundle
* **Fetch Hardening** — Response size limit, retry with exponential backoff for transient failures, credential redaction in logs
* **HMAC-SHA256 Integrity** — Tamper-evident finding hashes with optional HMAC key (zeroized after use)
* **Audit-Grade Persistence** — Immutable `finding_evidence` + mutable `finding_status` with full transition history; stale runs marked ABANDONED
* **High Performance** — Streaming CSV ingestion, bulk insert for 100k+ identities, indexes on query paths
* **Policy-Driven** — Configurable severity levels (CRITICAL/HIGH/MEDIUM/LOW) for orphan, missing, and drift findings
* **Failure-Aware** — Invalid sources trigger hard stop; transaction rollback on any error; single-writer process lock
* **Structured Logging** — Escaped JSON or text output; file logging is opt-in, with rotation support (spdlog)
* **Modern CLI** — Subcommands: `reconcile`, `inspect`, `config`, `keygen` (CLI11)
* **TOML Configuration** — Hierarchical config with environment variable overrides
* **Cross-Platform** — Linux, macOS, Windows (vcpkg for dependencies)

---

## Project Layout

```
IDSentinel/
├── src/
│   ├── main.cpp                      # Entry point → CLI dispatch
│   ├── cli/CLI.{h,cpp}               # CLI11 subcommands
│   ├── config/Config.{h,cpp}         # TOML config + env overrides
│   ├── core/
│   │   ├── Identity.h                # Identity model
│   │   ├── Policy.{h,cpp}            # Enums: ViolationType, Severity, RunStatus, FindingStatus
│   │   ├── Result.h                  # Result<T, Error> (C++23 std::expected compatible)
│   │   ├── Logging.{h,cpp}           # spdlog wrapper (escaped JSON/text, rotation)
│   │   ├── ProcessLock.{h,cpp}       # Cross-process single-writer lock
│   │   ├── SourceValidator.{h,cpp}   # Fail-closed source validation
│   │   └── Reconciler.{h,cpp}        # Core reconciliation logic
│   ├── connectors/NetworkConnector.{h,cpp} # libcurl wrapper (HTTPS-only, retry, size limit)
│   ├── parsers/CSVParser.{h,cpp}     # CSV parsing (header mapping, streaming)
│   └── persistence/
│       ├── IViolationStore.h         # Write-path interface
│       ├── IComplianceStore.h        # Read-path (query) interface
│       └── ComplianceStore.{h,cpp}   # SQLite implementation (WAL, bulk, triggers)
├── tests/                            # Catch2 unit tests
├── data/
│   ├── hr_feed.csv                   # Mock HR feed
│   └── system_dump.csv               # Mock target system snapshot
├── config.toml                       # Default configuration
├── vcpkg.json                        # vcpkg manifest
├── CMakeLists.txt
└── Doxyfile                          # API documentation
```

---

## Build & Run

### Prerequisites

* CMake ≥ 3.25
* C++23 Compiler (GCC 13+, Clang 16+, MSVC 19.35+)
* vcpkg (for dependencies)

### Build (Out-of-Source)

```bash
# Bootstrap vcpkg (once)
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh  # or .bat on Windows

# Install dependencies from manifest
./vcpkg/vcpkg install --feature-flags=manifests

# Configure and build (manifest mode resolves dependencies automatically)
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release --parallel
```

Binary output: `build/bin/IDSentinel` (or `build/bin/Release/IDSentinel.exe` on Windows)

> **Note:** The vcpkg toolchain file is required. Debug builds need the
> corresponding debug triplets installed (`vcpkg install` fetches both by
> default); a Release-only `vcpkg_installed` tree can only link Release builds.

---

## Usage

### Quick Start

```bash
# Run reconciliation (uses config.toml defaults)
./build/bin/IDSentinel reconcile

# Dry-run: preview violations without writing to DB
./build/bin/IDSentinel reconcile --dry-run

# Inspect a specific run (paginated; run-not-found exits 1)
./build/bin/IDSentinel inspect --run-id RUN_abc123 --format json --limit 50 --offset 0

# Show current configuration
./build/bin/IDSentinel config

# Validate configuration
./build/bin/IDSentinel config --validate

# Generate HMAC key for integrity hashes
./build/bin/IDSentinel keygen
```

### Configuration

Create `config.toml` (search order: `--config` flag → `IDSENTINEL_CONFIG` env → `./config.toml` → `$XDG_CONFIG_HOME/idsentinel/config.toml` → platform-specific system paths):

```toml
[network]
hr_feed_url = "https://api.hr.example.com/feed"
timeout_seconds = 10
ca_bundle_path = ""  # empty = system store
max_response_mb = 10  # reject oversized responses (fail-closed)
max_retries = 3  # retries with exponential backoff for transient failures

[database]
path = ""  # empty = platform default (~/.local/share/idsentinel/compliance.db)
wal_mode = true
busy_timeout_ms = 5000

[policy]
orphan_severity = "CRITICAL"
missing_severity = "MEDIUM"
drift_severity = "HIGH"

[source]
max_file_age_hours = 0  # 0 = freshness check disabled; >0 rejects stale local files

[logging]
level = "info"
format = "json"
file = ""  # empty = console only (file logging is opt-in)
rotation = { max_size_mb = 10, max_files = 30, daily = true }

[security]
hmac_key = ""  # base64-encoded 32-byte key (generate with: idsentinel keygen)
```

### Environment Variable Overrides

Any config value can be overridden via `IDSENTINEL_<SECTION>__<KEY>` (double underscore = nested):

```bash
export IDSENTINEL_NETWORK__HR_FEED_URL="https://custom.hr/feed"
export IDSENTINEL_DATABASE__PATH="/var/lib/idsentinel/db.sqlite"
export IDSENTINEL_LOGGING__LEVEL="debug"
export IDSENTINEL_SECURITY__HMAC_KEY="$(idsentinel keygen)"
```

---

## Database Schema (Governance Ledger)

### `recon_runs` — Reconciliation executions
| Column | Description |
|--------|-------------|
| run_id | Unique run identifier (e.g., `RUN_1704652000_abc123`) |
| source_system | HR feed source |
| target_system | Target system |
| started_at | Start timestamp |
| completed_at | End timestamp |
| status | RUNNING / SUCCESS / FAILED / ABANDONED (stale RUNNING runs are abandoned on startup) |
| total_violations | Auto-maintained by trigger |

### `finding_evidence` — Immutable evidence (UPDATE/DELETE rejected by triggers)
| Column | Description |
|--------|-------------|
| finding_id | Primary key |
| run_id | FK → recon_runs |
| user_id | Identity ID |
| violation_type | ORPHAN_ACCOUNT / MISSING_ACCOUNT / ATTRIBUTE_DRIFT |
| severity | CRITICAL / HIGH / MEDIUM / LOW |
| detected_at | Timestamp |
| integrity_hash | HMAC-SHA256 or SHA-256 hash |

### `finding_status` — Mutable workflow state (one row per finding)
| Column | Description |
|--------|-------------|
| finding_id | PK/FK → finding_evidence |
| status | OPEN / REVIEW / REMEDIATED |
| updated_at | Timestamp |
| updated_by | Actor |

### `finding_status_history` — Status transition audit trail (trigger-maintained)
| Column | Description |
|--------|-------------|
| history_id | Primary key |
| finding_id | FK → finding_evidence |
| old_status / new_status | Transition |
| changed_at / changed_by | When and by whom |

### `violation_history` — Aggregated history (trigger-maintained)
| Column | Description |
|--------|-------------|
| user_id | Identity |
| violation_type | Risk type |
| first_detected | First occurrence |
| last_detected | Most recent |
| occurrence_count | Auto-incremented |

Indexes: `idx_evidence_run`, `idx_evidence_user`, `idx_evidence_type`, `idx_status_history_finding`

---

## Sample Output

```
$ idsentinel reconcile
{"timestamp":"2026-09-30T10:30:45.123+0530","level":"info","logger":"idsentinel","message":"Starting reconciliation run: RUN_0x2748a3f2_0x7f8b1c2d"}
{"timestamp":"2026-09-30T10:30:45.456+0530","level":"warning","logger":"idsentinel","message":"ORPHAN_ACCOUNT Detected: Evil Hacker (ID: 999)"}
{"timestamp":"2026-09-30T10:30:45.457+0530","level":"info","logger":"idsentinel","message":"Run RUN_0x2748a3f2_0x7f8b1c2d completed: 1 orphans, 0 missing, 0 drifted"}

$ idsentinel inspect --run-id RUN_0x2748a3f2_0x7f8b1c2d --format json
{
  "run_id": "RUN_0x2748a3f2_0x7f8b1c2d",
  "status": "SUCCESS",
  "total_violations": 1,
  "finding_count": 1,
  "limit": 100,
  "offset": 0,
  "findings": [
    {
      "finding_id": 1,
      "run_id": "RUN_0x2748a3f2_0x7f8b1c2d",
      "user_id": "999",
      "violation_type": "ORPHAN_ACCOUNT",
      "severity": "CRITICAL",
      "detected_at": "2026-09-29 10:30:45",
      "status": "OPEN",
      "integrity_hash": "a1b2c3d4..."
    }
  ]
}
```

---

## Security

* **HTTPS Only**: Non-HTTPS feed URLs are refused; redirects restricted to HTTPS
* **TLS Verification**: Always on (`CURLOPT_SSL_VERIFYPEER=1`, `CURLOPT_SSL_VERIFYHOST=2`); dev-only escape hatch via `IDSENTINEL_DEV_DISABLE_TLS=1` (never persist it)
* **CA Bundle**: Configure via `network.ca_bundle_path` or `IDSENTINEL_NETWORK__CA_BUNDLE_PATH`
* **Fetch Limits**: `network.max_response_mb` caps response size; `network.max_retries` bounds transient-failure retries
* **Log Hygiene**: URLs are redacted (no userinfo/query/fragment) before logging
* **Integrity Hashes**: HMAC-SHA256 when `security.hmac_key` is set (32-byte base64 key, zeroized after use); falls back to SHA-256 with warning
* **Key Generation**: `idsentinel keygen` outputs base64 key; or `openssl rand -base64 32`
* **Single Writer**: An exclusive lock file (`<db>.lock`) refuses concurrent runs

---

## Development

### Running Tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```
(`-C` is required on multi-config generators such as Visual Studio.)

### Code Quality

```bash
# Format
clang-format -i src/**/*.h src/**/*.cpp

# Static analysis
clang-tidy -p build src/**/*.cpp
cppcheck --enable=warning,performance,portability src/
```

### Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install
```

### Documentation

```bash
doxygen Doxyfile
# Output in docs/html/
```

---

## Dependencies (vcpkg)

| Package | Purpose |
|---------|---------|
| curl | HTTPS fetch |
| sqlite3 | Database |
| openssl | TLS, HMAC, SHA-256 |
| spdlog | Structured logging |
| cli11 | CLI parsing |
| toml++ | TOML configuration |
| catch2 | Unit testing |
| nlohmann-json | JSON output (inspect) |
| fmt | Formatting |

---

## Roadmap

* [x] Attribute drift detection (name/department mismatch)
* [ ] Delta reconciliation between runs
* [ ] Remediation connector (disable orphan accounts via API)
* [ ] Multi-tenancy support
* [ ] Prometheus metrics endpoint
* [ ] SIEM export (CEF, Syslog)

---

## License

MIT — see LICENSE file.