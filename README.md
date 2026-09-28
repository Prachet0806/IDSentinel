# IDSentinel

**A Resilient, Audit-Ready Identity Reconciliation Engine (C++23)**

IDSentinel is a C++23 identity reconciliation engine that compares an **authoritative HR identity feed** against a **target system snapshot**, detects compliance gaps (orphan and missing accounts), and persists **immutable, audit-grade evidence** to a SQLite governance ledger.

---

## Features

* **Hybrid Connectivity** — Network-first HR feed ingestion (HTTPS via libcurl) with automatic local CSV fallback
* **TLS Verification** — Certificate validation enabled by default; configurable CA bundle
* **HMAC-SHA256 Integrity** — Tamper-evident finding hashes with optional HMAC key
* **Audit-Grade Persistence** — SQLite with WAL mode, triggers for history/metrics, foreign key enforcement
* **High Performance** — Bulk insert for 100k+ identities, indexes on query paths
* **Policy-Driven** — Configurable severity levels (CRITICAL/HIGH/MEDIUM/LOW)
* **Failure-Aware** — Empty HR feeds trigger hard stop; transaction rollback on any error
* **Structured Logging** — JSON or text output with file rotation (spdlog)
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
│   │   ├── Policy.h                  # Enums: ViolationType, Severity, RunStatus, FindingStatus
│   │   ├── Result.h                  # Result<T, Error> (C++23 std::expected compatible)
│   │   ├── Logging.{h,cpp}           # spdlog wrapper (JSON/text, rotation)
│   │   └── Reconciler.{h,cpp}        # Core reconciliation logic
│   ├── connectors/NetworkConnector.{h,cpp} # libcurl wrapper (TLS, timeouts, CA bundle)
│   ├── parsers/CSVParser.{h,cpp}     # CSV parsing (streaming + bulk)
│   └── persistence/
│       ├── IViolationStore.h         # Interface for violation storage
│       └── ComplianceStore.{h,cpp}   # SQLite implementation (WAL, bulk insert, triggers)
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

# Configure and build
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release --parallel
```

Binary output: `build/bin/IDSentinel` (or `build/bin/Release/IDSentinel.exe` on Windows)

---

## Usage

### Quick Start

```bash
# Run reconciliation (uses config.toml defaults)
./build/bin/IDSentinel reconcile

# Dry-run: preview violations without writing to DB
./build/bin/IDSentinel reconcile --dry-run

# Inspect a specific run
./build/bin/IDSentinel inspect --run-id RUN_abc123 --format json

# Show current configuration
./build/bin/IDSentinel config show

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

[database]
path = ""  # empty = platform default (~/.local/share/idsentinel/compliance.db)
wal_mode = true
busy_timeout_ms = 5000

[policy]
orphan_severity = "CRITICAL"
missing_severity = "MEDIUM"

[logging]
level = "info"
format = "json"
file = ""
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
| status | RUNNING / SUCCESS / FAILED |
| total_violations | Auto-maintained by trigger |

### `compliance_findings` — Immutable evidence
| Column | Description |
|--------|-------------|
| finding_id | Primary key |
| run_id | FK → recon_runs |
| user_id | Identity ID |
| violation_type | ORPHAN_ACCOUNT / MISSING_ACCOUNT |
| severity | CRITICAL / HIGH / MEDIUM / LOW |
| detected_at | Timestamp |
| status | OPEN / REVIEW / REMEDIATED |
| integrity_hash | HMAC-SHA256 or SHA-256 hash |

### `violation_history` — Aggregated history (trigger-maintained)
| Column | Description |
|--------|-------------|
| user_id | Identity |
| violation_type | Risk type |
| first_detected | First occurrence |
| last_detected | Most recent |
| occurrence_count | Auto-incremented |

Indexes: `idx_findings_run`, `idx_findings_user`, `idx_findings_type`

---

## Sample Output

```
$ idsentinel reconcile
[INFO]  Starting reconciliation run: RUN_0x2748a3f2_0x7f8b1c2d
[WARN]  Orphan Account Detected: Evil Hacker (ID: 999)
[INFO]  Run RUN_0x2748a3f2_0x7f8b1c2d completed: 1 orphans, 0 missing

$ idsentinel inspect --run-id RUN_0x2748a3f2_0x7f8b1c2d --format json
[
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
```

---

## Security

* **TLS Verification**: Enabled by default (`CURLOPT_SSL_VERIFYPEER=1`, `CURLOPT_SSL_VERIFYHOST=2`)
* **CA Bundle**: Configure via `network.ca_bundle_path` or `IDSENTINEL_NETWORK__CA_BUNDLE_PATH`
* **Integrity Hashes**: HMAC-SHA256 when `security.hmac_key` is set (32-byte base64 key); falls back to SHA-256 with warning
* **Key Generation**: `idsentinel keygen` outputs base64 key; or `openssl rand -base64 32`

---

## Development

### Running Tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --config Debug
ctest --test-dir build --output-on-failure
```

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

* [ ] Attribute drift detection (department/role mismatch)
* [ ] Delta reconciliation between runs
* [ ] Remediation connector (disable orphan accounts via API)
* [ ] Multi-tenancy support
* [ ] Prometheus metrics endpoint
* [ ] SIEM export (CEF, Syslog)

---

## License

MIT — see LICENSE file.