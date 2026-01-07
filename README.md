# IDSentinel

**A Resilient, Audit-Ready Identity Reconciliation Engine (C++17)**

IDSentinel is a C++17 demonstration service that simulates an **enterprise Identity Governance & Administration (IGA) reconciliation cycle**.
It compares an **authoritative HR identity feed** against a **target system snapshot**, detects compliance gaps (orphan and missing accounts), and persists **immutable, audit-grade evidence** to a SQLite governance ledger.

---

## What IDSentinel Does

* Fetches an **authoritative HR feed** via HTTPS using `libcurl`

  * Automatically falls back to a **local cached CSV** if the network fetch fails *or returns invalid data*
* Loads a **target system export** (e.g., AD / legacy system snapshot) from disk
* Parses both datasets into in-memory identity maps keyed by **User ID**
* Detects identity compliance gaps:

  * **ORPHAN_ACCOUNT** – Present in target system, missing from HR
  * **MISSING_ACCOUNT** – Present in HR, missing from target system
* Writes **immutable findings** to SQLite
* Uses **database triggers** to automatically maintain:

  * Per-run violation counts
  * Per-user historical violation tracking

---

##  Key Design Features 

* **Hybrid Connectivity**
  Network-first ingestion with safe local fallback prevents false positives caused by bad HR feeds.

* **Audit-Grade Persistence**
  SQLite is used as a governance ledger, not just storage.

* **Integrity & Safety**
  TLS verification is enabled on network fetches, evidence hashes use SHA-256, and database writes use prepared statements with error checking and rollback on failure.

* **Trigger-Enforced Consistency**
  History and metrics are maintained by SQL triggers — no application-layer drift.

* **Policy-Driven Logic**
  Risk severity is defined centrally and applied consistently during reconciliation.

* **Failure-Aware Design**
  Empty or invalid HR feeds trigger a hard stop, preventing catastrophic orphan explosions.

---

## Project Layout

```
IDSentinel/
├── src/
│   ├── main.cpp                    # Orchestrator: Fetch → Parse → Reconcile → Persist
│   ├── connectors/
│   │   └── NetworkConnector.{h,cpp} # libcurl wrapper with timeouts and fallback logic
│   ├── parsers/
│   │   └── CSVParser.{h,cpp}        # Minimal CSV parsing (id,name,department)
│   ├── core/
│   │   ├── Identity.h               # Identity model
│   │   └── Reconciler.{h,cpp}       # Core reconciliation logic & policy engine
│   └── persistence/
│       └── ComplianceStore.{h,cpp}  # SQLite schema, transactions, triggers
├── data/
│   ├── hr_feed.csv                  # Mock HR feed
│   └── system_dump.csv              # Mock target system snapshot
├── compliance.db                    # SQLite DB (created at runtime)
└── CMakeLists.txt
```

---

## Build & Run

### Prerequisites

* CMake ≥ 3.12
* C++17 Compiler (GCC / Clang / MSVC)
* `libcurl`, `sqlite3`, and `OpenSSL` development libraries

### Build (Out-of-Source)

```bash
cmake -S . -B build
cmake --build build --config Release
```

Binary output:

```
build/bin/IDSentinel
```

### Run

```bash
./build/bin/IDSentinel
```

---

## Runtime Behavior

1. Attempts to fetch HR feed from:

   ```
   https://gist.githubusercontent.com/dummy/raw/hr_feed.csv
   ```
2. If the fetch fails **or parses to zero identities**, falls back to:

   ```
   data/hr_feed.csv
   ```
3. Loads the target system snapshot from:

   ```
   data/system_dump.csv
   ```
4. Executes reconciliation and writes results to:

   ```
   compliance.db
   ```

---

## Sample Console Output

```
[IDSentinel] Starting identity reconciliation...
[INFO] HR feed invalid or empty. Falling back to local cache.
[INFO] Starting run RUN_1704652000
[ALERT] Orphan Account Detected: Evil Hacker (ID: 999)
[SUCCESS] Run completed.
```

---

## 💾 Database Schema (The Governance Ledger)

### `recon_runs`

Tracks every reconciliation execution.

| Column           | Description                |
| ---------------- | -------------------------- |
| run_id           | Unique run identifier      |
| source_system    | HR feed source             |
| target_system    | Target system              |
| started_at       | Start timestamp            |
| completed_at     | End timestamp              |
| status           | RUNNING / SUCCESS / FAILED |
| total_violations | Auto-maintained count      |

---

### `compliance_findings`

Immutable evidence of detected risks.

| Column         | Description                |
| -------------- | -------------------------- |
| finding_id     | Primary key                |
| run_id         | FK → recon_runs            |
| user_id        | Identity ID                |
| violation_type | ORPHAN / MISSING           |
| severity       | CRITICAL / MEDIUM          |
| status         | OPEN / REVIEW / REMEDIATED |
| integrity_hash | Tamper-evidence hash       |

---

### `violation_history`

Aggregated, trigger-managed history.

| Column           | Description      |
| ---------------- | ---------------- |
| user_id          | Identity         |
| violation_type   | Risk type        |
| first_detected   | First occurrence |
| last_detected    | Most recent      |
| occurrence_count | Auto-incremented |

---

## Risk Policy

Defined in `Reconciler`:

| Violation Type  | Severity |
| --------------- | -------- |
| ORPHAN_ACCOUNT  | CRITICAL |
| MISSING_ACCOUNT | MEDIUM   |

---

## 🔍 Inspecting Results

Open the database:

```bash
sqlite3 compliance.db
```

Useful queries:

```sql
SELECT * FROM recon_runs;
SELECT * FROM compliance_findings;
SELECT * FROM violation_history;
```

---

## Limitations

* **CSV Parsing**
  Handles quoted fields and escaped quotes but not multiline rows or exotic edge cases.

* **Security**
  TLS certificate verification is enabled; only disable for controlled demos.

* **Hashing**
  Findings use SHA-256; add HMAC/signing if you need stronger tamper-evidence guarantees.

* **Configuration**
  URLs, file paths, and policy settings are still hardcoded; expose via CLI/env for production.

---

##  Future Roadmap

* Attribute drift detection (department / role mismatch)
* Tamper-evident signing (HMAC/PKI) for findings
* Configurable policies and sources via CLI/env (URLs, severities, DB path)
* Delta reconciliation between runs
* Remediation connector (disable orphan accounts)
* BI / SIEM export (JSON)

---