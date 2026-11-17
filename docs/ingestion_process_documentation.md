# Ingestion Process: Step-by-Step Workflow

This document outlines the technical process for how the Ethical Tool pulls security data from external APIs and persists it into the local database with high throughput and low memory overhead.

## 1. Initialization and Orchestration
The process begins in `main.py` via the `run_sync` function, which instantiates the `APIManager` (the orchestrator in `api_orchestrator.py`).

### A. Database Connection Pooling (`db_pool.py`)
Before any data is pulled, the `APIManager` initializes the `DatabasePool`.
*   **Singleton Pattern**: The `DatabasePool` ensures only one pool is created for the entire application lifecycle.
*   **Environment Loading**: It locates the project root and loads database credentials from `configs/db.env`.
*   **Pool Configuration**: It establishes a `PooledDB` pool of up to 15 MySQL connections (with 5 minimum cached) to handle operations efficiently.

### B. Component Assembly
The `APIManager` initializes the following components, injecting the shared `db_pool` where necessary:
*   `NVDFetcher` & `MITREFetcher`: Handle HTTP requests and API pagination.
*   `NVDProcessor` & `MITREProcessor`: Transform raw JSON payloads into database-ready tuples.
*   `Upsert`: Handles all bulk SQL execution using the shared pool.

---

## 2. NVD (CVE) Ingestion Flow
Triggered by `APIManager.run_nvd_sync(mode, days)`, this flow handles high-volume vulnerability data using a bounded streaming architecture.

### Step 1: Bounded Request Streaming (`nvd_puller.py`)
*   **Window & Chunk Sizing**: The `NVDFetcher` sets the time window (up to the NVD API 2.0 maximum of 120 days in `lastmod` mode) and enforces a hardcoded page size of **2,000 records per request** (`CHUNK_LIMIT = 2000`) to minimize HTTP round-trips.
*   **Initial Discovery**: It executes an immediate initial request to determine `totalResults` and yields the first batch of vulnerabilities right away.
*   **Sliding Window Backpressure**: Instead of queuing all remaining pages at once, it uses a `ThreadPoolExecutor` with a bounded sliding window (`wait(..., return_when=FIRST_COMPLETED)`). Only a small window of concurrent requests (`max_workers * 2`) stays in flight at any time—automatically pausing network fetches if database writes fall behind to maintain a flat RAM footprint.
*   **Thread-Safe Rate Limiting**: A mutex-locked token pacer (`_wait_for_rate_limit`) dynamically enforces request intervals (`0.65s` with an API key across 5 workers; `6.2s` without a key on 1 worker) and handles `429`/`5xx` responses with exponential backoff.
*   **Fast JSON Decoding**: Responses are parsed using `orjson` directly from raw bytes for maximum CPU and memory efficiency.

### Step 2: Data Transformation & Memory Cleanup (`nvd_processor.py` & `api_orchestrator.py`)
*   Raw JSON batches are passed to `NVDProcessor.process_batch()`.
*   The processor extracts core CVE metadata (IDs, CVSS v4.0/v3.1/v3.0/v2.0 metrics, CISA KEV fields, descriptions, CWE weaknesses, references) and flattens vulnerable CPE (Product) strings into lightweight tuples.
*   Immediately after transformation, `api_orchestrator.py` explicitly deletes (`del raw_batch`) the raw JSON dictionaries so Python's garbage collector can reclaim the memory before SQL serialization begins.

### Step 3: Sub-Chunked Database Upsert (`db_filler.py`)
*   The `Upsert` class checks out a connection from `db_pool`.
*   **CPE Sub-Chunking**: Because single CVEs can contain thousands of affected product configurations, `process_and_save()` slices large CPE lists into safe sub-chunks of **2,000 rows** before execution to prevent multi-megabyte SQL query allocations in `MySQLdb`.
*   **Bulk Insertion & Conflict Handling**: It uses `cursor.executemany()` with `ON DUPLICATE KEY UPDATE` for CVEs (updating existing records with the latest NVD data) and `INSERT IGNORE` for CPEs.
*   **Iterative Binary Splitting**: If a batch insertion fails due to a deadlocks/lock timeouts (`1213`, `1205`), it retries after a brief pause. If a batch fails due to a malformed record, an iterative stack splits the chunk in half repeatedly to isolate the exact offending record while committing all valid records.
*   Once persisted, `api_orchestrator.py` explicitly frees `processed_batch` from memory before pulling the next batch.

---

## 3. MITRE ATT&CK Ingestion Flow
Triggered by `APIManager.run_mitre_sync()`, this flow refreshes the adversarial tactics and techniques framework.

### Step 1: Matrix Fetching (`mitre_puller.py`)
*   The `MITREFetcher` connects to the MITRE STIX/TAXII sources and streams raw matrices for the Enterprise, Mobile, and ICS frameworks.

### Step 2: Framework Processing (`mitre_processor.py`)
*   The processor parses the STIX objects into lightweight tuples, identifying **Tactics**, **Techniques**, **Sub-Techniques**, and their relational mappings.
*   Raw matrices are freed via `del raw_matrix` immediately after parsing.

### Step 3: Relational Persistence (`db_filler.py`)
*   The processed data is passed to `save_mitre_framework()`, which executes four distinct bulk insertion tasks in relational order:
    1.  Upsert Tactics (`attack_tactics`).
    2.  Upsert Base Techniques (`attack_techniques`).
    3.  Upsert Sub-Techniques referencing parent IDs (`attack_techniques`).
    4.  Insert Mappings into the join table (`technique_tactics`) using `INSERT IGNORE` to skip pre-existing relationships.

---

## 4. Error Handling, Logging & Cleanup
Across both pipelines, the system maintains strict resource and operational hygiene:
*   **Transaction Management**: All batch writes run inside explicit transactions; if an unrecoverable database error occurs mid-batch, a `rollback()` is issued to preserve data integrity.
*   **Connection Return**: The `finally` blocks in `db_filler.py` guarantee `cursor.close()` and `conn.close()` are always called, safely returning connections to the `PooledDB` pool.
*   **Milestone & Alert Logging**: To minimize I/O overhead during high-speed syncs, `APIManager` suppresses per-batch info logs and only logs sync start/completion milestones (including total execution duration) alongside `WARNING`, `ERROR`, and `CRITICAL` events via `log_manager`.