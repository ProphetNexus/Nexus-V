# Ingestion Process: Step-by-Step Workflow

This document outlines the technical process for how the Ethical Tool pulls security data from external APIs and persists it into the local database.

## 1. Initialization and Orchestration
The process begins in `main.py` via the `run_sync` function, which instantiates the `APIManager` (the orchestrator).

### A. Database Connection Pooling
Before any data is pulled, the `APIManager` initializes the `DatabasePool`.
*   **Singleton Pattern**: The `DatabasePool` ensures only one pool is created for the entire application.
*   **Environment Loading**: It locates the project root and loads credentials from `configs/db.env`.
*   **Pool Configuration**: It establishes a pool of 15 connections to handle concurrent operations.

### B. Component Assembly
The `APIManager` initializes the following components, injecting the shared `db_pool` where necessary:
*   `NVDFetcher` & `MITREFetcher`: Handle HTTP requests.
*   `NVDProcessor` & `MITREProcessor`: Transform raw JSON into database-ready tuples.
*   `Upsert`: Handles all SQL execution using the shared pool.

---

## 2. NVD (CVE) Ingestion Flow
Triggered by `APIManager.run_nvd_sync()`, this flow handles high-volume vulnerability data.

### Step 1: Request Streaming (`nvd_puller.py`)
*   The `NVDFetcher` determines the time window (e.g., the last 24 hours).
*   It calculates the total number of records available.
*   **Parallel Fetching**: It uses a `ThreadPoolExecutor` to fetch multiple chunks (batches) of CVE data simultaneously.
*   **Rate Limiting**: It dynamically adjusts `api_delay` based on whether an API key is present.

### Step 2: Data Transformation (`nvd_processor.py`)
*   Raw JSON batches are passed to the `NVDProcessor`.
*   The processor extracts core CVE metadata (IDs, scores, descriptions) and associated CPE (Product) strings.
*   It returns a dictionary containing lists of tuples ready for SQL insertion.

### Step 3: Database Upsert (`db_filler.py`)
*   The `Upsert` class requests a connection from the `db_pool`.
*   **Bulk Insertion**: It uses `cursor.executemany()` for high-performance writing.
*   **Conflict Handling**: It uses `ON DUPLICATE KEY UPDATE` to ensure existing CVEs are updated with the latest NVD data rather than creating duplicates.
*   **Recursive Chunking**: If a batch insertion fails due to a data error, the code recursively splits the batch into smaller pieces to isolate and skip the problematic record while saving the rest.

---

## 3. MITRE ATT&CK Ingestion Flow
Triggered by `APIManager.run_mitre_sync()`, this flow refreshes the adversarial tactics and techniques framework.

### Step 1: Matrix Fetching (`mitre_puller.py`)
*   The `MITREFetcher` connects to the MITRE STIX/TAXII servers.
*   It fetches the raw matrices for Enterprise, Mobile, and ICS frameworks.

### Step 2: Framework Processing (`mitre_processor.py`)
*   The processor parses the STIX objects.
*   It identifies **Tactics**, **Techniques**, and **Sub-Techniques**.
*   It maps the relationships (which technique belongs to which tactic).

### Step 3: Relational Persistence (`db_filler.py`)
*   The data is passed to `save_mitre_framework`.
*   It executes four distinct insertion tasks in order:
    1.  Insert Tactics.
    2.  Insert Base Techniques.
    3.  Insert Sub-Techniques (referencing parents).
    4.  Insert Mappings into the join table (`technique_tactics`).
*   It uses `INSERT IGNORE` for mappings to avoid errors on pre-existing relationships.

---

## 4. Error Handling & Cleanup
Across both processes, the system maintains strict resource management:
*   **Transaction Management**: If a database error occurs mid-batch, a `rollback()` is issued to maintain data integrity.
*   **Connection Return**: The `finally` blocks in `db_filler.py` and `db_reader.py` ensure that `conn.close()` is called, which returns the connection to the pool rather than killing it.
*   **Logging**: The `APIManager` catches exceptions and logs them via the `log_manager` before safely exiting the process.

---