-- Asset-to-CVE correlation via CPE. Requires PRAGMA foreign_keys = ON before execution.
-- Do not run on a database that still uses legacy asm_assets / cve_data layouts without a rename or drop plan.

CREATE TABLE asm_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    hostname VARCHAR,
    ip VARCHAR,
    cpe_string VARCHAR NOT NULL,
    os VARCHAR,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cve_data (
    cve_id TEXT PRIMARY KEY NOT NULL,
    cvss_score REAL,
    description TEXT,
    base_cpe TEXT NOT NULL,
    published_date TIMESTAMP
);

CREATE TABLE asset_cve_mapping (
    asset_id INTEGER NOT NULL,
    cve_id TEXT NOT NULL,
    matched_on_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (asset_id, cve_id),
    FOREIGN KEY (asset_id) REFERENCES asm_assets (id) ON DELETE CASCADE,
    FOREIGN KEY (cve_id) REFERENCES cve_data (cve_id) ON DELETE CASCADE
);
