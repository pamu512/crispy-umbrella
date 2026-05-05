-- Mature threat intelligence layout for ioc_records (SQLite).
-- Apply as part of a controlled migration; existing code still expects the legacy schema until wired.

CREATE TABLE ioc_records (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    ioc_value VARCHAR NOT NULL,
    ioc_type VARCHAR NOT NULL,
    threat_actor VARCHAR,
    kill_chain_phase VARCHAR,
    confidence_score INTEGER NOT NULL CHECK (confidence_score >= 0 AND confidence_score <= 100),
    severity VARCHAR NOT NULL,
    tlp_level VARCHAR NOT NULL CHECK (tlp_level IN ('RED', 'AMBER', 'GREEN', 'CLEAR')),
    expiration_date TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
