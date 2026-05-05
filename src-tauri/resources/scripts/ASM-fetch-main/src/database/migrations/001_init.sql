-- Alembic migration: Initial ASM schema
CREATE TYPE subscription_frequency AS ENUM ('daily', 'weekly', 'monthly', 'none');
CREATE TYPE scan_status AS ENUM ('pending', 'scanning', 'completed', 'failed', 'terminated', 'partial');

CREATE TABLE domains (
    id SERIAL PRIMARY KEY,
    domain_name VARCHAR(255) UNIQUE NOT NULL,
    subscription_frequency subscription_frequency DEFAULT 'none',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    task_id VARCHAR(255),
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE NOT NULL,
    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    status scan_status DEFAULT 'pending',
    error_message TEXT,
    logs TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE subdomain_data (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE NOT NULL,
    host VARCHAR(255) NOT NULL,
    ip VARCHAR(45) DEFAULT 'N/A',
    type VARCHAR(10) NOT NULL,
    asn VARCHAR(50) DEFAULT 'N/A',
    asn_name VARCHAR(255) DEFAULT 'N/A',
    whois JSON DEFAULT '{}',
    cve TEXT DEFAULT 'N/A',
    spf TEXT DEFAULT 'N/A',
    dmarc TEXT DEFAULT 'N/A',
    dkim TEXT DEFAULT 'N/A',
    opened_ports JSON DEFAULT '[]',
    unusual_ports JSON DEFAULT '[]',
    sensitive_subdomains TEXT DEFAULT 'N/A',
    tls_ssl JSON DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);