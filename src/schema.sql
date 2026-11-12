-- P2: UNSW-NB15 network flows (4 headerless CSV parts, 2.54M flows) -> 3NF SQLite
-- The raw parts carry no header. Column names and types come from the dataset's own
-- definition file (NUSW-NB15_features.csv), which is loaded first into feature_def.
-- load.py generates the flow table from feature_def; the generated DDL is written
-- to src/schema_generated.sql for the record.

DROP TABLE IF EXISTS flow;
DROP TABLE IF EXISTS feature_def;
DROP TABLE IF EXISTS host;
DROP TABLE IF EXISTS protocol;
DROP TABLE IF EXISTS service;
DROP TABLE IF EXISTS conn_state;
DROP TABLE IF EXISTS attack_category;
DROP TABLE IF EXISTS attack_label_variant;

CREATE TABLE feature_def (
    position     INTEGER PRIMARY KEY,   -- column position in the raw parts (1-based)
    name         TEXT NOT NULL UNIQUE,  -- cleaned name used in the flow table
    raw_name     TEXT NOT NULL,         -- name as written in the definition file
    raw_type     TEXT NOT NULL,
    description  TEXT
);

CREATE TABLE host (
    host_id   INTEGER PRIMARY KEY,
    ip        TEXT NOT NULL UNIQUE
);

CREATE TABLE protocol (
    protocol_id INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE
);

CREATE TABLE service (
    service_id INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE       -- '-' = no identified service
);

CREATE TABLE conn_state (
    state_id INTEGER PRIMARY KEY,
    name     TEXT NOT NULL UNIQUE
);

-- Nine canonical attack families.
CREATE TABLE attack_category (
    attack_cat_id INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE
);

-- Every spelling found in the raw files, mapped to its canonical family
-- (e.g. ' Fuzzers ', ' Fuzzers', 'Fuzzers' -> Fuzzers; 'Backdoor' -> Backdoors).
CREATE TABLE attack_label_variant (
    raw_label     TEXT PRIMARY KEY,
    attack_cat_id INTEGER NOT NULL REFERENCES attack_category(attack_cat_id),
    row_count     INTEGER NOT NULL
);
