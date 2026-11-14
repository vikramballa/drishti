-- Drishti schema v1 (spec §6.4). Engine results are recomputed or cached on
-- disk; the database holds identity, jobs and user/AI annotations.
CREATE TABLE IF NOT EXISTS binaries (
  sha256      TEXT PRIMARY KEY,
  file_name   TEXT NOT NULL,
  size        INTEGER NOT NULL,
  format      TEXT NOT NULL,
  file_info   TEXT NOT NULL,
  ext_path    TEXT,            -- local-mode: analysed in place, not copied
  mtime       INTEGER,
  created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS project_binaries (
  project_id  TEXT NOT NULL,
  sha256      TEXT NOT NULL,
  PRIMARY KEY (project_id, sha256)
);
CREATE TABLE IF NOT EXISTS jobs (
  id          TEXT PRIMARY KEY,
  sha256      TEXT NOT NULL,
  engines     TEXT NOT NULL,
  status      TEXT NOT NULL,
  error       TEXT,
  stats       TEXT,
  created_at  TEXT NOT NULL,
  finished_at TEXT
);
CREATE TABLE IF NOT EXISTS annotations (
  id          TEXT PRIMARY KEY,
  sha256      TEXT NOT NULL,
  addr        INTEGER NOT NULL,
  kind        TEXT NOT NULL,
  value       TEXT NOT NULL,
  scope       TEXT,
  author      TEXT NOT NULL,
  ai_status   TEXT,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS annotations_sha ON annotations (sha256, addr);
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
