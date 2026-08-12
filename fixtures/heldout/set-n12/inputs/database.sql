PRAGMA foreign_keys = ON;
PRAGMA user_version = 2;
CREATE TABLE entries (
  entry_id INTEGER PRIMARY KEY,
  category TEXT NOT NULL,
  quantity INTEGER NOT NULL
);
INSERT INTO entries(entry_id, category, quantity) VALUES
  (1, 'alpha', 14),
  (2, 'beta', 9);
