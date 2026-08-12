PRAGMA foreign_keys = ON;
PRAGMA user_version = 1;
CREATE TABLE accounts (
  account_id INTEGER PRIMARY KEY,
  owner TEXT NOT NULL,
  balance INTEGER NOT NULL
);
INSERT INTO accounts(account_id, owner, balance) VALUES
  (1, 'Ada', 120),
  (2, 'Lin', 80);
