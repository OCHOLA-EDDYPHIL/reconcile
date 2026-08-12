PRAGMA foreign_keys = ON;
PRAGMA user_version = 3;
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    owner TEXT NOT NULL,
    balance INTEGER NOT NULL
);
CREATE TABLE ledger (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    amount INTEGER NOT NULL
);
INSERT INTO accounts(id, owner, balance) VALUES (1, 'Ada', 100);
INSERT INTO accounts(id, owner, balance) VALUES (2, 'Lin', 25);
INSERT INTO ledger(id, account_id, amount) VALUES (1, 1, 100);
INSERT INTO ledger(id, account_id, amount) VALUES (2, 2, 25);
