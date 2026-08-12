PRAGMA foreign_keys = ON;
PRAGMA user_version = 3;
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    owner TEXT NOT NULL,
    balance INTEGER NOT NULL
);
INSERT INTO accounts(id, owner, balance) VALUES (1, 'Ada', 100);
INSERT INTO accounts(id, owner, balance) VALUES (2, 'Lin', 25);
