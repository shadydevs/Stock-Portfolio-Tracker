CREATE TABLE transactions (
    trans_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id INT NOT NULL,
    symbol VARCHAR(16) NOT NULL,
    price DOUBLE(10, 2) NOT NULL,
    shares INT NOT NULL,
    trans_time DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX trans_id on transactions (trans_id);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    username VARCHAR(16) NOT NULL,
    hash VARCHAR(16) NOT NULL,
    cash DOUBLE(10, 2) DEFAULT 10000
);
CREATE UNIQUE INDEX id on users (id);

