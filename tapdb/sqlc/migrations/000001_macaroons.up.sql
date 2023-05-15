CREATE TABLE IF NOT EXISTS macaroons (
    id BLOB PRIMARY KEY,
    root_key BLOB NOT NULL 
);
