# Crate TABLE users in your DB
CREATE TABLE users (
    user_id UUID PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    session_token TEXT,
    csrf_token TEXT
);


# .env Sample
DATABASE_URL = "your_postgres_db_url"
