#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE USER admin WITH SUPERUSER PASSWORD 'postgres';
    CREATE DATABASE shapassapi;
    GRANT ALL PRIVILEGES ON DATABASE shapassapi TO admin;
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

    CREATE TABLE users(
        id serial PRIMARY KEY,
        email VARCHAR(128),
        password VARCHAR(255),
        password_reset_token VARCHAR(255),
        last_password_reset_time TIMESTAMP,
        activated BOOLEAN DEFAULT FALSE,
        last_login TIMESTAMP,
        login_count INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE pattern(
        id serial PRIMARY KEY,
        user_id INT REFERENCES users(id),

        service_name VARCHAR(64),
        length INT DEFAULT 32,
        prefix_salt VARCHAR(32),
        suffix_salt VARCHAR(32),
        metadata JSON,
        algorithm VARCHAR(32),
        
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, service_name)
    );

    CREATE TABLE login(
        id serial PRIMARY KEY,
        guid uuid NOT NULL DEFAULT uuid_generate_v4() UNIQUE,

        user_id INT REFERENCES users(id),
        login_token VARCHAR(255),

        created_at TIMESTAMP DEFAULT NOW(),
        expire_at TIMESTAMP
    );
EOSQL
