#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE USER admin WITH SUPERUSER PASSWORD 'postgres';
    CREATE DATABASE shapass;
    GRANT ALL PRIVILEGES ON DATABASE shapass TO admin;
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    CREATE TYPE password_rule AS ENUM ('default');
EOSQL

psql -v ON_ERROR_STOP=1 --username admin --dbname shapass <<-EOSQL
    CREATE TABLE users(
        id serial PRIMARY KEY,
        name VARCHAR(128),
        email VARCHAR(128),
        password VARCHAR(128),
        login_cookie VARCHAR(255),
        login_valid BOOLEAN DEFAULT false,
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
        
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
    );
EOSQL