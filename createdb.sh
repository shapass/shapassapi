#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE USER admin WITH SUPERUSER PASSWORD 'postgres';
    CREATE DATABASE shapass;
    GRANT ALL PRIVILEGES ON DATABASE shapass TO admin;
EOSQL

psql -v ON_ERROR_STOP=1 --username admin --dbname shapass <<-EOSQL
    CREATE TABLE users(
        id serial PRIMARY KEY,
        email VARCHAR(128),
        password VARCHAR(255),
        password_reset_token VARCHAR(255),
        last_password_reset_time TIMESTAMP,
        last_login TIMESTAMP,
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
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, service_name)
    );

    CREATE TABLE login(
        id serial PRIMARY KEY,
        user_id INT REFERENCES users(id),
        login_token VARCHAR(255),

        created_at TIMESTAMP DEFAULT NOW(),
        expire_at TIMESTAMP
    );
EOSQL