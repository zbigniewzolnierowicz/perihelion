CREATE TABLE IF NOT EXISTS users (
    id uuid DEFAULT uuid_generate_v4 (),
    username VARCHAR NOT NULL UNIQUE,
    email VARCHAR NOT NULL UNIQUE,
    display_name VARCHAR NOT NULL,

    PRIMARY KEY (id)
);

CREATE TYPE credential_type AS enum ('password');

CREATE TABLE IF NOT EXISTS credentials (
    user_id uuid NOT NULL,
    credential_type credential_type DEFAULT 'password',
    credential_content TEXT NOT NULL,

    PRIMARY KEY (user_id, credential_type),
    CONSTRAINT
        fk_credentials_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS jwt (
    jwt_id UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    content TEXT NOT NULL,
    expiration TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (jwt_id, user_id),
    CONSTRAINT
        fk_jwt_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS refresh (
    refresh_id UUID UNIQUE NOT NULL DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    content TEXT NOT NULL,
    expiration TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (refresh_id, user_id),
    CONSTRAINT
        fk_refresh_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);
