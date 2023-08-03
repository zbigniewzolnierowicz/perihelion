CREATE TABLE IF NOT EXISTS users (
    id uuid DEFAULT uuid_generate_v4 (),
    username VARCHAR NOT NULL,
    email VARCHAR NOT NULL,

    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS jwt (
    id UUID UNIQUE NOT NULL,
    user_id UUID UNIQUE NOT NULL,
    content TEXT NOT NULL,
    expiration TIMESTAMP NOT NULL,

    PRIMARY KEY (id, user_id),
    CONSTRAINT
        fk_jwt_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS refresh (
    id UUID UNIQUE NOT NULL,
    user_id UUID UNIQUE NOT NULL,
    content TEXT NOT NULL,
    expiration TIMESTAMP NOT NULL,

    PRIMARY KEY (id, user_id),
    CONSTRAINT
        fk_refresh_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);
