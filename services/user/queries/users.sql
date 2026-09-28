-- name: GetUser :one
-- global: a user is one identity across every org.
SELECT * FROM users WHERE id = @id AND deleted_at IS NULL;

-- name: GetUserByEmail :one
-- global: email is the platform-wide identity.
SELECT * FROM users WHERE email = @email AND deleted_at IS NULL;

-- name: InsertUser :one
-- global: created on first sign-in or first invite, before any org is
-- known. A second org inviting the same email finds this row instead.
INSERT INTO users (id, email, name) VALUES (@id, @email, @name)
ON CONFLICT (email) WHERE deleted_at IS NULL DO NOTHING
RETURNING *;

-- name: UpdateUserName :one
-- global: the name is the person's, not an org's.
UPDATE users SET name = @name WHERE id = @id AND deleted_at IS NULL
RETURNING *;
