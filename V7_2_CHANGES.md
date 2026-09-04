# PostGuard v7.2 — Duplicate Email Registration Fix

- Preserves the existing pre-registration email lookup.
- Adds a database-level catch for PostgreSQL `UniqueViolation` and SQLite `IntegrityError`.
- Rolls back the failed transaction before returning a friendly registration message.
- Prevents a duplicate/racing registration request from producing an HTTP 500 page.
- Does not change Resend, password hashing, authentication, or existing user data.
