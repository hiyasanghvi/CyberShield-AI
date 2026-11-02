# Privacy deployment and migration

## Saved reports and no-save analysis

The scanner sends `X-Save-Report: true|false`. No-save calls skip all analysis, indicator and correlation writes, and the response omits the original input and directly identifying fields. Request bodies are not logged by application code. Upload routes close the temporary upload object after processing; Starlette may spool large uploads to the server's temporary directory until that close. Protect that temporary directory and its disk. Python cannot guarantee physical zeroization of immutable in-memory buffers; no-save means no application/database report retention, not forensic memory erasure.

## Encryption at rest (MySQL/MariaDB)

Saved-report writes are intentionally blocked until a 32-byte URL-safe base64 key is configured and legacy schema/data migration is confirmed. Keep `DATA_ENCRYPTION_KEY` in the deployment secret store, separately from the database. Never commit it.

1. Back up the database.
2. Generate a key using the command in `.env.example` and set it as `DATA_ENCRYPTION_KEY`.
3. From the backend directory, apply `scripts/privacy_encryption_mysql.sql` to MySQL/MariaDB.
4. From the backend directory, run `.venv/Scripts/python.exe scripts/encrypt_existing_data.py` on Windows (or `.venv/bin/python` on Linux).
5. Verify representative history/API reads and restore the backup if verification fails.
6. Set `DATA_ENCRYPTION_MIGRATION_COMPLETE=true` only after the migration succeeds. New sensitive report fields use AES-256-GCM; keys are not stored in the database.

New installations also need the key configured and the marker set after confirming the schema uses the encrypted text types. If the key is lost, encrypted report fields cannot be recovered.

## HTTPS

Terminate TLS at the production reverse proxy/load balancer, forward the original HTTPS scheme to the app, and set `ENFORCE_HTTPS=true`. The app redirects HTTP and adds HSTS to HTTPS responses. Keep local development at `false`. The Trust Center reports configuration; it cannot inspect certificates or verify proxy behavior.

## Retention and deletion

Retention cleanup runs when the user's dashboard, history or Trust Center is opened. Deletion removes analysis subtype rows, threat indicators and every relationship that references those indicators. Current upload endpoints do not retain uploaded files; legacy QR paths are removed only under `UPLOAD_DIR`.
