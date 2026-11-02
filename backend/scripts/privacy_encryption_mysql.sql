-- Back up the database before applying. Converts bounded VARCHAR input columns
-- so AES-GCM ciphertext is not truncated. MySQL/MariaDB only.
ALTER TABLE url_analyses MODIFY url MEDIUMTEXT NOT NULL, MODIFY domain MEDIUMTEXT NULL;
ALTER TABLE email_analyses MODIFY sender_email MEDIUMTEXT NULL, MODIFY subject MEDIUMTEXT NULL, MODIFY body MEDIUMTEXT NULL;
ALTER TABLE qr_analyses MODIFY decoded_url MEDIUMTEXT NULL;
ALTER TABLE apk_analyses MODIFY file_name MEDIUMTEXT NULL, MODIFY file_hash MEDIUMTEXT NULL;
ALTER TABLE network_analyses MODIFY source_ip MEDIUMTEXT NULL, MODIFY destination_ip MEDIUMTEXT NULL;
