import csv
import re
from pathlib import Path
from email import policy
from email.parser import BytesParser

PROJECT_ROOT = Path(__file__).resolve().parents[4]

RAW_DIR = PROJECT_ROOT / "ml" / "datasets" / "email" / "raw"
OUTPUT_DIR = PROJECT_ROOT / "ml" / "datasets" / "email" / "processed"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

URL_PATTERN = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)


def extract_body(message):
    parts = []

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()

            if content_type == "text/plain":
                try:
                    content = part.get_content()
                except Exception:
                    try:
                        content = part.get_payload(decode=True).decode(
                            errors="ignore"
                        )
                    except Exception:
                        content = ""

                if content:
                    parts.append(content)

    else:
        try:
            content = message.get_content()
        except Exception:
            try:
                content = message.get_payload(decode=True).decode(
                    errors="ignore"
                )
            except Exception:
                content = ""

        if content:
            parts.append(content)

    return "\n".join(parts)


def parse_email(file_path, label):
    try:
        with open(file_path, "rb") as f:
            message = BytesParser(policy=policy.default).parse(f)

        sender = message.get("From", "")
        subject = message.get("Subject", "")
        body = extract_body(message)

        raw_text = f"{subject} {body}"

        urls = URL_PATTERN.findall(raw_text)

        has_attachment = False

        if message.is_multipart():
            for part in message.walk():
                disposition = part.get_content_disposition()
                if disposition == "attachment":
                    has_attachment = True
                    break

        return {
            "label": label,
            "sender": str(sender),
            "subject": str(subject),
            "body": body,
            "contains_url": int(len(urls) > 0),
            "url_count": len(urls),
            "has_attachment": int(has_attachment),
        }

    except Exception as e:
        print(f"Skipped {file_path.name}: {e}")
        return None


def collect_files(directory):
    return [
        p for p in directory.rglob("*")
        if p.is_file()
    ]


def main():
    rows = []

    ham_dir = RAW_DIR / "ham"
    spam_dir = RAW_DIR / "spam"

    ham_files = collect_files(ham_dir)
    spam_files = collect_files(spam_dir)

    print(f"Ham files  : {len(ham_files)}")
    print(f"Spam files : {len(spam_files)}")

    for file_path in ham_files:
        row = parse_email(file_path, "HAM")
        if row:
            rows.append(row)

    for file_path in spam_files:
        row = parse_email(file_path, "SPAM")
        if row:
            rows.append(row)

    output_file = OUTPUT_DIR / "email_dataset.csv"

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "label",
                "sender",
                "subject",
                "body",
                "contains_url",
                "url_count",
                "has_attachment",
            ],
        )

        writer.writeheader()
        writer.writerows(rows)

    ham_count = sum(r["label"] == "HAM" for r in rows)
    spam_count = sum(r["label"] == "SPAM" for r in rows)

    print("\nDataset created successfully.")
    print(f"Total : {len(rows)}")
    print(f"HAM   : {ham_count}")
    print(f"SPAM  : {spam_count}")
    print(f"Saved : {output_file}")


if __name__ == "__main__":
    main()