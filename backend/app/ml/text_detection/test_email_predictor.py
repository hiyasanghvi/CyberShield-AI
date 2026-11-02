from app.ml.text_detection.email_predictor import predict_email


test_emails = [
    {
        "subject": "URGENT: Your account will be suspended",
        "body": "Click https://example.com/login immediately to verify your password."
    },
    {
        "subject": "Meeting tomorrow",
        "body": "Hi, can we meet tomorrow at 10 AM to discuss the project?"
    },
    {
        "subject": "Congratulations! You won a prize",
        "body": "Claim your free cash reward immediately by clicking the link."
    },
]


for i, email in enumerate(test_emails, start=1):
    result = predict_email(
        subject=email["subject"],
        body=email["body"]
    )

    print(f"\nEmail {i}")
    print("-" * 40)
    print("Classification :", result["classification"])
    print("Spam probability:", round(result["spam_probability"], 4))
    print("Ham probability :", round(result["ham_probability"], 4))
    print("Confidence      :", round(result["confidence"], 4))
    print("Contains URL    :", result["contains_url"])
    print("URL count       :", result["url_count"])