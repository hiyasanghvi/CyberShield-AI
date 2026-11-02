from url_predictor import predict_url


test_urls = [
    "https://www.google.com",
    "https://www.paypal.com",
    "http://192.168.1.10/login?user=admin",
]


for url in test_urls:

    print("\n========================================")
    print("URL PREDICTION TEST")
    print("========================================")

    print(f"URL: {url}")

    result = predict_url(url)

    print(
        f"Classification        : "
        f"{result['classification']}"
    )

    print(
        f"Phishing Probability  : "
        f"{result['phishing_probability']:.4f}"
    )

    print(
        f"Legitimate Probability: "
        f"{result['legitimate_probability']:.4f}"
    )

    print(
        f"Confidence            : "
        f"{result['confidence']:.4f}"
    )