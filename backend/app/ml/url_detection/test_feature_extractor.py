from feature_extractor import extract_url_features


test_urls = [
    "https://www.google.com",
    "http://example.com/login",
    "http://192.168.1.10/login?user=admin&password=123",
]


for url in test_urls:

    print("\n========================================")
    print(f"URL: {url}")
    print("========================================")

    features = extract_url_features(url)

    print(f"Number of features: {len(features)}")

    for name, value in features.items():
        print(f"{name:30} : {value}")