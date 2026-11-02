from app.services.url_analysis_service import analyze_url

test_urls = [
    "https://www.google.com",
    "https://www.paypal.com",
    "http://192.168.1.10/login?user=admin",
]


for url in test_urls:

    print("\n========================================")
    print("CYBERSHIELD URL ANALYSIS")
    print("========================================")

    result = analyze_url(url)

    print(f"URL            : {result['url']}")
    print(
        f"Classification : "
        f"{result['classification']}"
    )
    print(
        f"Confidence     : "
        f"{result['confidence']:.4f}"
    )
    print(
        f"Risk Score     : "
        f"{result['risk_score']}/100"
    )
    print(
        f"Severity       : "
        f"{result['severity']}"
    )

    print("\nExplanation:")
    print(result["explanation"])

    print("\nIndicators:")

    for indicator in result["indicators"]:
        print(f"  • {indicator}")

    print("\nRecommendation:")
    print(result["recommendation"])