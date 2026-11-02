from risk_engine import calculate_url_risk


# ============================================================
# TEST 1 — LOW RISK
# ============================================================

result = calculate_url_risk(
    phishing_probability=0.0028,
    classification="LEGITIMATE",
    features={
        "IsDomainIP": 0,
        "HasObfuscation": 0,
        "NoOfSubDomain": 1,
        "NoOfQMark": 0,
        "NoOfEqualsInURL": 0,
        "NoOfDegitsInURL": 0,
        "URLLength": 22,
        "IsHTTPS": 1,
    },
)

print("\n========================================")
print("RISK ENGINE TEST 1")
print("========================================")
print(result)


# ============================================================
# TEST 2 — CRITICAL RISK
# ============================================================

result = calculate_url_risk(
    phishing_probability=1.0,
    classification="PHISHING",
    features={
        "IsDomainIP": 1,
        "HasObfuscation": 0,
        "NoOfSubDomain": 0,
        "NoOfQMark": 1,
        "NoOfEqualsInURL": 1,
        "NoOfDegitsInURL": 10,
        "URLLength": 45,
        "IsHTTPS": 0,
    },
)

print("\n========================================")
print("RISK ENGINE TEST 2")
print("========================================")
print(result)