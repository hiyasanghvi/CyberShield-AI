import re
from urllib.parse import urlparse


def extract_url_features(url: str) -> dict:
    """
    Extract the 24 features required by the CyberShield
    final URL Random Forest model.
    """

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    # Add scheme if user enters something like example.com
    parsed_url = urlparse(
        url if "://" in url else "http://" + url
    )

    domain = parsed_url.netloc

    # Remove username/password and port where applicable
    domain = domain.split("@")[-1]
    domain = domain.split(":")[0]

    path = parsed_url.path or ""
    query = parsed_url.query or ""

    # Complete URL used for character-level features
    full_url = url

    # --------------------------------------------------------
    # Basic URL features
    # --------------------------------------------------------

    url_length = len(full_url)
    domain_length = len(domain)

    # IP address detection
    is_domain_ip = 1 if re.fullmatch(
        r"\d{1,3}(?:\.\d{1,3}){3}",
        domain
    ) else 0

    # --------------------------------------------------------
    # Subdomain
    # --------------------------------------------------------

    domain_parts = [
        part for part in domain.split(".")
        if part
    ]

    # Example:
    # login.example.com
    # -> 1 subdomain
    no_of_subdomain = max(
        len(domain_parts) - 2,
        0
    )

    # --------------------------------------------------------
    # Obfuscation
    # --------------------------------------------------------

    suspicious_obfuscation_chars = [
        "%",
        "@",
        "\\",
        "//",
        ".."
    ]

    obfuscated_count = 0

    for pattern in suspicious_obfuscation_chars:

        if pattern in full_url:
            if pattern == "//":
                # Ignore the normal protocol //
                occurrences = full_url.count("//") - 1
                obfuscated_count += max(
                    occurrences,
                    0
                )
            else:
                obfuscated_count += full_url.count(
                    pattern
                )

    has_obfuscation = (
        1 if obfuscated_count > 0 else 0
    )

    no_of_obfuscated_char = obfuscated_count

    obfuscation_ratio = (
        obfuscated_count / url_length
        if url_length > 0
        else 0.0
    )

    # --------------------------------------------------------
    # Character statistics
    # --------------------------------------------------------

    letters = sum(
        char.isalpha()
        for char in full_url
    )

    digits = sum(
        char.isdigit()
        for char in full_url
    )

    no_of_letters = letters

    letter_ratio = (
        letters / url_length
        if url_length > 0
        else 0.0
    )

    no_of_digits = digits

    digit_ratio = (
        digits / url_length
        if url_length > 0
        else 0.0
    )

    # --------------------------------------------------------
    # Special URL characters
    # --------------------------------------------------------

    no_of_equals = full_url.count("=")

    no_of_qmark = full_url.count("?")

    no_of_ampersand = full_url.count("&")

    special_characters = sum(
        1
        for char in full_url
        if not char.isalnum()
        and char not in [
            "/",
            ":",
            ".",
            "-",
            "_"
        ]
    )

    no_of_other_special_chars = (
        special_characters
    )

    special_char_ratio = (
        special_characters / url_length
        if url_length > 0
        else 0.0
    )

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    is_https = (
        1
        if parsed_url.scheme.lower() == "https"
        else 0
    )

    # --------------------------------------------------------
    # Redirect features
    #
    # These cannot be reliably determined without actually
    # fetching the URL. For the initial safe static detector,
    # keep them at 0.
    # --------------------------------------------------------

    no_of_url_redirect = 0

    no_of_self_redirect = 0

    # --------------------------------------------------------
    # Form / password indicators
    #
    # These require webpage content. We do NOT fetch arbitrary
    # URLs here because the initial CyberShield URL analyzer
    # should remain safe and static.
    # --------------------------------------------------------

    has_external_form_submit = 0

    has_password_field = 0

    # --------------------------------------------------------
    # Keyword indicators
    # --------------------------------------------------------

    url_lower = full_url.lower()

    bank_keywords = [
        "bank",
        "banking",
        "paypal",
        "paytm",
        "sbi",
        "hdfc",
        "icici",
        "axis"
    ]

    pay_keywords = [
        "pay",
        "payment",
        "checkout",
        "billing",
        "invoice"
    ]

    crypto_keywords = [
        "crypto",
        "bitcoin",
        "btc",
        "ethereum",
        "wallet",
        "usdt"
    ]

    bank = int(
        any(
            keyword in url_lower
            for keyword in bank_keywords
        )
    )

    pay = int(
        any(
            keyword in url_lower
            for keyword in pay_keywords
        )
    )

    crypto = int(
        any(
            keyword in url_lower
            for keyword in crypto_keywords
        )
    )

    # --------------------------------------------------------
    # Final feature dictionary
    # --------------------------------------------------------

    features = {

        "URLLength": url_length,

        "DomainLength": domain_length,
        "Domain": domain,

        "IsDomainIP": is_domain_ip,

        "NoOfSubDomain": no_of_subdomain,

        "HasObfuscation": has_obfuscation,

        "NoOfObfuscatedChar": no_of_obfuscated_char,

        "ObfuscationRatio": obfuscation_ratio,

        "NoOfLettersInURL": no_of_letters,

        "LetterRatioInURL": letter_ratio,

        "NoOfDegitsInURL": no_of_digits,

        "DegitRatioInURL": digit_ratio,

        "NoOfEqualsInURL": no_of_equals,

        "NoOfQMarkInURL": no_of_qmark,

        "NoOfAmpersandInURL": no_of_ampersand,

        "NoOfOtherSpecialCharsInURL":
            no_of_other_special_chars,

        "SpacialCharRatioInURL":
            special_char_ratio,

        "IsHTTPS": is_https,

        "NoOfURLRedirect":
            no_of_url_redirect,

        "NoOfSelfRedirect":
            no_of_self_redirect,

        "HasExternalFormSubmit":
            has_external_form_submit,

        "HasPasswordField":
            has_password_field,

        "Bank": bank,

        "Pay": pay,

        "Crypto": crypto,
    }

    return features