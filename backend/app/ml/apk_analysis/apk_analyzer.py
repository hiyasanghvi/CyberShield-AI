
import hashlib
import io
import re
import zipfile
from urllib.parse import urlsplit

from androguard.core.apk import APK


MAX_APK_SIZE = 100 * 1024 * 1024

SUSPICIOUS_PERMISSIONS = {
    "SEND_SMS": 10,
    "RECEIVE_SMS": 5,
    "READ_SMS": 5,
    "READ_CALL_LOG": 5,
    "WRITE_CALL_LOG": 5,
    "RECORD_AUDIO": 5,
    "REQUEST_INSTALL_PACKAGES": 5,
    "SYSTEM_ALERT_WINDOW": 5,
    "READ_CONTACTS": 3,
    "READ_PHONE_STATE": 3,
    "ACCESS_FINE_LOCATION": 3,
    "RECEIVE_BOOT_COMPLETED": 1,
}

API_PATTERNS = {
    "SMS sending": ("SmsManager", "sendTextMessage", 5),
    "Runtime command execution": ("Runtime", "exec", 3),
    "Process execution": ("ProcessBuilder", "start", 3),
    "Dynamic code loading": ("DexClassLoader", "loadClass", 8),
    "Reflection": ("java/lang/reflect", "Method", 2),
    "Accessibility service": ("AccessibilityService", "onAccessibilityEvent", 5),
}

DOC_DOMAINS = {
    "developer.android.com",
    "docs.oracle.com",
    "www.w3.org",
    "xml.org",
    "schemas.android.com",
    "spdx.org",
    "slf4j.org",
    "www.slf4j.org",
    "logback.qos.ch",
}

EXAMPLE_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
}


def _extract_urls(apk_bytes):
    urls = set()

    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as archive:
            for name in archive.namelist():
                if not name.endswith(".dex"):
                    continue

                data = archive.read(name)

                for match in re.findall(
                    rb"https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
                    data,
                ):
                    try:
                        url = match.decode("utf-8", errors="ignore").rstrip(".,;)")
                        if len(url) < 2048:
                            urls.add(url)
                    except Exception:
                        continue

    except zipfile.BadZipFile:
        raise ValueError("Invalid APK: file is not a valid ZIP/APK archive.")

    all_urls = sorted(urls)
    documentation = []
    examples = []
    local = []
    external = []

    for url in all_urls:
        try:
            hostname = (urlsplit(url).hostname or "").lower()

            if not hostname:
                continue

            if hostname in DOC_DOMAINS:
                documentation.append(url)
            elif (
                hostname in EXAMPLE_DOMAINS
                or hostname.endswith(".example")
                or hostname.endswith(".test")
                or hostname.endswith(".invalid")
            ):
                examples.append(url)
            elif hostname in {"127.0.0.1", "::1", "0.0.0.0"}:
                local.append(url)
            else:
                external.append(url)

        except Exception:
            continue

    return {
        "all_urls": all_urls,
        "documentation_urls": documentation,
        "example_urls": examples,
        "local_urls": local,
        "external_urls": external,
    }


def _extract_dex_strings(apk_bytes):
    strings = []

    with zipfile.ZipFile(io.BytesIO(apk_bytes)) as archive:
        for name in archive.namelist():
            if name.endswith(".dex"):
                data = archive.read(name)

                decoded = data.decode(
                    "latin-1",
                    errors="ignore",
                )

                strings.append(decoded)

    return "\n".join(strings)


def _extract_exported_components(apk):
    components = []

    try:
        manifest = apk.get_android_manifest_xml()
        application = manifest.find("application")

        if application is None:
            return components

        component_tags = {
            "activity",
            "activity-alias",
            "service",
            "receiver",
            "provider",
        }

        for component in application:
            tag = component.tag.split("}")[-1]

            if tag not in component_tags:
                continue

            name = component.get(
                "{http://schemas.android.com/apk/res/android}name"
            )

            exported = component.get(
                "{http://schemas.android.com/apk/res/android}exported"
            )

            has_intent_filter = any(
                child.tag.split("}")[-1] == "intent-filter"
                for child in component
            )

            is_exported = (
                exported == "true"
                or (
                    exported is None
                    and has_intent_filter
                )
            )

            if is_exported:
                components.append({
                    "type": tag,
                    "name": name,
                    "has_intent_filter": has_intent_filter,
                })

    except Exception:
        pass

    return components


def _extract_certificates(apk):
    certificates = []

    try:
        for certificate in apk.get_certificates():
            certificates.append({
                "subject": str(
                    getattr(certificate, "subject", "")
                ),
                "issuer": str(
                    getattr(certificate, "issuer", "")
                ),
                "serial_number": str(
                    getattr(certificate, "serial_number", "")
                ),
            })

    except Exception:
        pass

    return certificates


def analyze_apk_file(apk_bytes: bytes, file_name: str):
    if not apk_bytes:
        raise ValueError("Uploaded APK is empty.")

    if len(apk_bytes) > MAX_APK_SIZE:
        raise ValueError("APK exceeds the 100 MB limit.")

    if not zipfile.is_zipfile(io.BytesIO(apk_bytes)):
        raise ValueError("Invalid APK file.")

    try:
        apk = APK(apk_bytes, raw=True)
        if not apk.is_valid_APK():
            raise ValueError("APK structure is invalid.")
    except ValueError:
        raise
    except Exception as error:
        raise ValueError(
        f"Unable to parse APK: {type(error).__name__}: {error}"
    ) from error

    if not apk.is_valid_APK():
        raise ValueError("APK structure is invalid.")

    file_hash = hashlib.sha256(apk_bytes).hexdigest()

    try:
        package_name = apk.get_package()
    except Exception:
        package_name = None

    try:
        version_name = apk.get_androidversion_name()
    except Exception:
        version_name = None

    try:
        version_code = apk.get_androidversion_code()
        version_code = int(version_code) if version_code else None
    except Exception:
        version_code = None

    permissions = sorted(set(apk.get_permissions() or []))

    suspicious_permissions = []

    for permission in permissions:
        short_name = permission.split(".")[-1]

        if short_name in SUSPICIOUS_PERMISSIONS:
            suspicious_permissions.append({
                "permission": permission,
                "points": SUSPICIOUS_PERMISSIONS[short_name],
            })

    dex_strings = _extract_dex_strings(apk_bytes)

    suspicious_apis = []

    for label, (token1, token2, points) in API_PATTERNS.items():
        if token1 in dex_strings and token2 in dex_strings:
            suspicious_apis.append({
                "name": label,
                "points": points,
                "evidence": "Matching DEX strings found; not proof of execution.",
            })

    url_analysis = _extract_urls(apk_bytes)
    exported_components = _extract_exported_components(apk)
    signing_certificates = _extract_certificates(apk)

    score = sum(
        item["points"]
        for item in suspicious_permissions
    )

    score += sum(
        item["points"]
        for item in suspicious_apis
    )

    permission_names = {
        item.split(".")[-1]
        for item in permissions
    }

    sms_permissions = {
        "SEND_SMS",
        "RECEIVE_SMS",
        "READ_SMS",
    }

    if len(permission_names.intersection(sms_permissions)) >= 2:
        score += 8

    if (
        "SYSTEM_ALERT_WINDOW" in permission_names
        and any(
            item["type"] == "service"
            for item in exported_components
        )
    ):
        score += 5

    score += min(
        5,
        len(url_analysis["external_urls"]),
    )

    score = min(100, score)

    if score >= 70:
        classification = "MALICIOUS"
        severity = "CRITICAL"
    elif score >= 40:
        classification = "SUSPICIOUS"
        severity = "HIGH"
    elif score >= 20:
        classification = "SUSPICIOUS"
        severity = "MEDIUM"
    else:
        classification = "LOW_RISK"
        severity = "LOW"

    indicators = []

    if suspicious_permissions:
        indicators.append("Sensitive Android permissions detected.")

    if suspicious_apis:
        indicators.append("Potentially sensitive API references detected.")

    if exported_components:
        indicators.append(
            "Exported Android components found; review their access controls."
        )

    if url_analysis["external_urls"]:
        indicators.append("External URLs found inside DEX strings.")

    if not indicators:
        indicators.append(
            "No strong static indicators were detected by these checks."
        )

    evidence = {
        "suspicious_permissions": suspicious_permissions,
        "external_url_count": len(url_analysis["external_urls"]),
        "exported_component_count": len(exported_components),
        "suspicious_api_count": len(suspicious_apis),
    }

    explanation = (
        f"Static APK analysis identified {len(suspicious_permissions)} "
        f"sensitive permission indicators, {len(suspicious_apis)} "
        f"potentially sensitive API references and "
        f"{len(url_analysis['external_urls'])} external URLs. "
        f"Calculated heuristic risk score: {score}/100."
    )

    recommendation = (
        "Review sensitive permissions, exported components, API references "
        "and embedded URLs. Do not install an APK from an untrusted source."
        if score >= 20
        else
        "No strong indicators were detected by the current static checks. "
        "This does not guarantee that the APK is safe."
    )

    return {
        "file_name": file_name,
        "file_hash": file_hash,
        "file_size": len(apk_bytes),
        "package_name": package_name,
        "version_name": version_name,
        "version_code": version_code,
        "permissions": permissions,
        "suspicious_apis": suspicious_apis,
        "suspicious_permissions": suspicious_permissions,
        "exported_components": exported_components,
        "signing_certificates": signing_certificates,
        "extracted_urls": url_analysis["all_urls"],
        "url_analysis": url_analysis,
        "evidence": evidence,
        "risk_score": score,
        "classification": classification,
        "severity": severity,
        "confidence": None,
        "indicators": indicators,
        "explanation": explanation,
        "recommendation": recommendation,
    }
