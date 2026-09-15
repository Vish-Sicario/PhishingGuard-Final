import ipaddress
import math
import re
import socket
import ssl
from collections import Counter
from urllib.parse import urljoin, urlparse, urlunparse, unquote

import requests
import tensorflow as tf
import tldextract
from bs4 import BeautifulSoup


MODEL_PATH = "phishing_url_detector.keras"

MAX_REDIRECTS = 3
MAX_DOWNLOAD_BYTES = 1_000_000
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}


# ============================================================
# MODEL
# ============================================================

model = tf.keras.models.load_model(MODEL_PATH)


def cnn_phishing_score(url):
    prediction = model(
        tf.constant([url], dtype=tf.string),
        training=False
    )

    probability = float(
        prediction.numpy().reshape(-1)[0]
    )

    probability = max(
        0.0,
        min(1.0, probability)
    )

    return round(
        probability * 100,
        2
    )


# ============================================================
# CNN INPUT PREPROCESSING
# ============================================================

def prepare_url_for_cnn(url):
    """
    Normalize superficial root-path formatting before CNN inference.
    Does not modify hostname, protocol, query string or real URL paths.
    """

    parsed = urlparse(url)

    if parsed.path == "/" and not parsed.params:
        parsed = parsed._replace(path="")

    return urlunparse(parsed)


def stable_cnn_phishing_score(url):

    cnn_input = prepare_url_for_cnn(url)

    score = cnn_phishing_score(cnn_input)

    return score, cnn_input



# ============================================================
# URL VALIDATION / SSRF PROTECTION
# ============================================================

def normalize_url(raw_url):

    if not isinstance(raw_url, str):
        raise ValueError("URL must be text.")

    url = raw_url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(
            "Only HTTP and HTTPS websites can be analysed."
        )

    if not parsed.hostname:
        raise ValueError(
            "A valid hostname is required."
        )

    if parsed.username or parsed.password:
        raise ValueError(
            "URLs containing embedded credentials are not allowed."
        )

    try:
        port = parsed.port
    except ValueError:
        raise ValueError(
            "Invalid port number."
        )

    if port and port not in ALLOWED_PORTS:
        raise ValueError(
            "Only standard web ports 80 and 443 are allowed."
        )

    parsed = parsed._replace(
        fragment=""
    )

    return urlunparse(parsed)


def hostname_is_private(hostname):

    host = hostname.lower().rstrip(".")

    if host in {
        "localhost",
        "localhost.localdomain"
    }:
        return True

    if (
        host.endswith(".localhost")
        or host.endswith(".local")
        or host.endswith(".internal")
    ):
        return True

    try:
        ip = ipaddress.ip_address(host)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

    except ValueError:
        pass

    try:
        addresses = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM
        )

    except socket.gaierror:
        raise ValueError(
            "Website hostname could not be resolved."
        )

    for address in addresses:

        ip_text = address[4][0]

        ip = ipaddress.ip_address(
            ip_text
        )

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True

    return False


def validate_public_url(raw_url):

    url = normalize_url(raw_url)

    hostname = urlparse(
        url
    ).hostname

    if hostname_is_private(hostname):
        raise ValueError(
            "Private, local or reserved "
            "network addresses cannot be analysed."
        )

    return url


# ============================================================
# SAFE WEBSITE FETCH
# ============================================================

def safe_fetch(raw_url):

    current_url = validate_public_url(
        raw_url
    )

    session = requests.Session()
    session.trust_env = False

    headers = {
        "User-Agent":
        "Mozilla/5.0 "
        "(compatible; PhishingGuard/1.0; "
        "Cybersecurity Research)"
    }

    redirect_chain = []

    for redirect_number in range(
        MAX_REDIRECTS + 1
    ):

        response = session.get(
            current_url,
            headers=headers,
            timeout=(4, 8),
            allow_redirects=False,
            stream=True
        )

        if response.status_code in {
            301, 302, 303, 307, 308
        }:

            location = response.headers.get(
                "Location"
            )

            if not location:
                response.close()
                raise ValueError(
                    "Invalid redirect."
                )

            if redirect_number >= MAX_REDIRECTS:
                response.close()
                raise ValueError(
                    "Maximum redirect limit exceeded."
                )

            next_url = urljoin(
                current_url,
                location
            )

            # Validate EVERY redirect
            next_url = validate_public_url(
                next_url
            )

            redirect_chain.append({
                "from": current_url,
                "to": next_url,
                "status": response.status_code
            })

            response.close()

            current_url = next_url

            continue

        content_type = (
            response.headers
            .get("Content-Type", "")
            .lower()
        )

        content = bytearray()

        for chunk in response.iter_content(
            chunk_size=16384
        ):

            if not chunk:
                continue

            remaining = (
                MAX_DOWNLOAD_BYTES
                - len(content)
            )

            if remaining <= 0:
                break

            content.extend(
                chunk[:remaining]
            )

        body = bytes(content)

        response.close()

        return {
            "final_url": current_url,
            "status_code":
                response.status_code,

            "redirect_chain":
                redirect_chain,

            "redirect_count":
                len(redirect_chain),

            "content_type":
                content_type,

            "content":
                body,

            "downloaded_bytes":
                len(body)
        }

    raise ValueError(
        "Unable to complete website request."
    )


# ============================================================
# LEXICAL INTELLIGENCE
# ============================================================

SUSPICIOUS_WORDS = [
    "login", "signin", "verify",
    "verification", "secure",
    "account", "update", "confirm",
    "password", "credential",
    "bank", "wallet", "payment",
    "invoice", "support", "unlock",
    "suspended", "limited", "urgent",
    "security"
]


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly"
}


def domain_name(host):

    extracted = tldextract.extract(
        host or ""
    )

    return (
        extracted.top_domain_under_public_suffix
        or host
        or ""
    )


def entropy(text):

    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length)
        * math.log2(count / length)
        for count in counts.values()
    )


def lexical_analysis(url):

    parsed = urlparse(url)

    host = (
        parsed.hostname or ""
    ).lower()

    path = unquote(
        parsed.path or ""
    ).lower()

    query = unquote(
        parsed.query or ""
    ).lower()

    full_text = (
        host + path + query
    )

    extracted = tldextract.extract(
        host
    )

    registered_domain = (
        extracted.top_domain_under_public_suffix
        or host
    )

    subdomains = [
        item
        for item
        in extracted.subdomain.split(".")
        if item
    ]

    score = 0
    reasons = []

    try:
        ipaddress.ip_address(host)

        score += 30
        reasons.append(
            "Raw IP address used instead "
            "of a normal domain."
        )

    except ValueError:
        pass

    if "xn--" in host:
        score += 20
        reasons.append(
            "Punycode detected in domain."
        )

    if "@" in url:
        score += 20
        reasons.append(
            "@ symbol detected in URL."
        )

    if len(url) >= 100:
        score += 15
        reasons.append(
            "URL is unusually long."
        )

    elif len(url) >= 75:
        score += 8
        reasons.append(
            "URL is relatively long."
        )

    if len(subdomains) >= 3:
        score += 15
        reasons.append(
            "Large number of subdomains detected."
        )

    elif len(subdomains) == 2:
        score += 7
        reasons.append(
            "Multiple subdomains detected."
        )

    hyphen_count = host.count("-")

    if hyphen_count >= 3:
        score += 12
        reasons.append(
            "Domain contains many hyphens."
        )

    elif hyphen_count:
        score += 4
        reasons.append(
            "Domain contains hyphens."
        )

    digit_count = sum(
        character.isdigit()
        for character in host
    )

    if digit_count >= 5:
        score += 10
        reasons.append(
            "Domain contains many numbers."
        )

    if "%" in url:
        score += 8
        reasons.append(
            "Encoded characters detected."
        )

    suspicious_words = sorted({
        word
        for word in SUSPICIOUS_WORDS
        if word in full_text
    })

    if suspicious_words:

        score += min(
            25,
            len(suspicious_words) * 5
        )

        reasons.append(
            "Suspicious phishing-related "
            "terms detected: "
            + ", ".join(
                suspicious_words[:8]
            )
        )

    if registered_domain in SHORTENERS:
        score += 20
        reasons.append(
            "URL shortening service detected."
        )

    domain_entropy = entropy(host)

    if domain_entropy > 4.3:
        score += 10
        reasons.append(
            "High domain character randomness detected."
        )

    path_depth = len([
        item
        for item
        in parsed.path.split("/")
        if item
    ])

    if path_depth >= 5:
        score += 8
        reasons.append(
            "Deeply nested URL path detected."
        )

    return {
        "score":
            min(100, score),

        "registered_domain":
            registered_domain,

        "hostname":
            host,

        "url_length":
            len(url),

        "subdomain_count":
            len(subdomains),

        "hyphen_count":
            hyphen_count,

        "digit_count":
            digit_count,

        "path_depth":
            path_depth,

        "entropy":
            round(domain_entropy, 3),

        "suspicious_words":
            suspicious_words,

        "reasons":
            reasons
    }


# ============================================================
# TLS INTELLIGENCE
# ============================================================

def get_tls_information(hostname):

    result = {
        "checked": False,
        "valid": False,
        "issuer": None,
        "subject": None,
        "expires": None,
        "error": None
    }

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:

                certificate = (
                    secure_socket.getpeercert()
                )

                issuer = dict(
                    item[0]
                    for item
                    in certificate.get(
                        "issuer", []
                    )
                )

                subject = dict(
                    item[0]
                    for item
                    in certificate.get(
                        "subject", []
                    )
                )

                result.update({
                    "checked": True,
                    "valid": True,
                    "issuer":
                        issuer.get(
                            "organizationName",
                            issuer.get("commonName")
                        ),
                    "subject":
                        subject.get("commonName"),
                    "expires":
                        certificate.get("notAfter")
                })

    except Exception as exc:

        result["checked"] = True
        result["error"] = str(exc)

    return result


# ============================================================
# LIVE WEBSITE INTELLIGENCE
# ============================================================

SUSPICIOUS_PAGE_TERMS = [
    "verify your account",
    "confirm your account",
    "account suspended",
    "account locked",
    "urgent action required",
    "verify your identity",
    "confirm your identity",
    "update your payment",
    "update your account",
    "security alert",
    "unusual activity",
    "password expired"
]


def live_website_analysis(url):

    result = {
        "available": False,
        "final_url": None,
        "http_status": None,
        "redirect_count": 0,

        "https": False,

        "tls": {
            "checked": False,
            "valid": False,
            "issuer": None,
            "subject": None,
            "expires": None,
            "error": None
        },

        "forms": 0,
        "password_fields": 0,
        "email_fields": 0,
        "hidden_fields": 0,
        "iframes": 0,

        "external_form_actions": 0,
        "insecure_form_actions": 0,

        "total_links": 0,
        "external_links": 0,
        "external_link_ratio": 0,

        "suspicious_phrases": [],

        "risk_score": 0,
        "reasons": [],
        "error": None
    }

    try:

        fetched = safe_fetch(url)

        result["available"] = True

        result["final_url"] = (
            fetched["final_url"]
        )

        result["http_status"] = (
            fetched["status_code"]
        )

        result["redirect_count"] = (
            fetched["redirect_count"]
        )

        final_parsed = urlparse(
            fetched["final_url"]
        )

        result["https"] = (
            final_parsed.scheme == "https"
        )

        if (
            result["https"]
            and final_parsed.hostname
        ):
            result["tls"] = get_tls_information(
                final_parsed.hostname
            )

        if not result["https"]:

            result["risk_score"] += 15

            result["reasons"].append(
                "Website is not using HTTPS."
            )

        if (
            result["https"]
            and result["tls"]["checked"]
            and not result["tls"]["valid"]
        ):

            result["risk_score"] += 15

            result["reasons"].append(
                "TLS certificate validation failed."
            )

        if fetched["redirect_count"] >= 3:

            result["risk_score"] += 8

            result["reasons"].append(
                "Multiple redirects detected."
            )

        content_type = fetched[
            "content_type"
        ]

        if (
            "html" not in content_type
            and fetched["content"]
        ):

            result["risk_score"] = min(
                100,
                result["risk_score"]
            )

            return result

        html = fetched[
            "content"
        ].decode(
            "utf-8",
            errors="ignore"
        )

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

        forms = soup.find_all(
            "form"
        )

        result["forms"] = len(
            forms
        )

        password_fields = soup.find_all(
            "input",
            attrs={"type": "password"}
        )

        result["password_fields"] = len(
            password_fields
        )

        email_fields = soup.find_all(
            "input",
            attrs={"type": "email"}
        )

        result["email_fields"] = len(
            email_fields
        )

        hidden_fields = soup.find_all(
            "input",
            attrs={"type": "hidden"}
        )

        result["hidden_fields"] = len(
            hidden_fields
        )

        iframes = soup.find_all(
            "iframe"
        )

        result["iframes"] = len(
            iframes
        )

        current_domain = domain_name(
            final_parsed.hostname
        )

        for form in forms:

            action = (
                form.get("action")
                or ""
            ).strip()

            if not action:
                continue

            action_url = urljoin(
                fetched["final_url"],
                action
            )

            action_parsed = urlparse(
                action_url
            )

            action_domain = domain_name(
                action_parsed.hostname
            )

            if (
                action_domain
                and current_domain
                and action_domain
                != current_domain
            ):

                result[
                    "external_form_actions"
                ] += 1

            if (
                action_parsed.scheme == "http"
                and result["https"]
            ):

                result[
                    "insecure_form_actions"
                ] += 1

        if result["external_form_actions"]:

            result["risk_score"] += 25

            result["reasons"].append(
                "Form submits data to an external domain."
            )

        if result["insecure_form_actions"]:

            result["risk_score"] += 25

            result["reasons"].append(
                "Secure page submits a form over HTTP."
            )

        if result["password_fields"]:

            result["risk_score"] += 8

            result["reasons"].append(
                "Password input field detected."
            )

        if (
            result["password_fields"]
            and not result["https"]
        ):

            result["risk_score"] += 30

            result["reasons"].append(
                "Password field is present on a non-HTTPS page."
            )

        if result["iframes"] >= 3:

            result["risk_score"] += 8

            result["reasons"].append(
                "Multiple embedded frames detected."
            )

        page_text = soup.get_text(
            " ",
            strip=True
        ).lower()

        suspicious_phrases = [
            phrase
            for phrase in SUSPICIOUS_PAGE_TERMS
            if phrase in page_text
        ]

        result["suspicious_phrases"] = (
            suspicious_phrases
        )

        if suspicious_phrases:

            result["risk_score"] += min(
                20,
                len(suspicious_phrases) * 5
            )

            result["reasons"].append(
                "Suspicious account or security language detected on page."
            )

        links = soup.find_all(
            "a",
            href=True
        )

        result["total_links"] = len(
            links
        )

        external_links = 0

        for link in links:

            href = link.get(
                "href"
            )

            absolute = urljoin(
                fetched["final_url"],
                href
            )

            link_parsed = urlparse(
                absolute
            )

            link_domain = domain_name(
                link_parsed.hostname
            )

            if (
                link_domain
                and current_domain
                and link_domain
                != current_domain
            ):
                external_links += 1

        result["external_links"] = (
            external_links
        )

        if result["total_links"]:

            ratio = (
                external_links
                / result["total_links"]
            )

            result[
                "external_link_ratio"
            ] = round(
                ratio,
                3
            )

            if (
                result["total_links"] >= 10
                and ratio >= 0.75
            ):

                result["risk_score"] += 8

                result["reasons"].append(
                    "Very high proportion of external links detected."
                )

        result["risk_score"] = min(
            100,
            result["risk_score"]
        )

    except Exception as exc:

        result["error"] = str(exc)

    return result


# ============================================================
# DECISION ENGINE
# ============================================================

def get_risk_level(score):

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 35:
        return "MEDIUM"

    return "LOW"


def get_recommendation(level):

    recommendations = {
        "LOW": (
            "No strong phishing indicators were detected. "
            "Remain cautious and verify unexpected requests."
        ),

        "MEDIUM": (
            "Some suspicious indicators were detected. "
            "Verify the website before entering personal information."
        ),

        "HIGH": (
            "Multiple phishing indicators were detected. "
            "Avoid entering credentials or payment information."
        ),

        "CRITICAL": (
            "Strong phishing indicators were detected. "
            "Do not interact with the website or submit sensitive data."
        )
    }

    return recommendations[level]


def scan_url(raw_url):

    # Validate BEFORE model/live analysis
    url = validate_public_url(
        raw_url
    )

    # Analyse lexical characteristics of the ORIGINAL submitted URL.
    # This preserves suspicious indicators that may exist before redirects.
    lexical = lexical_analysis(
        url
    )

    # Safely inspect the website and follow validated redirects.
    live = live_website_analysis(
        url
    )

    live_score = (
        live["risk_score"]
        if live["available"]
        else 0
    )

    # CNN analyses the validated final destination when available.
    # This prevents superficial redirect/canonicalisation differences
    # from producing inconsistent predictions.
    cnn_target_url = (
        live["final_url"]
        if live["available"] and live.get("final_url")
        else url
    )

    cnn_score, cnn_input = stable_cnn_phishing_score(
        cnn_target_url
    )

    overall = (
        0.62 * cnn_score
        + 0.20 * lexical["score"]
        + 0.18 * live_score
    )

    overall = min(
        100,
        max(0, overall)
    )

    # Cross-layer corroboration guard.
    # A very high CNN score is not allowed to create a HIGH/CRITICAL
    # verdict by itself when both independent analysis layers are clean
    # and the live site presents a valid HTTPS/TLS connection. This is
    # domain-agnostic: no trusted-site allowlist or hard-coded domain is used.
    cnn_uncorroborated = (
        cnn_score >= 80
        and lexical["score"] < 10
        and live_score < 10
        and live["available"]
        and live["https"]
        and live["tls"]["valid"]
        and not live["external_form_actions"]
        and not live["insecure_form_actions"]
        and not (
            live["password_fields"]
            and not live["https"]
        )
    )

    if cnn_uncorroborated:
        overall = min(overall, 24.99)

    # Safety overrides

    if live["external_form_actions"]:
        overall = max(
            overall,
            60
        )

    if live["insecure_form_actions"]:
        overall = max(
            overall,
            65
        )

    if (
        live["password_fields"]
        and not live["https"]
    ):
        overall = max(
            overall,
            70
        )

    if lexical["score"] >= 70:
        overall = max(
            overall,
            60
        )

    overall = round(
        overall,
        2
    )

    risk_level = get_risk_level(
        overall
    )

    reasons = []

    reasons.extend(
        lexical["reasons"]
    )

    reasons.extend(
        live["reasons"]
    )

    if cnn_uncorroborated:

        reasons.insert(
            0,
            "The deep-learning model flagged a URL pattern, "
            "but independent URL and live-site checks did not "
            "corroborate a strong phishing risk."
        )

    elif cnn_score >= 80:

        reasons.insert(
            0,
            "Deep-learning model detected "
            "a very strong phishing pattern."
        )

    elif cnn_score >= 60:

        reasons.insert(
            0,
            "Deep-learning model detected "
            "a strong phishing pattern."
        )

    elif cnn_score >= 35:

        reasons.insert(
            0,
            "Deep-learning model detected "
            "some suspicious URL patterns."
        )

    if not reasons:

        reasons.append(
            "No major phishing indicators "
            "were detected by the analysis layers."
        )

    reasons = list(
        dict.fromkeys(reasons)
    )

    return {
        "url":
            url,

        "overall_risk_score":
            overall,

        "risk_level":
            risk_level,

        "cnn_phishing_score":
            cnn_score,

        "cnn_input":
            cnn_input,

        "lexical_risk_score":
            lexical["score"],

        "live_website_risk_score":
            live_score,

        "registered_domain":
            lexical["registered_domain"],

        "hostname":
            lexical["hostname"],

        "website_available":
            live["available"],

        "final_url":
            live["final_url"],

        "http_status":
            live["http_status"],

        "https":
            live["https"],

        "tls_valid":
            live["tls"]["valid"],

        "tls_issuer":
            live["tls"]["issuer"],

        "tls_expires":
            live["tls"]["expires"],

        "redirect_count":
            live["redirect_count"],

        "forms":
            live["forms"],

        "password_fields":
            live["password_fields"],

        "email_fields":
            live["email_fields"],

        "hidden_fields":
            live["hidden_fields"],

        "iframes":
            live["iframes"],

        "external_form_actions":
            live["external_form_actions"],

        "insecure_form_actions":
            live["insecure_form_actions"],

        "total_links":
            live["total_links"],

        "external_links":
            live["external_links"],

        "external_link_ratio":
            live["external_link_ratio"],

        "suspicious_phrases":
            live["suspicious_phrases"],

        "reasons":
            reasons[:8],

        "recommendation":
            get_recommendation(
                risk_level
            ),

        "engine":
            "CNN + URL Intelligence + Live Website Analysis",

        "disclaimer": (
            "Automated security assessment based on detected risk indicators. "
            "Results do not guarantee that a website is safe or malicious."
        )
    }
