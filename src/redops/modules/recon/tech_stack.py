"""
Technology stack fingerprinting module.

Identifies web technologies, frameworks, and libraries used by a target
through HTTP header analysis, HTML inspection, and favicon fingerprinting.
"""

from typing import Any
import hashlib
import re
import ssl
import socket
from urllib.parse import urlparse
from redops.core.context import Context
from redops.core.models import TechStack, Finding, RiskLevel

# Try to import requests for HTTP functionality
try:
    import requests
    from requests.exceptions import RequestException, SSLError, Timeout

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# Known favicon hashes mapped to technologies (Shodan-style)
FAVICON_HASHES = {
    "f3418a443e7d841097c714d69ec4bcb8": "Apache Default",
    "4e98db578e1e94ac7a6c9e6d0add9659": "IIS Default",
    "1b6499d782f8bf6dd1c2dbb42c8d1a41": "Tomcat",
    "a141e2d4c6e1e4e4b6f8e1b9c9b8b9b1": "WordPress",
    "e965bf68a4d4b5b3b5c5a5b5c5b5a5b5": "Drupal",
}

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HSTS - Enforces HTTPS connections",
        "severity": RiskLevel.MEDIUM,
    },
    "Content-Security-Policy": {
        "description": "CSP - Prevents XSS and injection attacks",
        "severity": RiskLevel.MEDIUM,
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": RiskLevel.LOW,
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": RiskLevel.LOW,
    },
    "X-XSS-Protection": {
        "description": "Browser XSS filter (legacy)",
        "severity": RiskLevel.INFO,
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": RiskLevel.LOW,
    },
    "Permissions-Policy": {
        "description": "Controls browser features access",
        "severity": RiskLevel.LOW,
    },
}

# Technology detection patterns
TECH_PATTERNS = {
    # Frontend frameworks
    "React": [
        r"react(?:\.min)?\.js",
        r"react-dom",
        r"data-reactroot",
        r"__REACT_DEVTOOLS",
        r"_reactRootContainer",
    ],
    "Vue.js": [
        r"vue(?:\.min)?\.js",
        r"data-v-[a-f0-9]+",
        r"__VUE__",
        r"Vue\.component",
    ],
    "Angular": [
        r"angular(?:\.min)?\.js",
        r"ng-app",
        r"ng-controller",
        r"ng-version",
        r"\[\(ngModel\)\]",
    ],
    "jQuery": [
        r"jquery(?:\.min)?\.js",
        r"jQuery\s*\(",
        r"\$\s*\(\s*document\s*\)",
    ],
    "Bootstrap": [
        r"bootstrap(?:\.min)?\.(?:js|css)",
        r'class="[^"]*\b(?:container|row|col-)',
    ],
    "Tailwind CSS": [
        r"tailwind(?:css)?(?:\.min)?\.css",
        r'class="[^"]*\b(?:flex|grid|p-\d|m-\d|text-)',
    ],
    # CMS
    "WordPress": [
        r"wp-content",
        r"wp-includes",
        r"wp-json",
        r'<meta name="generator" content="WordPress',
    ],
    "Drupal": [
        r"Drupal\.settings",
        r"/sites/default/files",
        r'<meta name="Generator" content="Drupal',
    ],
    "Joomla": [
        r"/media/jui/",
        r'<meta name="generator" content="Joomla',
        r"option=com_",
    ],
    "Shopify": [
        r"cdn\.shopify\.com",
        r"Shopify\.theme",
        r"myshopify\.com",
    ],
    # Backend frameworks
    "Django": [
        r"csrfmiddlewaretoken",
        r"__admin_media_prefix__",
        r"django",
    ],
    "Ruby on Rails": [
        r"csrf-token",
        r"data-turbolinks",
        r"rails-ujs",
        r"X-CSRF-Token",
    ],
    "Laravel": [
        r"laravel_session",
        r"XSRF-TOKEN",
        r"laravel",
    ],
    "Express.js": [
        r"X-Powered-By:\s*Express",
    ],
    "ASP.NET": [
        r"__VIEWSTATE",
        r"__EVENTVALIDATION",
        r"asp\.net",
        r"X-AspNet-Version",
    ],
    # Analytics & tracking
    "Google Analytics": [
        r"google-analytics\.com/analytics\.js",
        r"googletagmanager\.com",
        r"gtag\(",
        r"_gaq\.push",
    ],
    "Google Tag Manager": [
        r"googletagmanager\.com/gtm\.js",
        r"GTM-[A-Z0-9]+",
    ],
    "Facebook Pixel": [
        r"connect\.facebook\.net",
        r"fbq\(",
        r"facebook\.com/tr",
    ],
    # CDNs
    "Cloudflare": [
        r"cloudflare",
        r"cf-ray",
        r"__cfduid",
    ],
    "Fastly": [
        r"fastly",
        r"X-Served-By:.*cache-",
    ],
    "Akamai": [
        r"akamai",
        r"X-Akamai-",
    ],
}

# Web server patterns from Server header
SERVER_PATTERNS = {
    r"nginx/?(\d+\.[\d.]+)?": "nginx",
    r"Apache/?(\d+\.[\d.]+)?": "Apache",
    r"Microsoft-IIS/?(\d+\.[\d.]+)?": "IIS",
    r"LiteSpeed": "LiteSpeed",
    r"cloudflare": "Cloudflare",
    r"gws": "Google Web Server",
    r"openresty/?(\d+\.[\d.]+)?": "OpenResty",
    r"gunicorn/?(\d+\.[\d.]+)?": "Gunicorn",
    r"uvicorn": "Uvicorn",
    r"Werkzeug/?(\d+\.[\d.]+)?": "Werkzeug (Flask)",
    r"Kestrel": "Kestrel (ASP.NET)",
    r"Caddy": "Caddy",
}


def fingerprint(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Fingerprint the technology stack of a target.

    Performs:
    - HTTP/HTTPS request to target
    - HTTP header analysis (Server, X-Powered-By, security headers)
    - HTML content analysis for framework detection
    - Favicon hash fingerprinting
    - SSL/TLS certificate analysis

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - target: Override target
            - timeout: Request timeout in seconds (default: 10)
            - follow_redirects: Follow HTTP redirects (default: True)
            - verify_ssl: Verify SSL certificates (default: True)

    Returns:
        Updated context with tech_stack data
    """
    params = params or {}
    target = params.get("target") or ctx.target
    timeout = params.get("timeout", 10)
    follow_redirects = params.get("follow_redirects", True)
    verify_ssl = params.get("verify_ssl", True)

    if not target:
        ctx.log("No target specified for tech stack fingerprinting", level="WARNING")
        return ctx

    if not REQUESTS_AVAILABLE:
        ctx.log(
            "requests library not available - install with: pip install requests",
            level="WARNING",
        )
        ctx.add("tech_stack", TechStack().model_dump())
        return ctx

    ctx.log(f"Fingerprinting tech stack for: {target}", level="INFO")

    # Normalize target URL
    url = normalize_url(target)
    ctx.log(f"Target URL: {url}", level="DEBUG")

    # Initialize tech stack
    tech_stack = TechStack(
        web_server=None,
        frameworks=[],
        languages=[],
        libraries=[],
        headers={},
        fingerprints={},
    )

    detected_techs = set()
    findings = []

    # Make HTTP request
    try:
        response = make_request(
            url,
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify_ssl=verify_ssl,
        )

        if response:
            # Analyze headers
            headers_analysis = analyze_headers(dict(response.headers))
            tech_stack.headers = dict(response.headers)

            # Extract web server
            if headers_analysis["server"] != "Unknown":
                tech_stack.web_server = headers_analysis["server"]
                ctx.log(f"Web server: {tech_stack.web_server}", level="INFO")

            # Check X-Powered-By
            if headers_analysis["powered_by"] != "Unknown":
                detected_techs.add(headers_analysis["powered_by"])
                ctx.log(f"Powered by: {headers_analysis['powered_by']}", level="INFO")

            # Check for missing security headers
            missing_security = check_security_headers(dict(response.headers))
            if missing_security:
                ctx.log(
                    f"Missing security headers: {list(missing_security.keys())}",
                    level="WARNING",
                )

                for header, info in missing_security.items():
                    finding = Finding(
                        module="recon.tech_stack",
                        title=f"Missing Security Header: {header}",
                        description=f"{info['description']}. This header is not present.",
                        severity=info["severity"],
                        data={
                            "header": header,
                            "recommendation": f"Add {header} header",
                        },
                    )
                    findings.append(finding)

            # Analyze HTML content for frameworks
            if response.text:
                html_techs = detect_technologies(response.text, dict(response.headers))
                detected_techs.update(html_techs)

                if html_techs:
                    ctx.log(
                        f"Detected technologies from HTML: {html_techs}", level="INFO"
                    )

            # Store response info
            tech_stack.fingerprints["status_code"] = response.status_code
            tech_stack.fingerprints["content_length"] = len(response.content)
            tech_stack.fingerprints["content_type"] = response.headers.get(
                "Content-Type", ""
            )

    except SSLError as e:
        ctx.log(f"SSL error connecting to {url}: {e}", level="WARNING")
        tech_stack.fingerprints["ssl_error"] = str(e)
    except Timeout:
        ctx.log(f"Timeout connecting to {url}", level="WARNING")
        tech_stack.fingerprints["timeout"] = True
    except RequestException as e:
        ctx.log(f"Error connecting to {url}: {e}", level="WARNING")
        tech_stack.fingerprints["connection_error"] = str(e)

    # Try to fetch and hash favicon
    favicon_result = fetch_favicon_hash(url, timeout=timeout, verify_ssl=verify_ssl)
    if favicon_result:
        favicon_hash, favicon_tech = favicon_result
        tech_stack.fingerprints["favicon_hash"] = favicon_hash
        if favicon_tech:
            detected_techs.add(favicon_tech)
            ctx.log(f"Favicon identified: {favicon_tech}", level="INFO")

    # Get SSL certificate info
    ssl_info = get_ssl_info(target)
    if ssl_info:
        tech_stack.fingerprints["ssl"] = ssl_info
        ctx.log(f"SSL issuer: {ssl_info.get('issuer', 'Unknown')}", level="DEBUG")

    # Categorize detected technologies
    frameworks = []
    libraries = []
    for tech in detected_techs:
        if tech in [
            "React",
            "Vue.js",
            "Angular",
            "Django",
            "Ruby on Rails",
            "Laravel",
            "Express.js",
            "ASP.NET",
            "WordPress",
            "Drupal",
            "Joomla",
            "Shopify",
        ]:
            frameworks.append(tech)
        else:
            libraries.append(tech)

    tech_stack.frameworks = sorted(frameworks)
    tech_stack.libraries = sorted(libraries)

    # Create finding for detected technologies
    if detected_techs:
        finding = Finding(
            module="recon.tech_stack",
            title=f"Technology Stack Identified for {target}",
            description=f"Detected {len(detected_techs)} technologies",
            severity=RiskLevel.INFO,
            data={
                "web_server": tech_stack.web_server,
                "frameworks": tech_stack.frameworks,
                "libraries": tech_stack.libraries,
            },
        )
        findings.append(finding)

    # Check for version disclosure (potential vulnerability)
    version_disclosure = check_version_disclosure(
        tech_stack.headers, tech_stack.web_server
    )
    if version_disclosure:
        ctx.log(f"Version disclosure detected: {version_disclosure}", level="WARNING")
        finding = Finding(
            module="recon.tech_stack",
            title="Server Version Disclosure",
            description="Server is disclosing version information which may aid attackers",
            severity=RiskLevel.LOW,
            data={"disclosed_versions": version_disclosure},
        )
        findings.append(finding)

    # Add findings to context
    for i, finding in enumerate(findings):
        ctx.add(f"finding_tech_{i}_{target}", finding.model_dump())

    ctx.add("tech_stack", tech_stack.model_dump())
    ctx.log(
        f"Tech stack fingerprinting completed: {len(detected_techs)} technologies detected",
        level="INFO",
    )

    return ctx


def normalize_url(target: str) -> str:
    """
    Normalize a target to a proper URL.

    Args:
        target: Domain, IP, or URL

    Returns:
        Normalized URL with scheme
    """
    if target.startswith(("http://", "https://")):
        return target

    # Default to HTTPS
    return f"https://{target}"


def make_request(
    url: str, timeout: int = 10, follow_redirects: bool = True, verify_ssl: bool = True
) -> Any | None:
    """
    Make an HTTP request to a URL.

    Args:
        url: URL to request
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow redirects
        verify_ssl: Whether to verify SSL certificates

    Returns:
        Response object or None on failure
    """
    if not REQUESTS_AVAILABLE:
        return None

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=follow_redirects,
            verify=verify_ssl,
        )
        return response
    except (OSError, RuntimeError, TypeError, ValueError, ConnectionError):
        # Try HTTP if HTTPS fails
        if url.startswith("https://"):
            try:
                http_url = url.replace("https://", "http://")
                response = requests.get(
                    http_url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=follow_redirects,
                )
                return response
            except (OSError, RuntimeError, TypeError, ValueError, ConnectionError):
                pass
        return None


def analyze_headers(headers: dict[str, str]) -> dict[str, Any]:
    """
    Analyze HTTP headers to identify technologies.

    Args:
        headers: HTTP headers to analyze

    Returns:
        Analysis results with server info and security headers
    """
    # Normalize header keys to title case for consistent access
    normalized = {k.title(): v for k, v in headers.items()}

    analysis = {
        "server": "Unknown",
        "powered_by": "Unknown",
        "framework_hints": [],
        "security_headers": {},
    }

    # Parse Server header
    server_value = normalized.get("Server", "")
    if server_value:
        for pattern, server_name in SERVER_PATTERNS.items():
            match = re.search(pattern, server_value, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else ""
                analysis["server"] = (
                    f"{server_name}/{version}" if version else server_name
                )
                break
        if analysis["server"] == "Unknown":
            analysis["server"] = server_value

    # Check X-Powered-By
    powered_by = normalized.get("X-Powered-By", "")
    if powered_by:
        analysis["powered_by"] = powered_by

    # Collect present security headers
    for header in SECURITY_HEADERS:
        if header in normalized:
            analysis["security_headers"][header] = normalized[header]

    return analysis


def check_security_headers(headers: dict[str, str]) -> dict[str, dict[str, Any]]:
    """
    Check for missing security headers.

    Args:
        headers: HTTP headers to check

    Returns:
        Dictionary of missing headers with their info
    """
    normalized = {k.lower(): v for k, v in headers.items()}
    missing = {}

    for header, info in SECURITY_HEADERS.items():
        if header.lower() not in normalized:
            missing[header] = info

    return missing


def detect_technologies(html: str, headers: dict[str, str]) -> list[str]:
    """
    Detect technologies from HTML content and headers.

    Args:
        html: HTML content to analyze
        headers: HTTP headers

    Returns:
        List of detected technology names
    """
    detected = []
    combined = html + " " + " ".join(f"{k}: {v}" for k, v in headers.items())

    for tech, patterns in TECH_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                detected.append(tech)
                break

    return detected


def fetch_favicon_hash(
    url: str, timeout: int = 10, verify_ssl: bool = True
) -> tuple[str, str | None] | None:
    """
    Fetch and hash the favicon for fingerprinting.

    Args:
        url: Base URL
        timeout: Request timeout
        verify_ssl: Whether to verify SSL

    Returns:
        Tuple of (hash, identified_technology) or None
    """
    if not REQUESTS_AVAILABLE:
        return None

    # Common favicon locations
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    favicon_urls = [
        f"{base_url}/favicon.ico",
        f"{base_url}/favicon.png",
    ]

    for favicon_url in favicon_urls:
        try:
            response = requests.get(
                favicon_url,
                timeout=timeout,
                verify=verify_ssl,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if response.status_code == 200 and len(response.content) > 0:
                hash_value = favicon_hash(response.content)

                # Check against known hashes
                identified = FAVICON_HASHES.get(hash_value)
                return (hash_value, identified)
        except (OSError, RuntimeError, TypeError, ValueError, ConnectionError):
            continue

    return None


def favicon_hash(favicon_bytes: bytes) -> str:
    """
    Calculate MD5 hash of favicon for fingerprinting.

    Args:
        favicon_bytes: Raw bytes of the favicon

    Returns:
        MD5 hash string
    """
    return hashlib.md5(favicon_bytes).hexdigest()


def get_ssl_info(target: str) -> dict[str, Any] | None:
    """
    Get SSL/TLS certificate information.

    Args:
        target: Domain or IP

    Returns:
        Dictionary with SSL info or None
    """
    # Extract hostname from target
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        hostname = parsed.netloc
    else:
        hostname = target

    # Remove port if present
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                if cert:
                    # Extract useful info
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))

                    return {
                        "issuer": issuer.get("organizationName", "Unknown"),
                        "subject": subject.get("commonName", "Unknown"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "serial_number": cert.get("serialNumber"),
                        "version": cert.get("version"),
                    }
    except (OSError, RuntimeError, TypeError, ValueError):
        pass

    return None


def check_version_disclosure(
    headers: dict[str, str], web_server: str | None
) -> list[str]:
    """
    Check for version disclosure in headers and server string.

    Args:
        headers: HTTP headers
        web_server: Detected web server string

    Returns:
        List of disclosed version strings
    """
    disclosed = []

    # Check Server header for version
    if web_server and "/" in web_server:
        disclosed.append(f"Server: {web_server}")

    # Check common version-disclosing headers
    version_headers = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
    normalized = {k.lower(): v for k, v in headers.items()}

    for header in version_headers:
        if header.lower() in normalized:
            disclosed.append(f"{header}: {normalized[header.lower()]}")

    return disclosed


def detect_frameworks(html_content: str, headers: dict[str, str]) -> list[str]:
    """
    Detect web frameworks from HTML content and headers.

    This is a convenience wrapper around detect_technologies for
    backward compatibility.

    Args:
        html_content: HTML content to analyze
        headers: HTTP headers

    Returns:
        List of detected frameworks
    """
    return detect_technologies(html_content, headers)
