"""
Technology stack fingerprinting module.

Identifies web technologies, frameworks, and libraries used by a target.
"""

from typing import Optional, Dict, Any
import hashlib
from redops.core.context import Context
from redops.core.models import TechStack


def fingerprint(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Fingerprint the technology stack of a target.
    
    Performs:
    - HTTP header analysis
    - Favicon hash fingerprinting
    - Framework detection
    
    Args:
        ctx: Pipeline context
        params: Optional parameters
        
    Returns:
        Updated context
    """
    params = params or {}
    target = params.get('target') or ctx.target
    
    if not target:
        ctx.log("No target specified for tech stack fingerprinting", level="WARNING")
        return ctx
    
    ctx.log(f"Fingerprinting tech stack for: {target}", level="INFO")
    
    # Create a TechStack model
    tech_stack = TechStack(
        web_server="Unknown",
        frameworks=[],
        languages=[],
        libraries=[],
        headers={},
        fingerprints={}
    )
    
    # Stubbed implementations - in real use, would make HTTP requests
    # and analyze responses
    
    ctx.log("HTTP header analysis not yet implemented", level="DEBUG")
    ctx.log("Favicon fingerprinting not yet implemented", level="DEBUG")
    
    ctx.add("tech_stack", tech_stack.model_dump())
    ctx.log(f"Tech stack fingerprinting completed for {target}", level="INFO")
    
    return ctx


def analyze_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Analyze HTTP headers to identify technologies.
    
    Args:
        headers: HTTP headers to analyze
        
    Returns:
        Analysis results
    """
    analysis = {
        "server": headers.get("Server", "Unknown"),
        "powered_by": headers.get("X-Powered-By", "Unknown"),
        "framework_hints": [],
        "security_headers": {}
    }
    
    # Check for security headers
    security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security"
    ]
    
    for header in security_headers:
        if header in headers:
            analysis["security_headers"][header] = headers[header]
    
    return analysis


def favicon_hash(favicon_bytes: bytes) -> str:
    """
    Calculate hash of a favicon for fingerprinting.
    
    Args:
        favicon_bytes: Raw bytes of the favicon
        
    Returns:
        Hash string
    """
    return hashlib.md5(favicon_bytes).hexdigest()


def detect_frameworks(html_content: str, headers: Dict[str, str]) -> list:
    """
    Detect web frameworks from HTML content and headers.
    
    Args:
        html_content: HTML content to analyze
        headers: HTTP headers
        
    Returns:
        List of detected frameworks
    """
    frameworks = []
    
    # Common framework indicators
    indicators = {
        "React": ["react", "ReactDOM"],
        "Vue.js": ["Vue", "vue-"],
        "Angular": ["ng-", "angular"],
        "Django": ["csrfmiddlewaretoken"],
        "Ruby on Rails": ["csrf-token", "_rails"],
        "Laravel": ["laravel_session"],
        "WordPress": ["wp-content", "wp-includes"],
        "Drupal": ["Drupal.settings"],
        "Joomla": ["Joomla!"]
    }
    
    for framework, patterns in indicators.items():
        for pattern in patterns:
            if pattern in html_content.lower():
                frameworks.append(framework)
                break
    
    return frameworks
