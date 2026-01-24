"""
Code artifact analysis module.

Analyzes code repositories for metadata, dependencies, and patterns.
Detects potential secrets, API keys, and sensitive information in code.
"""

import json
import re
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from redops.core.context import Context
from redops.core.models import Finding, RiskLevel


# Secret detection patterns with named groups
SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}",
        "description": "AWS Access Key ID",
        "severity": RiskLevel.CRITICAL,
    },
    "aws_secret_key": {
        "pattern": r"(?:aws_secret_access_key|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "description": "AWS Secret Access Key",
        "severity": RiskLevel.CRITICAL,
    },
    "github_token": {
        "pattern": r"gh[ps]_[A-Za-z0-9_]{36,}",
        "description": "GitHub Personal Access Token",
        "severity": RiskLevel.CRITICAL,
    },
    "github_oauth": {
        "pattern": r"gho_[A-Za-z0-9_]{36,}",
        "description": "GitHub OAuth Token",
        "severity": RiskLevel.CRITICAL,
    },
    "generic_api_key": {
        "pattern": r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
        "description": "Generic API Key",
        "severity": RiskLevel.HIGH,
    },
    "generic_secret": {
        "pattern": r"(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "description": "Generic Secret/Password",
        "severity": RiskLevel.HIGH,
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "description": "Private Key",
        "severity": RiskLevel.CRITICAL,
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
        "description": "Slack Token",
        "severity": RiskLevel.HIGH,
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
        "description": "Slack Webhook URL",
        "severity": RiskLevel.HIGH,
    },
    "stripe_key": {
        "pattern": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}",
        "description": "Stripe API Key",
        "severity": RiskLevel.CRITICAL,
    },
    "google_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "description": "Google API Key",
        "severity": RiskLevel.HIGH,
    },
    "google_oauth": {
        "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "description": "Google OAuth Client ID",
        "severity": RiskLevel.MEDIUM,
    },
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "description": "JWT Token",
        "severity": RiskLevel.MEDIUM,
    },
    "bearer_token": {
        "pattern": r"[Bb]earer\s+[A-Za-z0-9_\-\.=]+",
        "description": "Bearer Token",
        "severity": RiskLevel.MEDIUM,
    },
    "database_url": {
        "pattern": r"(?:mysql|postgres|postgresql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        "description": "Database Connection String with Credentials",
        "severity": RiskLevel.CRITICAL,
    },
    "sendgrid_key": {
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "description": "SendGrid API Key",
        "severity": RiskLevel.HIGH,
    },
    "twilio_key": {
        "pattern": r"SK[a-f0-9]{32}",
        "description": "Twilio API Key",
        "severity": RiskLevel.HIGH,
    },
    "mailgun_key": {
        "pattern": r"key-[A-Za-z0-9]{32}",
        "description": "Mailgun API Key",
        "severity": RiskLevel.HIGH,
    },
    "heroku_key": {
        "pattern": r"[hH]eroku[A-Za-z0-9_\-]*[=:]\s*['\"]?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}['\"]?",
        "description": "Heroku API Key",
        "severity": RiskLevel.HIGH,
    },
    "npm_token": {
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "description": "NPM Access Token",
        "severity": RiskLevel.HIGH,
    },
    "pypi_token": {
        "pattern": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+",
        "description": "PyPI API Token",
        "severity": RiskLevel.HIGH,
    },
}

# Files to skip when scanning
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pyc", ".pyo", ".class",
}

SKIP_DIRECTORIES = {
    ".git", ".svn", ".hg",
    "node_modules", "vendor", "venv", ".venv", "__pycache__",
    "dist", "build", "target", "bin", "obj",
    ".idea", ".vscode", ".vs",
    "coverage", ".coverage", "htmlcov",
    ".tox", ".nox", ".eggs",
}

# Files that often contain secrets (for prioritized scanning)
HIGH_PRIORITY_FILES = {
    ".env", ".env.local", ".env.development", ".env.production",
    "config.yaml", "config.yml", "config.json",
    "secrets.yaml", "secrets.yml", "secrets.json",
    "credentials.json", "credentials.yaml",
    "settings.py", "settings.json",
    "application.properties", "application.yml",
}


def analyze_repository(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Analyze a code repository for artifacts and metadata.

    Scans for secrets, analyzes dependencies, and identifies patterns.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - repo_path: Path to the repository
            - scan_secrets: Enable secret scanning (default: True)
            - max_files: Maximum files to scan (default: 10000)
            - include_git_history: Scan git history (default: False)

    Returns:
        Updated context with repository_analysis and findings
    """
    params = params or {}
    repo_path = params.get("repo_path") or ctx.target
    scan_secrets = params.get("scan_secrets", True)
    max_files = params.get("max_files", 10000)
    include_git_history = params.get("include_git_history", False)

    if not repo_path:
        ctx.log("No repository path specified", level="WARNING")
        return ctx

    path = Path(repo_path)
    if not path.exists():
        ctx.log(f"Repository path does not exist: {repo_path}", level="WARNING")
        return ctx

    ctx.log(f"Analyzing repository: {repo_path}", level="INFO")

    analysis: Dict[str, Any] = {
        "path": str(repo_path),
        "languages": [],
        "dependencies": {},
        "patterns": [],
        "secrets_found": 0,
        "files_scanned": 0,
        "metadata": {},
    }

    findings: List[Finding] = []

    # Detect languages
    languages = detect_languages(repo_path)
    analysis["languages"] = languages
    ctx.log(f"Detected languages: {', '.join(languages) if languages else 'none'}", level="DEBUG")

    # Extract dependencies
    dependencies = extract_dependencies(repo_path)
    analysis["dependencies"] = dependencies

    # Scan for secrets
    if scan_secrets:
        ctx.log("Scanning for secrets and sensitive data...", level="INFO")
        secret_results = scan_for_secrets(repo_path, max_files=max_files)
        analysis["secrets_found"] = len(secret_results)
        analysis["files_scanned"] = secret_results[0]["files_scanned"] if secret_results else 0

        # Create findings for each secret
        for secret in secret_results:
            if secret.get("type") == "summary":
                continue

            finding = Finding(
                module="metadata.code_artifacts",
                title=f"Secret Detected: {secret['description']}",
                description=f"Found {secret['description']} in {secret['file']} at line {secret['line']}",
                severity=secret["severity"],
                data={
                    "file": secret["file"],
                    "line": secret["line"],
                    "type": secret["secret_type"],
                    "pattern": secret["pattern_name"],
                    "context": secret.get("context", ""),
                    "recommendation": "Remove the secret and rotate credentials immediately",
                },
            )
            findings.append(finding)

        if analysis["secrets_found"] > 0:
            ctx.log(
                f"CRITICAL: Found {analysis['secrets_found']} potential secrets!",
                level="WARNING"
            )

    # Find code patterns
    patterns = find_code_patterns(repo_path)
    analysis["patterns"] = patterns

    # Extract git metadata if available
    git_metadata = extract_git_metadata(repo_path)
    if git_metadata:
        analysis["metadata"]["git"] = git_metadata

    # Add to context
    ctx.add("repository_analysis", analysis)

    # Add findings
    for i, finding in enumerate(findings):
        ctx.add(f"finding_code_{i}", finding.model_dump())

    # Add summary
    ctx.add("code_analysis_summary", {
        "languages": languages,
        "dependency_managers": list(dependencies.keys()),
        "secrets_found": analysis["secrets_found"],
        "files_scanned": analysis["files_scanned"],
        "total_findings": len(findings),
    })

    ctx.log("Repository analysis completed", level="INFO")

    return ctx


def detect_languages(repo_path: str) -> List[str]:
    """
    Detect programming languages used in a repository.

    Args:
        repo_path: Path to the repository

    Returns:
        List of detected languages sorted by file count
    """
    path = Path(repo_path)

    if not path.exists():
        return []

    # Extended file extensions mapping
    extensions = {
        ".py": "Python",
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".java": "Java",
        ".cpp": "C++",
        ".cc": "C++",
        ".cxx": "C++",
        ".c": "C",
        ".h": "C/C++",
        ".hpp": "C++",
        ".go": "Go",
        ".rs": "Rust",
        ".rb": "Ruby",
        ".php": "PHP",
        ".cs": "C#",
        ".swift": "Swift",
        ".kt": "Kotlin",
        ".scala": "Scala",
        ".vue": "Vue",
        ".svelte": "Svelte",
        ".lua": "Lua",
        ".r": "R",
        ".R": "R",
        ".jl": "Julia",
        ".hs": "Haskell",
        ".ex": "Elixir",
        ".exs": "Elixir",
        ".erl": "Erlang",
        ".clj": "Clojure",
        ".dart": "Dart",
        ".sh": "Shell",
        ".bash": "Shell",
        ".zsh": "Shell",
        ".sql": "SQL",
    }

    language_counts: Dict[str, int] = {}

    try:
        for file_path in path.rglob("*"):
            if file_path.is_file():
                # Skip directories in SKIP_DIRECTORIES
                if any(skip_dir in file_path.parts for skip_dir in SKIP_DIRECTORIES):
                    continue

                ext = file_path.suffix.lower()
                if ext in extensions:
                    lang = extensions[ext]
                    language_counts[lang] = language_counts.get(lang, 0) + 1
    except PermissionError:
        pass

    # Sort by count descending
    sorted_langs = sorted(language_counts.items(), key=lambda x: x[1], reverse=True)
    return [lang for lang, _ in sorted_langs]


def extract_dependencies(repo_path: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Extract dependencies from various package managers.

    Args:
        repo_path: Path to the repository

    Returns:
        Dictionary of dependencies by package manager
    """
    path = Path(repo_path)
    dependencies: Dict[str, List[Dict[str, str]]] = {}

    # Python - requirements.txt
    req_path = path / "requirements.txt"
    if req_path.exists():
        dependencies["pip"] = parse_requirements_txt(req_path)

    # Python - pyproject.toml
    pyproject_path = path / "pyproject.toml"
    if pyproject_path.exists():
        pyproject_deps = parse_pyproject_toml(pyproject_path)
        if pyproject_deps:
            dependencies["pyproject"] = pyproject_deps

    # Node.js - package.json
    package_path = path / "package.json"
    if package_path.exists():
        npm_deps = parse_package_json(package_path)
        if npm_deps:
            dependencies["npm"] = npm_deps

    # Go - go.mod
    go_mod_path = path / "go.mod"
    if go_mod_path.exists():
        go_deps = parse_go_mod(go_mod_path)
        if go_deps:
            dependencies["go"] = go_deps

    # Ruby - Gemfile
    gemfile_path = path / "Gemfile"
    if gemfile_path.exists():
        gem_deps = parse_gemfile(gemfile_path)
        if gem_deps:
            dependencies["bundler"] = gem_deps

    # Rust - Cargo.toml
    cargo_path = path / "Cargo.toml"
    if cargo_path.exists():
        cargo_deps = parse_cargo_toml(cargo_path)
        if cargo_deps:
            dependencies["cargo"] = cargo_deps

    return dependencies


def parse_requirements_txt(file_path: Path) -> List[Dict[str, str]]:
    """
    Parse a Python requirements.txt file.

    Args:
        file_path: Path to requirements.txt

    Returns:
        List of dependencies with name and version
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        deps = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Parse various formats: pkg, pkg==1.0, pkg>=1.0, pkg[extra]>=1.0
            match = re.match(r"^([A-Za-z0-9_-]+)(?:\[[^\]]+\])?(?:([<>=!~]+)(.+))?$", line)
            if match:
                name = match.group(1)
                version = match.group(3) if match.group(3) else "any"
                deps.append({"name": name, "version": version})

        return deps
    except Exception:
        return []


def parse_pyproject_toml(file_path: Path) -> List[Dict[str, str]]:
    """
    Parse dependencies from pyproject.toml.

    Args:
        file_path: Path to pyproject.toml

    Returns:
        List of dependencies
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        deps = []
        # Simple pattern matching for dependencies
        # Note: Full TOML parsing would be better but adds dependency
        dep_section = re.search(r'\[(?:project\.)?dependencies\](.*?)(?:\[|$)', content, re.DOTALL)
        if dep_section:
            for match in re.finditer(r'"([^"]+)"', dep_section.group(1)):
                dep_str = match.group(1)
                name_match = re.match(r'^([A-Za-z0-9_-]+)', dep_str)
                if name_match:
                    deps.append({"name": name_match.group(1), "version": "from pyproject.toml"})

        return deps
    except Exception:
        return []


def parse_package_json(file_path: Path) -> List[Dict[str, str]]:
    """
    Parse dependencies from package.json.

    Args:
        file_path: Path to package.json

    Returns:
        List of dependencies
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        deps = []

        for dep_type in ["dependencies", "devDependencies"]:
            if dep_type in data:
                for name, version in data[dep_type].items():
                    deps.append({
                        "name": name,
                        "version": version,
                        "dev": dep_type == "devDependencies"
                    })

        return deps
    except Exception:
        return []


def parse_go_mod(file_path: Path) -> List[Dict[str, str]]:
    """
    Parse dependencies from go.mod.

    Args:
        file_path: Path to go.mod

    Returns:
        List of dependencies
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        deps = []

        # Match require block
        require_block = re.search(r'require\s*\((.*?)\)', content, re.DOTALL)
        if require_block:
            # Match module paths (start with letter, contain alphanumerics and dots/slashes)
            for match in re.finditer(r'^\s*([a-zA-Z][^\s]*)\s+(v[^\s]+)', require_block.group(1), re.MULTILINE):
                deps.append({"name": match.group(1), "version": match.group(2)})

        # Match single require statements
        for match in re.finditer(r'^require\s+([a-zA-Z][^\s]*)\s+(v[^\s]+)', content, re.MULTILINE):
            deps.append({"name": match.group(1), "version": match.group(2)})

        return deps
    except Exception:
        return []


def parse_gemfile(file_path: Path) -> List[Dict[str, str]]:
    """
    Parse dependencies from Gemfile.

    Args:
        file_path: Path to Gemfile

    Returns:
        List of dependencies
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        deps = []

        # Match gem statements
        for match in re.finditer(r"gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", content):
            name = match.group(1)
            version = match.group(2) if match.group(2) else "any"
            deps.append({"name": name, "version": version})

        return deps
    except Exception:
        return []


def parse_cargo_toml(file_path: Path) -> List[Dict[str, str]]:
    """
    Parse dependencies from Cargo.toml.

    Args:
        file_path: Path to Cargo.toml

    Returns:
        List of dependencies
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        deps = []

        # Match [dependencies] section
        dep_section = re.search(r'\[dependencies\](.*?)(?:\[|$)', content, re.DOTALL)
        if dep_section:
            for match in re.finditer(r'^([A-Za-z0-9_-]+)\s*=\s*["\']?([^"\'\n]+)["\']?', dep_section.group(1), re.MULTILINE):
                deps.append({"name": match.group(1), "version": match.group(2)})

        return deps
    except Exception:
        return []


def scan_for_secrets(
    repo_path: str,
    max_files: int = 10000,
    patterns: Optional[Dict[str, Dict]] = None
) -> List[Dict[str, Any]]:
    """
    Scan repository for secrets and sensitive data.

    Args:
        repo_path: Path to the repository
        max_files: Maximum number of files to scan
        patterns: Optional custom patterns (uses SECRET_PATTERNS if None)

    Returns:
        List of found secrets with location info
    """
    path = Path(repo_path)

    if not path.exists():
        return []

    patterns = patterns or SECRET_PATTERNS
    results: List[Dict[str, Any]] = []
    files_scanned = 0

    # First, scan high-priority files
    for priority_file in HIGH_PRIORITY_FILES:
        file_path = path / priority_file
        if file_path.exists():
            file_results = scan_file_for_secrets(file_path, patterns)
            results.extend(file_results)
            files_scanned += 1

    # Then scan all other files
    try:
        for file_path in path.rglob("*"):
            if files_scanned >= max_files:
                break

            if not file_path.is_file():
                continue

            # Skip binary files and directories
            if file_path.suffix.lower() in SKIP_EXTENSIONS:
                continue

            if any(skip_dir in file_path.parts for skip_dir in SKIP_DIRECTORIES):
                continue

            # Skip already scanned high-priority files
            if file_path.name in HIGH_PRIORITY_FILES:
                continue

            file_results = scan_file_for_secrets(file_path, patterns)
            results.extend(file_results)
            files_scanned += 1

    except PermissionError:
        pass

    # Add summary as first result
    results.insert(0, {
        "type": "summary",
        "files_scanned": files_scanned,
        "secrets_found": len(results),
    })

    return results


def scan_file_for_secrets(
    file_path: Path,
    patterns: Dict[str, Dict]
) -> List[Dict[str, Any]]:
    """
    Scan a single file for secrets.

    Args:
        file_path: Path to the file
        patterns: Secret detection patterns

    Returns:
        List of found secrets
    """
    results = []

    try:
        # Skip large files (> 1MB)
        if file_path.stat().st_size > 1_000_000:
            return []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, start=1):
            for pattern_name, pattern_info in patterns.items():
                matches = re.finditer(pattern_info["pattern"], line, re.IGNORECASE)
                for match in matches:
                    # Get context (mask the actual secret)
                    context = get_masked_context(line, match)

                    results.append({
                        "file": str(file_path),
                        "line": line_num,
                        "pattern_name": pattern_name,
                        "description": pattern_info["description"],
                        "severity": pattern_info["severity"],
                        "secret_type": pattern_name,
                        "context": context,
                    })

    except Exception:
        pass

    return results


def get_masked_context(line: str, match: re.Match) -> str:
    """
    Get context around match with the secret masked.

    Args:
        line: The line containing the match
        match: The regex match object

    Returns:
        Masked context string
    """
    # Mask the matched secret
    start, end = match.span()
    secret_len = end - start
    masked = line[:start] + "*" * min(secret_len, 20) + line[end:]
    return masked.strip()[:100]


def find_code_patterns(repo_path: str) -> List[Dict[str, Any]]:
    """
    Find common code patterns and security practices.

    Args:
        repo_path: Path to the repository

    Returns:
        List of identified patterns
    """
    path = Path(repo_path)
    patterns = []

    if not path.exists():
        return patterns

    # Check for common security patterns
    checks = [
        ("has_dockerfile", "Dockerfile"),
        ("has_docker_compose", "docker-compose.yml"),
        ("has_ci", ".github/workflows"),
        ("has_gitlab_ci", ".gitlab-ci.yml"),
        ("has_env_example", ".env.example"),
        ("has_gitignore", ".gitignore"),
        ("has_readme", "README.md"),
        ("has_security_policy", "SECURITY.md"),
        ("has_contributing", "CONTRIBUTING.md"),
        ("has_license", "LICENSE"),
    ]

    for pattern_name, file_pattern in checks:
        check_path = path / file_pattern
        if check_path.exists():
            patterns.append({
                "name": pattern_name,
                "type": "file_exists",
                "path": file_pattern,
            })

    # Check for security-related files
    security_patterns = [
        (path / ".pre-commit-config.yaml", "has_pre_commit"),
        (path / "requirements-dev.txt", "has_dev_deps"),
        (path / "Makefile", "has_makefile"),
    ]

    for check_path, pattern_name in security_patterns:
        if check_path.exists():
            patterns.append({
                "name": pattern_name,
                "type": "security_practice",
                "path": str(check_path.relative_to(path)),
            })

    return patterns


def extract_git_metadata(repo_path: str) -> Optional[Dict[str, Any]]:
    """
    Extract git repository metadata.

    Args:
        repo_path: Path to the repository

    Returns:
        Git metadata dictionary or None
    """
    path = Path(repo_path)
    git_dir = path / ".git"

    if not git_dir.exists():
        return None

    metadata: Dict[str, Any] = {
        "is_git_repo": True,
    }

    # Try to read git config
    config_path = git_dir / "config"
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Extract remote URL
            url_match = re.search(r'url\s*=\s*(.+)', content)
            if url_match:
                url = url_match.group(1).strip()
                # Mask credentials in URL if present
                url = re.sub(r'://[^:]+:[^@]+@', '://***:***@', url)
                metadata["remote_url"] = url

        except Exception:
            pass

    # Check HEAD for current branch
    head_path = git_dir / "HEAD"
    if head_path.exists():
        try:
            with open(head_path, "r", encoding="utf-8") as f:
                head_content = f.read().strip()

            if head_content.startswith("ref: refs/heads/"):
                metadata["current_branch"] = head_content[16:]
        except Exception:
            pass

    return metadata


def get_secrets_summary(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a summary of found secrets.

    Args:
        results: List of secret detection results

    Returns:
        Summary dictionary
    """
    summary = {
        "total": 0,
        "by_severity": {},
        "by_type": {},
        "files_affected": set(),
    }

    for result in results:
        if result.get("type") == "summary":
            continue

        summary["total"] += 1

        severity = str(result.get("severity", "unknown"))
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

        secret_type = result.get("secret_type", "unknown")
        summary["by_type"][secret_type] = summary["by_type"].get(secret_type, 0) + 1

        summary["files_affected"].add(result.get("file", ""))

    summary["files_affected"] = list(summary["files_affected"])
    return summary
