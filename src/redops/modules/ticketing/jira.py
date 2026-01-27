"""
Jira integration for RedOPS.

Automatically creates Jira issues from security findings.
"""

from typing import Optional, Dict, Any, List
import os
import json
from dataclasses import dataclass, field
from redops.core.context import Context

# Try to import requests
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class JiraConfig:
    """Jira configuration."""

    base_url: str
    username: str
    api_token: str
    project_key: str
    issue_type: str = "Bug"
    priority_map: Dict[str, str] = field(default_factory=dict)
    labels: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.priority_map:
            # Default severity to Jira priority mapping
            self.priority_map = {
                "critical": "Highest",
                "high": "High",
                "medium": "Medium",
                "low": "Low",
                "info": "Lowest",
            }
        if not self.labels:
            self.labels = ["redops", "security"]

    @classmethod
    def from_env(cls) -> "JiraConfig":
        """Create config from environment variables."""
        custom_fields_str = os.environ.get("JIRA_CUSTOM_FIELDS", "{}")
        try:
            custom_fields = json.loads(custom_fields_str)
        except json.JSONDecodeError:
            custom_fields = {}

        labels_str = os.environ.get("JIRA_LABELS", "redops,security")
        labels = [label.strip() for label in labels_str.split(",") if label.strip()]

        return cls(
            base_url=os.environ.get("JIRA_BASE_URL", ""),
            username=os.environ.get("JIRA_USERNAME", ""),
            api_token=os.environ.get("JIRA_API_TOKEN", ""),
            project_key=os.environ.get("JIRA_PROJECT_KEY", ""),
            issue_type=os.environ.get("JIRA_ISSUE_TYPE", "Bug"),
            labels=labels,
            custom_fields=custom_fields,
        )


class JiraClient:
    """
    Client for Jira REST API.

    Creates and manages security issues in Jira.
    """

    def __init__(self, config: Optional[JiraConfig] = None):
        """
        Initialize the client.

        Args:
            config: Jira configuration (uses env vars if not provided)
        """
        self.config = config or JiraConfig.from_env()

    def _get_auth(self) -> tuple:
        """Get basic auth tuple."""
        return (self.config.username, self.config.api_token)

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _api_url(self, endpoint: str) -> str:
        """Build API URL."""
        base = self.config.base_url.rstrip("/")
        return f"{base}/rest/api/3/{endpoint.lstrip('/')}"

    def create_issue(
        self,
        summary: str,
        description: str,
        severity: str = "medium",
        labels: Optional[List[str]] = None,
        components: Optional[List[str]] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a Jira issue.

        Args:
            summary: Issue summary
            description: Issue description (supports Jira markdown)
            severity: Finding severity for priority mapping
            labels: Additional labels
            components: Project components
            custom_fields: Additional custom field values

        Returns:
            Result with issue key and URL
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "requests library not available"}

        if not all([self.config.base_url, self.config.username, self.config.api_token]):
            return {"success": False, "error": "Jira not configured"}

        if not self.config.project_key:
            return {"success": False, "error": "Jira project key not configured"}

        # Build issue data
        all_labels = self.config.labels.copy()
        if labels:
            all_labels.extend(labels)

        priority = self.config.priority_map.get(severity, "Medium")

        issue_data = {
            "fields": {
                "project": {"key": self.config.project_key},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description}],
                        }
                    ],
                },
                "issuetype": {"name": self.config.issue_type},
                "priority": {"name": priority},
                "labels": all_labels,
            }
        }

        # Add components if specified
        if components or self.config.components:
            component_list = components or self.config.components
            issue_data["fields"]["components"] = [{"name": c} for c in component_list]

        # Add custom fields
        merged_custom = {**self.config.custom_fields, **(custom_fields or {})}
        for field_id, value in merged_custom.items():
            issue_data["fields"][field_id] = value

        try:
            response = requests.post(
                self._api_url("issue"),
                auth=self._get_auth(),
                headers=self._get_headers(),
                json=issue_data,
                timeout=30,
            )

            if response.status_code == 201:
                data = response.json()
                issue_key = data.get("key")
                return {
                    "success": True,
                    "issue_key": issue_key,
                    "issue_id": data.get("id"),
                    "url": f"{self.config.base_url}/browse/{issue_key}",
                    "message": f"Created issue {issue_key}",
                }

            # Handle error response
            try:
                error_data = response.json()
                errors = error_data.get("errors", {})
                error_messages = error_data.get("errorMessages", [])
                error_text = (
                    ", ".join(error_messages) if error_messages else str(errors)
                )
            except (ValueError, KeyError):
                error_text = response.text[:200]

            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {error_text}",
            }

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def create_issue_from_finding(
        self,
        finding: Dict[str, Any],
        scan_id: Optional[str] = None,
        target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create an issue from a security finding.

        Args:
            finding: Finding data dict
            scan_id: Scan identifier
            target: Scan target

        Returns:
            Result with issue details
        """
        title = finding.get("title", "Security Finding")
        severity = finding.get("severity", "medium")
        module = finding.get("module", "unknown")
        description_text = finding.get("description", "")
        data = finding.get("data", {})

        # Build formatted description
        lines = [
            "*Security Finding from RedOPS*",
            "",
            f"*Module:* {module}",
            f"*Severity:* {severity.upper()}",
        ]

        if target:
            lines.append(f"*Target:* {target}")
        if scan_id:
            lines.append(f"*Scan ID:* {scan_id}")

        lines.extend(
            [
                "",
                "*Description:*",
                description_text,
            ]
        )

        if data:
            lines.extend(
                [
                    "",
                    "*Technical Details:*",
                    "{code:json}",
                    json.dumps(data, indent=2, default=str)[:2000],
                    "{code}",
                ]
            )

        description = "\n".join(lines)
        summary = f"[RedOPS] {title}"

        labels = [f"severity-{severity}", module.replace(".", "-")]

        return self.create_issue(
            summary=summary[:255],  # Jira limit
            description=description,
            severity=severity,
            labels=labels,
        )

    def get_issue(self, issue_key: str) -> Dict[str, Any]:
        """
        Get issue details.

        Args:
            issue_key: Jira issue key (e.g., "PROJ-123")

        Returns:
            Issue details or error
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "requests library not available"}

        try:
            response = requests.get(
                self._api_url(f"issue/{issue_key}"),
                auth=self._get_auth(),
                headers=self._get_headers(),
                timeout=30,
            )

            if response.status_code == 200:
                return {"success": True, "issue": response.json()}

            return {
                "success": False,
                "error": f"HTTP {response.status_code}",
            }

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}


def create_jira_issue(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Create a single Jira issue.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - summary: Issue summary
            - description: Issue description
            - severity: Severity for priority mapping
            - project_key: Jira project key
            - All JiraConfig options

    Returns:
        Updated context with issue result
    """
    params = params or {}

    config = JiraConfig(
        base_url=params.get("base_url") or os.environ.get("JIRA_BASE_URL", ""),
        username=params.get("username") or os.environ.get("JIRA_USERNAME", ""),
        api_token=params.get("api_token") or os.environ.get("JIRA_API_TOKEN", ""),
        project_key=params.get("project_key") or os.environ.get("JIRA_PROJECT_KEY", ""),
        issue_type=params.get("issue_type", "Bug"),
    )

    client = JiraClient(config)

    summary = params.get("summary", f"RedOPS Finding for {ctx.target}")
    description = params.get("description", "Security finding from RedOPS scan")
    severity = params.get("severity", "medium")

    ctx.log(f"Creating Jira issue: {summary[:50]}...", level="INFO")

    result = client.create_issue(
        summary=summary,
        description=description,
        severity=severity,
    )

    if result.get("success"):
        ctx.log(f"Created Jira issue: {result.get('issue_key')}", level="INFO")
    else:
        ctx.log(f"Jira issue creation failed: {result.get('error')}", level="WARNING")

    ctx.add("jira_issue_result", result)
    return ctx


def create_jira_issues_from_findings(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Create Jira issues from all findings in context.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - min_severity: Minimum severity to create issues for (default: medium)
            - All JiraConfig options

    Returns:
        Updated context with issue creation results
    """
    params = params or {}

    config = JiraConfig(
        base_url=params.get("base_url") or os.environ.get("JIRA_BASE_URL", ""),
        username=params.get("username") or os.environ.get("JIRA_USERNAME", ""),
        api_token=params.get("api_token") or os.environ.get("JIRA_API_TOKEN", ""),
        project_key=params.get("project_key") or os.environ.get("JIRA_PROJECT_KEY", ""),
    )

    client = JiraClient(config)
    min_severity = params.get("min_severity", "medium")
    scan_id = ctx.get("pipeline_name", "unknown")

    # Severity ordering
    severity_order = ["critical", "high", "medium", "low", "info"]
    min_index = (
        severity_order.index(min_severity) if min_severity in severity_order else 2
    )

    # Collect findings
    findings = []
    for key, value in ctx.data.items():
        if key.startswith("finding_") and isinstance(value, dict):
            finding_severity = value.get("severity", "medium")
            severity_index = (
                severity_order.index(finding_severity)
                if finding_severity in severity_order
                else 2
            )
            if severity_index <= min_index:
                findings.append(value)

    ctx.log(f"Creating Jira issues for {len(findings)} findings", level="INFO")

    results = {
        "total_findings": len(findings),
        "issues_created": [],
        "errors": [],
    }

    for finding in findings:
        result = client.create_issue_from_finding(
            finding=finding,
            scan_id=scan_id,
            target=ctx.target,
        )

        if result.get("success"):
            results["issues_created"].append(
                {
                    "finding_title": finding.get("title"),
                    "issue_key": result.get("issue_key"),
                    "url": result.get("url"),
                }
            )
        else:
            results["errors"].append(
                {
                    "finding_title": finding.get("title"),
                    "error": result.get("error"),
                }
            )

    ctx.log(f"Created {len(results['issues_created'])} Jira issues", level="INFO")
    ctx.add("jira_issues_result", results)
    return ctx
