"""
GitHub Issues integration for RedOPS.

Automatically creates GitHub issues from security findings.
"""

from typing import Any
from datetime import datetime, timezone
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


# GitHub API endpoint
GITHUB_API = "https://api.github.com"


@dataclass
class GitHubConfig:
    """GitHub configuration."""

    token: str
    owner: str
    repo: str
    labels: list[str] = field(default_factory=list)
    assignees: list[str] = field(default_factory=list)
    milestone: int | None = None

    def __post_init__(self):
        if not self.labels:
            self.labels = ["security", "redops"]

    @classmethod
    def from_env(cls) -> "GitHubConfig":
        """Create config from environment variables."""
        labels_str = os.environ.get("GITHUB_LABELS", "security,redops")
        labels = [label.strip() for label in labels_str.split(",") if label.strip()]

        assignees_str = os.environ.get("GITHUB_ASSIGNEES", "")
        assignees = [a.strip() for a in assignees_str.split(",") if a.strip()]

        milestone_str = os.environ.get("GITHUB_MILESTONE", "")
        milestone = int(milestone_str) if milestone_str.isdigit() else None

        return cls(
            token=os.environ.get("GITHUB_TOKEN", ""),
            owner=os.environ.get("GITHUB_OWNER", ""),
            repo=os.environ.get("GITHUB_REPO", ""),
            labels=labels,
            assignees=assignees,
            milestone=milestone,
        )


class GitHubClient:
    """
    Client for GitHub REST API.

    Creates and manages security issues in GitHub.
    """

    def __init__(self, config: GitHubConfig | None = None):
        """
        Initialize the client.

        Args:
            config: GitHub configuration (uses env vars if not provided)
        """
        self.config = config or GitHubConfig.from_env()

    def _get_headers(self) -> dict[str, str]:
        """Get request headers."""
        return {
            "Authorization": f"Bearer {self.config.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _api_url(self, endpoint: str) -> str:
        """Build API URL."""
        return f"{GITHUB_API}/repos/{self.config.owner}/{self.config.repo}/{endpoint.lstrip('/')}"

    def create_issue(
        self,
        title: str,
        body: str,
        labels: list[str] | None = None,
        assignees: list[str] | None = None,
        milestone: int | None = None,
    ) -> dict[str, Any]:
        """
        Create a GitHub issue.

        Args:
            title: Issue title
            body: Issue body (supports GitHub Markdown)
            labels: Issue labels
            assignees: Usernames to assign
            milestone: Milestone number

        Returns:
            Result with issue number and URL
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "requests library not available"}

        if not self.config.token:
            return {"success": False, "error": "GitHub token not configured"}

        if not self.config.owner or not self.config.repo:
            return {"success": False, "error": "GitHub owner/repo not configured"}

        # Build issue data
        all_labels = self.config.labels.copy()
        if labels:
            all_labels.extend(labels)

        all_assignees = self.config.assignees.copy()
        if assignees:
            all_assignees.extend(assignees)

        issue_data = {
            "title": title,
            "body": body,
            "labels": list(set(all_labels)),
        }

        if all_assignees:
            issue_data["assignees"] = list(set(all_assignees))

        effective_milestone = milestone or self.config.milestone
        if effective_milestone:
            issue_data["milestone"] = effective_milestone

        try:
            response = requests.post(
                self._api_url("issues"),
                headers=self._get_headers(),
                json=issue_data,
                timeout=30,
            )

            if response.status_code == 201:
                data = response.json()
                return {
                    "success": True,
                    "issue_number": data.get("number"),
                    "issue_id": data.get("id"),
                    "url": data.get("html_url"),
                    "message": f"Created issue #{data.get('number')}",
                }

            # Handle error response
            try:
                error_data = response.json()
                error_text = error_data.get("message", str(error_data))
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
        finding: dict[str, Any],
        scan_id: str | None = None,
        target: str | None = None,
    ) -> dict[str, Any]:
        """
        Create an issue from a security finding.

        Args:
            finding: Finding data dict
            scan_id: Scan identifier
            target: Scan target

        Returns:
            Result with issue details
        """
        title_text = finding.get("title", "Security Finding")
        severity = finding.get("severity", "medium")
        module = finding.get("module", "unknown")
        description = finding.get("description", "")
        data = finding.get("data", {})

        # Build formatted Markdown body
        lines = [
            "## Security Finding from RedOPS",
            "",
            f"**Module:** `{module}`",
            f"**Severity:** {self._severity_badge(severity)}",
        ]

        if target:
            lines.append(f"**Target:** `{target}`")
        if scan_id:
            lines.append(f"**Scan ID:** `{scan_id}`")

        lines.extend(
            [
                "",
                "### Description",
                "",
                description,
            ]
        )

        if data:
            lines.extend(
                [
                    "",
                    "### Technical Details",
                    "",
                    "```json",
                    json.dumps(data, indent=2, default=str)[:3000],
                    "```",
                ]
            )

        lines.extend(
            [
                "",
                "---",
                f"*Generated by RedOPS at {datetime.now(timezone.utc).isoformat()}*",
            ]
        )

        body = "\n".join(lines)
        title = f"[RedOPS] {title_text}"

        # Severity-based labels
        severity_labels = {
            "critical": "priority:critical",
            "high": "priority:high",
            "medium": "priority:medium",
            "low": "priority:low",
            "info": "priority:low",
        }
        labels = [severity_labels.get(severity, "priority:medium")]

        return self.create_issue(
            title=title[:256],  # GitHub limit
            body=body,
            labels=labels,
        )

    def _severity_badge(self, severity: str) -> str:
        """Get emoji badge for severity."""
        badges = {
            "critical": ":red_circle: **CRITICAL**",
            "high": ":orange_circle: **HIGH**",
            "medium": ":yellow_circle: **MEDIUM**",
            "low": ":green_circle: **LOW**",
            "info": ":blue_circle: **INFO**",
        }
        return badges.get(severity, f":white_circle: **{severity.upper()}**")

    def get_issue(self, issue_number: int) -> dict[str, Any]:
        """
        Get issue details.

        Args:
            issue_number: GitHub issue number

        Returns:
            Issue details or error
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "requests library not available"}

        try:
            response = requests.get(
                self._api_url(f"issues/{issue_number}"),
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

    def add_comment(self, issue_number: int, body: str) -> dict[str, Any]:
        """
        Add a comment to an issue.

        Args:
            issue_number: GitHub issue number
            body: Comment body

        Returns:
            Result with comment details
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "requests library not available"}

        try:
            response = requests.post(
                self._api_url(f"issues/{issue_number}/comments"),
                headers=self._get_headers(),
                json={"body": body},
                timeout=30,
            )

            if response.status_code == 201:
                data = response.json()
                return {
                    "success": True,
                    "comment_id": data.get("id"),
                    "url": data.get("html_url"),
                }

            return {
                "success": False,
                "error": f"HTTP {response.status_code}",
            }

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}

    def close_issue(
        self, issue_number: int, comment: str | None = None
    ) -> dict[str, Any]:
        """
        Close an issue.

        Args:
            issue_number: GitHub issue number
            comment: Optional closing comment

        Returns:
            Result with status
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "requests library not available"}

        try:
            # Add closing comment if provided
            if comment:
                self.add_comment(issue_number, comment)

            response = requests.patch(
                self._api_url(f"issues/{issue_number}"),
                headers=self._get_headers(),
                json={"state": "closed"},
                timeout=30,
            )

            if response.status_code == 200:
                return {
                    "success": True,
                    "message": f"Closed issue #{issue_number}",
                }

            return {
                "success": False,
                "error": f"HTTP {response.status_code}",
            }

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}


def create_github_issue(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Create a single GitHub issue.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - title: Issue title
            - body: Issue body
            - owner: GitHub owner
            - repo: GitHub repo
            - All GitHubConfig options

    Returns:
        Updated context with issue result
    """
    params = params or {}

    config = GitHubConfig(
        token=params.get("token") or os.environ.get("GITHUB_TOKEN", ""),
        owner=params.get("owner") or os.environ.get("GITHUB_OWNER", ""),
        repo=params.get("repo") or os.environ.get("GITHUB_REPO", ""),
    )

    client = GitHubClient(config)

    title = params.get("title", f"RedOPS Finding for {ctx.target}")
    body = params.get("body", "Security finding from RedOPS scan")

    ctx.log(f"Creating GitHub issue: {title[:50]}...", level="INFO")

    result = client.create_issue(title=title, body=body)

    if result.get("success"):
        ctx.log(f"Created GitHub issue: #{result.get('issue_number')}", level="INFO")
    else:
        ctx.log(f"GitHub issue creation failed: {result.get('error')}", level="WARNING")

    ctx.add("github_issue_result", result)
    return ctx


def create_github_issues_from_findings(
    ctx: Context, params: dict[str, Any] | None = None
) -> Context:
    """
    Create GitHub issues from all findings in context.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - min_severity: Minimum severity to create issues for (default: medium)
            - All GitHubConfig options

    Returns:
        Updated context with issue creation results
    """
    params = params or {}

    config = GitHubConfig(
        token=params.get("token") or os.environ.get("GITHUB_TOKEN", ""),
        owner=params.get("owner") or os.environ.get("GITHUB_OWNER", ""),
        repo=params.get("repo") or os.environ.get("GITHUB_REPO", ""),
    )

    client = GitHubClient(config)
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

    ctx.log(f"Creating GitHub issues for {len(findings)} findings", level="INFO")

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
                    "issue_number": result.get("issue_number"),
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

    ctx.log(f"Created {len(results['issues_created'])} GitHub issues", level="INFO")
    ctx.add("github_issues_result", results)
    return ctx
