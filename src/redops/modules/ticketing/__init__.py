"""Ticketing system integrations for RedOPS."""

from redops.modules.ticketing.jira import (
    create_jira_issue,
    create_jira_issues_from_findings,
    JiraClient,
    JiraConfig,
)
from redops.modules.ticketing.github import (
    create_github_issue,
    create_github_issues_from_findings,
    GitHubClient,
    GitHubConfig,
)

__all__ = [
    # Jira
    "create_jira_issue",
    "create_jira_issues_from_findings",
    "JiraClient",
    "JiraConfig",
    # GitHub
    "create_github_issue",
    "create_github_issues_from_findings",
    "GitHubClient",
    "GitHubConfig",
]
