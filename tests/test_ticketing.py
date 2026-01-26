"""Tests for ticketing integrations: Jira and GitHub Issues."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import json

from redops.core.context import Context
from redops.core.models import Finding, RiskLevel


class TestJiraClient:
    """Tests for Jira integration."""

    def test_jira_config_from_env(self):
        """Test JiraConfig from environment variables."""
        env = {
            "JIRA_BASE_URL": "https://company.atlassian.net",
            "JIRA_USERNAME": "user@company.com",
            "JIRA_API_TOKEN": "test-token",
            "JIRA_PROJECT_KEY": "SEC",
            "JIRA_LABELS": "security,automated",
        }
        with patch.dict("os.environ", env):
            from redops.modules.ticketing.jira import JiraConfig
            config = JiraConfig.from_env()

            assert config.base_url == env["JIRA_BASE_URL"]
            assert config.username == env["JIRA_USERNAME"]
            assert config.api_token == env["JIRA_API_TOKEN"]
            assert config.project_key == "SEC"
            assert "security" in config.labels

    def test_jira_default_priority_map(self):
        """Test default severity to priority mapping."""
        from redops.modules.ticketing.jira import JiraConfig

        config = JiraConfig(
            base_url="https://test.atlassian.net",
            username="user",
            api_token="token",
            project_key="TEST",
        )

        assert config.priority_map["critical"] == "Highest"
        assert config.priority_map["high"] == "High"
        assert config.priority_map["medium"] == "Medium"
        assert config.priority_map["low"] == "Low"

    def test_jira_api_url(self):
        """Test API URL building."""
        from redops.modules.ticketing.jira import JiraClient, JiraConfig

        config = JiraConfig(
            base_url="https://test.atlassian.net/",
            username="user",
            api_token="token",
            project_key="TEST",
        )
        client = JiraClient(config)

        url = client._api_url("issue")
        assert url == "https://test.atlassian.net/rest/api/3/issue"

    def test_jira_create_issue_not_configured(self):
        """Test issue creation when not configured."""
        from redops.modules.ticketing.jira import JiraClient, JiraConfig

        config = JiraConfig(
            base_url="",
            username="",
            api_token="",
            project_key="",
        )
        client = JiraClient(config)

        with patch("redops.modules.ticketing.jira.HAS_REQUESTS", True):
            result = client.create_issue("Test", "Description")

        assert result["success"] is False
        assert "not configured" in result["error"]

    def test_jira_create_issue_no_project(self):
        """Test issue creation without project key."""
        from redops.modules.ticketing.jira import JiraClient, JiraConfig

        config = JiraConfig(
            base_url="https://test.atlassian.net",
            username="user",
            api_token="token",
            project_key="",
        )
        client = JiraClient(config)

        with patch("redops.modules.ticketing.jira.HAS_REQUESTS", True):
            result = client.create_issue("Test", "Description")

        assert result["success"] is False
        assert "project key" in result["error"]

    @patch("redops.modules.ticketing.jira.requests")
    def test_jira_create_issue_success(self, mock_requests):
        """Test successful issue creation."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": "12345",
            "key": "SEC-123",
        }
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.ticketing.jira.HAS_REQUESTS", True):
            from redops.modules.ticketing.jira import JiraClient, JiraConfig

            config = JiraConfig(
                base_url="https://test.atlassian.net",
                username="user",
                api_token="token",
                project_key="SEC",
            )
            client = JiraClient(config)

            result = client.create_issue(
                summary="Test Issue",
                description="Test description",
                severity="high",
            )

            assert result["success"] is True
            assert result["issue_key"] == "SEC-123"
            assert "test.atlassian.net/browse/SEC-123" in result["url"]

    @patch("redops.modules.ticketing.jira.requests")
    def test_jira_create_issue_error(self, mock_requests):
        """Test issue creation with error response."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "errorMessages": ["Project does not exist"]
        }
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.ticketing.jira.HAS_REQUESTS", True):
            from redops.modules.ticketing.jira import JiraClient, JiraConfig

            config = JiraConfig(
                base_url="https://test.atlassian.net",
                username="user",
                api_token="token",
                project_key="INVALID",
            )
            client = JiraClient(config)

            result = client.create_issue("Test", "Description")

            assert result["success"] is False
            assert "400" in result["error"]

    @patch("redops.modules.ticketing.jira.requests")
    def test_jira_create_issue_from_finding(self, mock_requests):
        """Test creating issue from finding."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "123", "key": "SEC-456"}
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.ticketing.jira.HAS_REQUESTS", True):
            from redops.modules.ticketing.jira import JiraClient, JiraConfig

            config = JiraConfig(
                base_url="https://test.atlassian.net",
                username="user",
                api_token="token",
                project_key="SEC",
            )
            client = JiraClient(config)

            finding = {
                "title": "SQL Injection Vulnerability",
                "severity": "critical",
                "module": "analysis.vulns",
                "description": "Found SQL injection",
                "data": {"endpoint": "/api/users"},
            }

            result = client.create_issue_from_finding(
                finding=finding,
                scan_id="scan-123",
                target="example.com",
            )

            assert result["success"] is True

            # Verify the request was made correctly
            call_args = mock_requests.post.call_args
            issue_data = call_args[1]["json"]
            assert "[RedOPS]" in issue_data["fields"]["summary"]
            assert "severity-critical" in issue_data["fields"]["labels"]

    @patch("redops.modules.ticketing.jira.requests")
    def test_create_jira_issues_from_findings(self, mock_requests):
        """Test creating multiple issues from findings."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "123", "key": "SEC-789"}
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.ticketing.jira.HAS_REQUESTS", True):
            from redops.modules.ticketing.jira import create_jira_issues_from_findings

            ctx = Context(target="example.com")
            ctx.add("finding_sqli", {
                "title": "SQL Injection",
                "severity": "critical",
                "module": "test",
                "description": "Found SQLi",
            })
            ctx.add("finding_xss", {
                "title": "XSS",
                "severity": "medium",
                "module": "test",
                "description": "Found XSS",
            })
            ctx.add("finding_info", {
                "title": "Info Disclosure",
                "severity": "low",  # Below threshold
                "module": "test",
                "description": "Minor info",
            })

            result = create_jira_issues_from_findings(ctx, {
                "base_url": "https://test.atlassian.net",
                "username": "user",
                "api_token": "token",
                "project_key": "SEC",
                "min_severity": "medium",
            })

            assert "jira_issues_result" in ctx.data
            # Should create 2 issues (critical and medium, but not low)
            assert ctx.data["jira_issues_result"]["total_findings"] == 2


class TestGitHubClient:
    """Tests for GitHub Issues integration."""

    def test_github_config_from_env(self):
        """Test GitHubConfig from environment variables."""
        env = {
            "GITHUB_TOKEN": "ghp_test123",
            "GITHUB_OWNER": "myorg",
            "GITHUB_REPO": "security-issues",
            "GITHUB_LABELS": "security,automated,redops",
            "GITHUB_ASSIGNEES": "securityteam",
        }
        with patch.dict("os.environ", env):
            from redops.modules.ticketing.github import GitHubConfig
            config = GitHubConfig.from_env()

            assert config.token == env["GITHUB_TOKEN"]
            assert config.owner == "myorg"
            assert config.repo == "security-issues"
            assert "security" in config.labels
            assert "securityteam" in config.assignees

    def test_github_api_url(self):
        """Test API URL building."""
        from redops.modules.ticketing.github import GitHubClient, GitHubConfig

        config = GitHubConfig(
            token="test-token",
            owner="myorg",
            repo="myrepo",
        )
        client = GitHubClient(config)

        url = client._api_url("issues")
        assert url == "https://api.github.com/repos/myorg/myrepo/issues"

    def test_github_create_issue_not_configured(self):
        """Test issue creation when not configured."""
        from redops.modules.ticketing.github import GitHubClient, GitHubConfig

        config = GitHubConfig(token="", owner="", repo="")
        client = GitHubClient(config)

        with patch("redops.modules.ticketing.github.HAS_REQUESTS", True):
            result = client.create_issue("Test", "Body")

        assert result["success"] is False
        assert "not configured" in result["error"]

    @patch("redops.modules.ticketing.github.requests")
    def test_github_create_issue_success(self, mock_requests):
        """Test successful issue creation."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": 12345,
            "number": 42,
            "html_url": "https://github.com/myorg/myrepo/issues/42",
        }
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.ticketing.github.HAS_REQUESTS", True):
            from redops.modules.ticketing.github import GitHubClient, GitHubConfig

            config = GitHubConfig(
                token="test-token",
                owner="myorg",
                repo="myrepo",
            )
            client = GitHubClient(config)

            result = client.create_issue(
                title="Test Issue",
                body="Test body",
            )

            assert result["success"] is True
            assert result["issue_number"] == 42
            assert "github.com" in result["url"]

    @patch("redops.modules.ticketing.github.requests")
    def test_github_create_issue_with_options(self, mock_requests):
        """Test issue creation with labels and assignees."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": 1, "number": 1, "html_url": "https://github.com/test"}
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.ticketing.github.HAS_REQUESTS", True):
            from redops.modules.ticketing.github import GitHubClient, GitHubConfig

            config = GitHubConfig(
                token="test-token",
                owner="myorg",
                repo="myrepo",
                labels=["security"],
                assignees=["user1"],
            )
            client = GitHubClient(config)

            result = client.create_issue(
                title="Test",
                body="Body",
                labels=["extra-label"],
                assignees=["user2"],
            )

            # Verify labels and assignees were merged
            call_args = mock_requests.post.call_args
            issue_data = call_args[1]["json"]
            assert "security" in issue_data["labels"]
            assert "extra-label" in issue_data["labels"]
            assert "user1" in issue_data["assignees"]
            assert "user2" in issue_data["assignees"]

    @patch("redops.modules.ticketing.github.requests")
    def test_github_create_issue_error(self, mock_requests):
        """Test issue creation with error response."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"message": "Not Found"}
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.ticketing.github.HAS_REQUESTS", True):
            from redops.modules.ticketing.github import GitHubClient, GitHubConfig

            config = GitHubConfig(
                token="test-token",
                owner="invalid",
                repo="invalid",
            )
            client = GitHubClient(config)

            result = client.create_issue("Test", "Body")

            assert result["success"] is False
            assert "404" in result["error"]

    @patch("redops.modules.ticketing.github.requests")
    def test_github_create_issue_from_finding(self, mock_requests):
        """Test creating issue from finding."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": 123,
            "number": 99,
            "html_url": "https://github.com/myorg/myrepo/issues/99",
        }
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.ticketing.github.HAS_REQUESTS", True):
            from redops.modules.ticketing.github import GitHubClient, GitHubConfig

            config = GitHubConfig(
                token="test-token",
                owner="myorg",
                repo="myrepo",
            )
            client = GitHubClient(config)

            finding = {
                "title": "Critical Vulnerability",
                "severity": "critical",
                "module": "analysis.vulns",
                "description": "Found critical issue",
                "data": {"cve": "CVE-2024-1234"},
            }

            result = client.create_issue_from_finding(
                finding=finding,
                scan_id="scan-456",
                target="api.example.com",
            )

            assert result["success"] is True
            assert result["issue_number"] == 99

            # Verify Markdown formatting
            call_args = mock_requests.post.call_args
            issue_data = call_args[1]["json"]
            assert "[RedOPS]" in issue_data["title"]
            assert "Security Finding" in issue_data["body"]
            assert "**Severity:**" in issue_data["body"]
            assert "api.example.com" in issue_data["body"]

    def test_github_severity_badge(self):
        """Test severity badge generation."""
        from redops.modules.ticketing.github import GitHubClient, GitHubConfig

        config = GitHubConfig(token="test", owner="test", repo="test")
        client = GitHubClient(config)

        assert "CRITICAL" in client._severity_badge("critical")
        assert "HIGH" in client._severity_badge("high")
        assert "MEDIUM" in client._severity_badge("medium")
        assert "LOW" in client._severity_badge("low")
        assert "INFO" in client._severity_badge("info")

    @patch("redops.modules.ticketing.github.requests")
    def test_github_add_comment(self, mock_requests):
        """Test adding a comment."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": 789,
            "html_url": "https://github.com/test/test/issues/1#issuecomment-789",
        }
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.ticketing.github.HAS_REQUESTS", True):
            from redops.modules.ticketing.github import GitHubClient, GitHubConfig

            config = GitHubConfig(token="test", owner="myorg", repo="myrepo")
            client = GitHubClient(config)

            result = client.add_comment(1, "Test comment")

            assert result["success"] is True
            assert result["comment_id"] == 789

    @patch("redops.modules.ticketing.github.requests")
    def test_github_close_issue(self, mock_requests):
        """Test closing an issue."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests.patch.return_value = mock_response
        mock_requests.post.return_value = MagicMock(status_code=201, json=MagicMock(return_value={}))

        with patch("redops.modules.ticketing.github.HAS_REQUESTS", True):
            from redops.modules.ticketing.github import GitHubClient, GitHubConfig

            config = GitHubConfig(token="test", owner="myorg", repo="myrepo")
            client = GitHubClient(config)

            result = client.close_issue(42, comment="Fixed")

            assert result["success"] is True

    @patch("redops.modules.ticketing.github.requests")
    def test_create_github_issues_from_findings(self, mock_requests):
        """Test creating multiple issues from findings."""
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": 1, "number": 1, "html_url": "https://github.com/test"}
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.ticketing.github.HAS_REQUESTS", True):
            from redops.modules.ticketing.github import create_github_issues_from_findings

            ctx = Context(target="example.com")
            ctx.add("finding_high", {
                "title": "High Severity",
                "severity": "high",
                "module": "test",
                "description": "High issue",
            })
            ctx.add("finding_medium", {
                "title": "Medium Severity",
                "severity": "medium",
                "module": "test",
                "description": "Medium issue",
            })
            ctx.add("finding_low", {
                "title": "Low Severity",
                "severity": "low",  # Below threshold
                "module": "test",
                "description": "Low issue",
            })

            result = create_github_issues_from_findings(ctx, {
                "token": "test-token",
                "owner": "myorg",
                "repo": "myrepo",
                "min_severity": "medium",
            })

            assert "github_issues_result" in ctx.data
            # Should create 2 issues (high and medium, but not low)
            assert ctx.data["github_issues_result"]["total_findings"] == 2


class TestTicketingModuleImports:
    """Test that all ticketing modules are properly exported."""

    def test_jira_imports(self):
        """Test Jira module imports."""
        from redops.modules.ticketing import (
            create_jira_issue,
            create_jira_issues_from_findings,
            JiraClient,
            JiraConfig,
        )

        assert callable(create_jira_issue)
        assert callable(create_jira_issues_from_findings)

    def test_github_imports(self):
        """Test GitHub module imports."""
        from redops.modules.ticketing import (
            create_github_issue,
            create_github_issues_from_findings,
            GitHubClient,
            GitHubConfig,
        )

        assert callable(create_github_issue)
        assert callable(create_github_issues_from_findings)
