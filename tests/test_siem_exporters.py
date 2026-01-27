"""Tests for SIEM export modules: Splunk, Elasticsearch, Datadog."""

from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from redops.core.context import Context
from redops.core.models import Finding, RiskLevel


class TestSplunkExporter:
    """Tests for Splunk HEC exporter."""

    def test_splunk_config_from_env(self):
        """Test SplunkConfig from environment variables."""
        env = {
            "SPLUNK_HEC_URL": "https://splunk.example.com:8088/services/collector",
            "SPLUNK_HEC_TOKEN": "test-token",
            "SPLUNK_INDEX": "security",
        }
        with patch.dict("os.environ", env):
            from redops.modules.export.siem.splunk import SplunkConfig

            config = SplunkConfig.from_env()

            assert config.hec_url == env["SPLUNK_HEC_URL"]
            assert config.hec_token == env["SPLUNK_HEC_TOKEN"]
            assert config.index == "security"

    def test_splunk_build_event(self):
        """Test building a Splunk HEC event."""
        from redops.modules.export.siem.splunk import SplunkHECExporter, SplunkConfig

        config = SplunkConfig(
            hec_url="https://splunk.example.com:8088",
            hec_token="test-token",
            index="main",
            source="redops",
            sourcetype="redops:scan",
        )
        exporter = SplunkHECExporter(config)

        event = exporter._build_event(
            {"key": "value"},
            timestamp=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
            event_type="test",
        )

        assert event["source"] == "redops"
        assert event["sourcetype"] == "redops:scan:test"
        assert event["index"] == "main"
        assert event["event"] == {"key": "value"}
        assert "time" in event

    def test_splunk_add_event(self):
        """Test adding events to batch."""
        from redops.modules.export.siem.splunk import SplunkHECExporter, SplunkConfig

        config = SplunkConfig(hec_url="https://test", hec_token="token")
        exporter = SplunkHECExporter(config)

        exporter.add_event({"data": "test1"})
        exporter.add_event({"data": "test2"})

        assert len(exporter._pending_events) == 2

    def test_splunk_add_finding(self):
        """Test adding a finding."""
        from redops.modules.export.siem.splunk import SplunkHECExporter, SplunkConfig

        config = SplunkConfig(hec_url="https://test", hec_token="token")
        exporter = SplunkHECExporter(config)

        finding = Finding(
            module="test.module",
            title="Test Finding",
            description="A test finding",
            severity=RiskLevel.HIGH,
            data={"detail": "info"},
        )
        exporter.add_finding(finding, scan_id="scan-123")

        assert len(exporter._pending_events) == 1
        event = exporter._pending_events[0]["event"]
        assert event["title"] == "Test Finding"
        assert event["severity"] == "high"
        assert event["scan_id"] == "scan-123"

    def test_splunk_flush_empty(self):
        """Test flushing empty batch."""
        from redops.modules.export.siem.splunk import SplunkHECExporter, SplunkConfig

        config = SplunkConfig(hec_url="https://test", hec_token="token")
        exporter = SplunkHECExporter(config)

        result = exporter.flush()

        assert result["success"] is True
        assert result["sent"] == 0

    def test_splunk_flush_no_requests(self):
        """Test flush when requests not available."""
        with patch("redops.modules.export.siem.splunk.HAS_REQUESTS", False):
            from redops.modules.export.siem.splunk import (
                SplunkHECExporter,
                SplunkConfig,
            )

            config = SplunkConfig(hec_url="https://test", hec_token="token")
            exporter = SplunkHECExporter(config)
            exporter.add_event({"test": "data"})

            result = exporter.flush()

            assert result["success"] is False
            assert "requests" in result["error"]

    def test_splunk_flush_not_configured(self):
        """Test flush when not configured."""
        from redops.modules.export.siem.splunk import SplunkHECExporter, SplunkConfig

        config = SplunkConfig(hec_url="", hec_token="")
        exporter = SplunkHECExporter(config)
        exporter.add_event({"test": "data"})

        with patch("redops.modules.export.siem.splunk.HAS_REQUESTS", True):
            result = exporter.flush()

        assert result["success"] is False
        assert "not configured" in result["error"]

    @patch("redops.modules.export.siem.splunk.requests")
    def test_splunk_flush_success(self, mock_requests):
        """Test successful flush."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.export.siem.splunk.HAS_REQUESTS", True):
            from redops.modules.export.siem.splunk import (
                SplunkHECExporter,
                SplunkConfig,
            )

            config = SplunkConfig(hec_url="https://splunk:8088", hec_token="token")
            exporter = SplunkHECExporter(config)
            exporter.add_event({"test": "data1"})
            exporter.add_event({"test": "data2"})

            result = exporter.flush()

            assert result["success"] is True
            assert result["sent"] == 2
            assert len(exporter._pending_events) == 0

    @patch("redops.modules.export.siem.splunk.requests")
    def test_splunk_flush_error(self, mock_requests):
        """Test flush with error response."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {"text": "Invalid token"}
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.export.siem.splunk.HAS_REQUESTS", True):
            from redops.modules.export.siem.splunk import (
                SplunkHECExporter,
                SplunkConfig,
            )

            config = SplunkConfig(hec_url="https://splunk:8088", hec_token="bad-token")
            exporter = SplunkHECExporter(config)
            exporter.add_event({"test": "data"})

            result = exporter.flush()

            assert result["success"] is False
            assert "403" in result["error"]

    @patch("redops.modules.export.siem.splunk.requests")
    def test_export_to_splunk_function(self, mock_requests):
        """Test the export_to_splunk pipeline function."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.export.siem.splunk.HAS_REQUESTS", True):
            from redops.modules.export.siem.splunk import export_to_splunk

            ctx = Context(target="example.com")
            ctx.add("pipeline_name", "test-pipeline")
            ctx.add("finding_test", {"title": "Test", "severity": "high"})

            export_to_splunk(
                ctx,
                {
                    "hec_url": "https://splunk:8088",
                    "hec_token": "token",
                },
            )

            assert "splunk_export_result" in ctx.data
            assert ctx.data["splunk_export_result"]["success"] is True


class TestElasticExporter:
    """Tests for Elasticsearch exporter."""

    def test_elastic_config_from_env(self):
        """Test ElasticConfig from environment variables."""
        env = {
            "ELASTIC_HOSTS": "http://es1:9200,http://es2:9200",
            "ELASTIC_INDEX_PREFIX": "security",
            "ELASTIC_API_KEY": "test-api-key",
        }
        with patch.dict("os.environ", env):
            from redops.modules.export.siem.elastic import ElasticConfig

            config = ElasticConfig.from_env()

            assert config.hosts == ["http://es1:9200", "http://es2:9200"]
            assert config.index_prefix == "security"
            assert config.api_key == "test-api-key"

    def test_elastic_get_index_name(self):
        """Test index name generation."""
        from redops.modules.export.siem.elastic import ElasticExporter, ElasticConfig

        config = ElasticConfig(hosts=["http://localhost:9200"], index_prefix="redops")
        exporter = ElasticExporter(config)

        index_name = exporter._get_index_name("scan")

        assert index_name.startswith("redops-scans-")
        assert "." in index_name  # Date separator

    def test_elastic_get_auth_headers_api_key(self):
        """Test API key auth headers."""
        from redops.modules.export.siem.elastic import ElasticExporter, ElasticConfig

        config = ElasticConfig(
            hosts=["http://localhost:9200"],
            api_key="test-api-key",
        )
        exporter = ElasticExporter(config)

        headers = exporter._get_auth_headers()

        assert "Authorization" in headers
        assert headers["Authorization"] == "ApiKey test-api-key"

    def test_elastic_get_auth_headers_basic(self):
        """Test basic auth headers."""
        from redops.modules.export.siem.elastic import ElasticExporter, ElasticConfig

        config = ElasticConfig(
            hosts=["http://localhost:9200"],
            username="elastic",
            password="password",
        )
        exporter = ElasticExporter(config)

        headers = exporter._get_auth_headers()

        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")

    def test_elastic_add_document(self):
        """Test adding documents."""
        from redops.modules.export.siem.elastic import ElasticExporter, ElasticConfig

        config = ElasticConfig(hosts=["http://localhost:9200"])
        exporter = ElasticExporter(config)

        exporter.add_document({"field": "value1"}, doc_type="scan")
        exporter.add_document({"field": "value2"}, doc_type="finding")

        assert len(exporter._pending_docs) == 2
        assert "@timestamp" in exporter._pending_docs[0]["doc"]

    def test_elastic_flush_empty(self):
        """Test flushing empty batch."""
        from redops.modules.export.siem.elastic import ElasticExporter, ElasticConfig

        config = ElasticConfig(hosts=["http://localhost:9200"])
        exporter = ElasticExporter(config)

        result = exporter.flush()

        assert result["success"] is True
        assert result["indexed"] == 0

    @patch("redops.modules.export.siem.elastic.requests")
    def test_elastic_flush_success(self, mock_requests):
        """Test successful flush."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"errors": False, "items": []}
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.export.siem.elastic.HAS_REQUESTS", True):
            from redops.modules.export.siem.elastic import (
                ElasticExporter,
                ElasticConfig,
            )

            config = ElasticConfig(hosts=["http://localhost:9200"])
            exporter = ElasticExporter(config)
            exporter.add_document({"test": "data1"})
            exporter.add_document({"test": "data2"})

            result = exporter.flush()

            assert result["success"] is True
            assert result["indexed"] == 2

    @patch("redops.modules.export.siem.elastic.requests")
    def test_elastic_flush_partial_errors(self, mock_requests):
        """Test flush with partial errors."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "errors": True,
            "items": [
                {"index": {"status": 201}},
                {"index": {"status": 400, "error": {"reason": "Parse error"}}},
            ],
        }
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.export.siem.elastic.HAS_REQUESTS", True):
            from redops.modules.export.siem.elastic import (
                ElasticExporter,
                ElasticConfig,
            )

            config = ElasticConfig(hosts=["http://localhost:9200"])
            exporter = ElasticExporter(config)
            exporter.add_document({"test": "data1"})
            exporter.add_document({"test": "data2"})

            result = exporter.flush()

            assert result["success"] is True
            assert result["indexed"] == 1
            assert "errors" in result

    @patch("redops.modules.export.siem.elastic.requests")
    def test_elastic_create_index_template(self, mock_requests):
        """Test creating index template."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests.put.return_value = mock_response

        with patch("redops.modules.export.siem.elastic.HAS_REQUESTS", True):
            from redops.modules.export.siem.elastic import (
                ElasticExporter,
                ElasticConfig,
            )

            config = ElasticConfig(hosts=["http://localhost:9200"])
            exporter = ElasticExporter(config)

            result = exporter.create_index_template()

            assert result["success"] is True

    @patch("redops.modules.export.siem.elastic.requests")
    def test_export_to_elastic_function(self, mock_requests):
        """Test the export_to_elastic pipeline function."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"errors": False, "items": []}
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.export.siem.elastic.HAS_REQUESTS", True):
            from redops.modules.export.siem.elastic import export_to_elastic

            ctx = Context(target="example.com")
            ctx.add("pipeline_name", "test-pipeline")
            ctx.add("finding_test", {"title": "Test", "severity": "high"})

            export_to_elastic(
                ctx,
                {
                    "hosts": "http://localhost:9200",
                },
            )

            assert "elastic_export_result" in ctx.data
            assert ctx.data["elastic_export_result"]["success"] is True


class TestDatadogExporter:
    """Tests for Datadog exporter."""

    def test_datadog_config_from_env(self):
        """Test DatadogConfig from environment variables."""
        env = {
            "DD_API_KEY": "test-api-key",
            "DD_SITE": "eu1",
            "DD_SERVICE": "my-service",
            "DD_TAGS": "env:prod,team:security",
        }
        with patch.dict("os.environ", env):
            from redops.modules.export.siem.datadog import DatadogConfig

            config = DatadogConfig.from_env()

            assert config.api_key == "test-api-key"
            assert config.site == "eu1"
            assert config.service == "my-service"
            assert "env:prod" in config.tags

    def test_datadog_endpoints(self):
        """Test endpoint selection by site."""
        from redops.modules.export.siem.datadog import DatadogConfig

        config_us1 = DatadogConfig(api_key="key", site="us1")
        config_eu1 = DatadogConfig(api_key="key", site="eu1")

        assert "datadoghq.com" in config_us1.logs_endpoint
        assert "datadoghq.eu" in config_eu1.logs_endpoint

    def test_datadog_build_log_entry(self):
        """Test building a log entry."""
        from redops.modules.export.siem.datadog import DatadogExporter, DatadogConfig

        config = DatadogConfig(
            api_key="test",
            service="redops",
            source="redops",
            tags=["env:test"],
        )
        exporter = DatadogExporter(config)

        entry = exporter._build_log_entry(
            "Test message",
            {"field": "value"},
            level="warning",
            tags=["extra:tag"],
        )

        assert entry["message"] == "Test message"
        assert entry["service"] == "redops"
        assert entry["status"] == "warning"
        assert "env:test" in entry["ddtags"]
        assert "extra:tag" in entry["ddtags"]

    def test_datadog_add_log(self):
        """Test adding logs."""
        from redops.modules.export.siem.datadog import DatadogExporter, DatadogConfig

        config = DatadogConfig(api_key="test")
        exporter = DatadogExporter(config)

        exporter.add_log("Test log 1", {"key": "value1"})
        exporter.add_log("Test log 2", {"key": "value2"}, level="error")

        assert len(exporter._pending_logs) == 2

    def test_datadog_add_finding(self):
        """Test adding a finding."""
        from redops.modules.export.siem.datadog import DatadogExporter, DatadogConfig

        config = DatadogConfig(api_key="test")
        exporter = DatadogExporter(config)

        finding = Finding(
            module="test.module",
            title="High Severity Finding",
            description="A critical issue",
            severity=RiskLevel.HIGH,
            data={},
        )
        exporter.add_finding(finding, scan_id="scan-123")

        assert len(exporter._pending_logs) == 1
        log = exporter._pending_logs[0]
        assert "High Severity Finding" in log["message"]
        assert log["status"] == "error"  # HIGH maps to error

    def test_datadog_flush_empty(self):
        """Test flushing empty batch."""
        from redops.modules.export.siem.datadog import DatadogExporter, DatadogConfig

        config = DatadogConfig(api_key="test")
        exporter = DatadogExporter(config)

        result = exporter.flush_logs()

        assert result["success"] is True
        assert result["sent"] == 0

    def test_datadog_flush_no_api_key(self):
        """Test flush without API key."""
        from redops.modules.export.siem.datadog import DatadogExporter, DatadogConfig

        config = DatadogConfig(api_key="")
        exporter = DatadogExporter(config)
        exporter.add_log("Test")

        with patch("redops.modules.export.siem.datadog.HAS_REQUESTS", True):
            result = exporter.flush_logs()

        assert result["success"] is False
        assert "not configured" in result["error"]

    @patch("redops.modules.export.siem.datadog.requests")
    def test_datadog_flush_success(self, mock_requests):
        """Test successful flush."""
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.export.siem.datadog.HAS_REQUESTS", True):
            from redops.modules.export.siem.datadog import (
                DatadogExporter,
                DatadogConfig,
            )

            config = DatadogConfig(api_key="test-key")
            exporter = DatadogExporter(config)
            exporter.add_log("Log 1")
            exporter.add_log("Log 2")

            result = exporter.flush_logs()

            assert result["success"] is True
            assert result["sent"] == 2

    @patch("redops.modules.export.siem.datadog.requests")
    def test_datadog_send_event(self, mock_requests):
        """Test sending an event."""
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_response.json.return_value = {"event": {"id": 12345}}
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.export.siem.datadog.HAS_REQUESTS", True):
            from redops.modules.export.siem.datadog import (
                DatadogExporter,
                DatadogConfig,
            )

            config = DatadogConfig(api_key="test-key")
            exporter = DatadogExporter(config)

            result = exporter.send_event(
                title="Test Event",
                text="Event details",
                alert_type="warning",
            )

            assert result["success"] is True
            assert result["event_id"] == 12345

    @patch("redops.modules.export.siem.datadog.requests")
    def test_export_to_datadog_function(self, mock_requests):
        """Test the export_to_datadog pipeline function."""
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_requests.post.return_value = mock_response

        with patch("redops.modules.export.siem.datadog.HAS_REQUESTS", True):
            from redops.modules.export.siem.datadog import export_to_datadog

            ctx = Context(target="example.com")
            ctx.add("pipeline_name", "test-pipeline")
            ctx.add("finding_test", {"title": "Test", "severity": "high"})

            export_to_datadog(
                ctx,
                {
                    "api_key": "test-key",
                },
            )

            assert "datadog_export_result" in ctx.data
            assert ctx.data["datadog_export_result"]["success"] is True


class TestSIEMModuleImports:
    """Test that all SIEM modules are properly exported."""

    def test_siem_imports_from_export(self):
        """Test imports from export module."""
        from redops.modules.export import (
            export_to_splunk,
            export_to_elastic,
            export_to_datadog,
        )

        assert callable(export_to_splunk)
        assert callable(export_to_elastic)
        assert callable(export_to_datadog)

    def test_siem_imports_from_siem(self):
        """Test imports from siem module."""
        from redops.modules.export.siem import (
            export_to_splunk,
            export_to_elastic,
            export_to_datadog,
        )

        assert callable(export_to_splunk)
        assert callable(export_to_elastic)
        assert callable(export_to_datadog)
