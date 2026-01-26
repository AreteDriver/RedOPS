"""
Elasticsearch/OpenSearch integration.

Exports RedOPS findings and scan results to Elasticsearch or OpenSearch
for SIEM integration and analysis.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import os
import json
from dataclasses import dataclass
from redops.core.context import Context
from redops.core.models import Finding

# Try to import requests
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class ElasticConfig:
    """Elasticsearch configuration."""

    hosts: List[str]
    index_prefix: str = "redops"
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: bool = True
    timeout: int = 30

    @classmethod
    def from_env(cls) -> "ElasticConfig":
        """Create config from environment variables."""
        hosts_str = os.environ.get("ELASTIC_HOSTS", "http://localhost:9200")
        hosts = [h.strip() for h in hosts_str.split(",")]
        return cls(
            hosts=hosts,
            index_prefix=os.environ.get("ELASTIC_INDEX_PREFIX", "redops"),
            api_key=os.environ.get("ELASTIC_API_KEY"),
            username=os.environ.get("ELASTIC_USERNAME"),
            password=os.environ.get("ELASTIC_PASSWORD"),
            verify_ssl=os.environ.get("ELASTIC_VERIFY_SSL", "true").lower() == "true",
        )


class ElasticExporter:
    """
    Exports data to Elasticsearch/OpenSearch.

    Supports both API key and basic authentication.
    Uses the bulk API for efficient indexing.
    """

    def __init__(self, config: Optional[ElasticConfig] = None):
        """
        Initialize the exporter.

        Args:
            config: Elasticsearch configuration (uses env vars if not provided)
        """
        self.config = config or ElasticConfig.from_env()
        self._pending_docs: List[Dict] = []
        self._host_index = 0

    def _get_host(self) -> str:
        """Get the current host (round-robin selection)."""
        host = self.config.hosts[self._host_index % len(self.config.hosts)]
        self._host_index += 1
        return host.rstrip("/")

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        headers = {"Content-Type": "application/json"}

        if self.config.api_key:
            headers["Authorization"] = f"ApiKey {self.config.api_key}"
        elif self.config.username and self.config.password:
            import base64
            credentials = f"{self.config.username}:{self.config.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        return headers

    def _get_index_name(self, doc_type: str = "scan") -> str:
        """
        Generate index name with date suffix.

        Args:
            doc_type: Document type (scan, finding, etc.)

        Returns:
            Index name like 'redops-scans-2024.01.15'
        """
        date_str = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        return f"{self.config.index_prefix}-{doc_type}s-{date_str}"

    def add_document(
        self,
        data: Dict[str, Any],
        doc_type: str = "scan",
        doc_id: Optional[str] = None,
    ) -> None:
        """
        Add a document to the pending batch.

        Args:
            data: Document data
            doc_type: Document type for index selection
            doc_id: Optional document ID
        """
        index_name = self._get_index_name(doc_type)

        # Add timestamp if not present
        if "@timestamp" not in data:
            data["@timestamp"] = datetime.now(timezone.utc).isoformat()

        self._pending_docs.append({
            "index": index_name,
            "id": doc_id,
            "doc": data,
        })

    def add_finding(self, finding: Finding, scan_id: Optional[str] = None) -> None:
        """
        Add a finding document.

        Args:
            finding: RedOPS finding
            scan_id: Optional scan identifier
        """
        doc = {
            "scan_id": scan_id,
            "event_type": "security_finding",
            "module": finding.module,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value if finding.severity else "unknown",
            "data": finding.data,
            "@timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.add_document(doc, doc_type="finding")

    def flush(self) -> Dict[str, Any]:
        """
        Send all pending documents via bulk API.

        Returns:
            Result with status and counts
        """
        if not self._pending_docs:
            return {"success": True, "indexed": 0, "message": "No documents to index"}

        if not HAS_REQUESTS:
            return {"success": False, "error": "requests library not available"}

        if not self.config.hosts:
            return {"success": False, "error": "Elasticsearch hosts not configured"}

        headers = self._get_auth_headers()

        # Build bulk request body
        bulk_lines = []
        for doc_info in self._pending_docs:
            action = {"index": {"_index": doc_info["index"]}}
            if doc_info.get("id"):
                action["index"]["_id"] = doc_info["id"]
            bulk_lines.append(json.dumps(action))
            bulk_lines.append(json.dumps(doc_info["doc"]))

        bulk_body = "\n".join(bulk_lines) + "\n"
        total_docs = len(self._pending_docs)

        try:
            host = self._get_host()
            response = requests.post(
                f"{host}/_bulk",
                headers=headers,
                data=bulk_body,
                verify=self.config.verify_ssl,
                timeout=self.config.timeout,
            )

            if response.status_code in (200, 201):
                result_data = response.json()

                # Check for individual errors
                errors = []
                if result_data.get("errors"):
                    for item in result_data.get("items", []):
                        index_result = item.get("index", {})
                        if index_result.get("error"):
                            errors.append(index_result["error"])

                self._pending_docs = []

                if errors:
                    return {
                        "success": True,
                        "indexed": total_docs - len(errors),
                        "errors": errors[:5],  # Limit error details
                        "message": f"Indexed {total_docs - len(errors)} of {total_docs} documents",
                    }

                return {
                    "success": True,
                    "indexed": total_docs,
                    "message": f"Indexed {total_docs} documents",
                }

            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text[:200]}",
                "attempted": total_docs,
            }

        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": str(e),
                "attempted": total_docs,
            }

    def export_context(self, ctx: Context, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Export all context data to Elasticsearch.

        Args:
            ctx: Pipeline context
            scan_id: Optional scan identifier

        Returns:
            Export result
        """
        scan_id = scan_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Export scan summary
        summary_doc = {
            "scan_id": scan_id,
            "event_type": "scan_summary",
            "target": ctx.target,
            "pipeline_name": ctx.get("pipeline_name"),
            "pipeline_version": ctx.get("pipeline_version"),
            "data_keys": list(ctx.data.keys()),
            "@timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.add_document(summary_doc, doc_type="scan", doc_id=scan_id)

        # Export findings
        for key, value in ctx.data.items():
            if key.startswith("finding_"):
                finding_doc = {
                    "scan_id": scan_id,
                    "finding_key": key,
                    "event_type": "finding",
                    **value,
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self.add_document(finding_doc, doc_type="finding")

        # Export key scan results
        export_keys = [
            "domain_profile",
            "dns_enumeration",
            "subdomains",
            "port_scan",
            "ssl_analysis",
            "whois_data",
            "greynoise_result",
            "abuseipdb_result",
            "urlhaus_result",
            "urlscan_result",
            "passivedns_result",
            "otx_indicator",
        ]

        for key in export_keys:
            if key in ctx.data:
                result_doc = {
                    "scan_id": scan_id,
                    "result_type": key,
                    "event_type": "scan_result",
                    "data": ctx.data[key],
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self.add_document(result_doc, doc_type="result")

        return self.flush()

    def create_index_template(self) -> Dict[str, Any]:
        """
        Create an index template for RedOPS indices.

        Returns:
            Result with status
        """
        if not HAS_REQUESTS:
            return {"success": False, "error": "requests library not available"}

        template = {
            "index_patterns": [f"{self.config.index_prefix}-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "scan_id": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "target": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "module": {"type": "keyword"},
                        "title": {"type": "text"},
                        "description": {"type": "text"},
                        "pipeline_name": {"type": "keyword"},
                        "result_type": {"type": "keyword"},
                    }
                }
            }
        }

        headers = self._get_auth_headers()
        host = self._get_host()

        try:
            response = requests.put(
                f"{host}/_index_template/{self.config.index_prefix}-template",
                headers=headers,
                json=template,
                verify=self.config.verify_ssl,
                timeout=self.config.timeout,
            )

            if response.status_code in (200, 201):
                return {"success": True, "message": "Index template created"}

            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text[:200]}",
            }

        except requests.exceptions.RequestException as e:
            return {"success": False, "error": str(e)}


def export_to_elastic(
    ctx: Context, params: Optional[Dict[str, Any]] = None
) -> Context:
    """
    Export scan results to Elasticsearch.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - hosts: Elasticsearch hosts (comma-separated or ELASTIC_HOSTS env var)
            - index_prefix: Index prefix (default: redops)
            - api_key: API key (or ELASTIC_API_KEY env var)
            - username: Username (or ELASTIC_USERNAME env var)
            - password: Password (or ELASTIC_PASSWORD env var)
            - scan_id: Optional scan identifier

    Returns:
        Updated context with export result
    """
    params = params or {}

    hosts_str = params.get("hosts") or os.environ.get("ELASTIC_HOSTS", "")
    hosts = [h.strip() for h in hosts_str.split(",")] if hosts_str else []

    config = ElasticConfig(
        hosts=hosts,
        index_prefix=params.get("index_prefix", "redops"),
        api_key=params.get("api_key") or os.environ.get("ELASTIC_API_KEY"),
        username=params.get("username") or os.environ.get("ELASTIC_USERNAME"),
        password=params.get("password") or os.environ.get("ELASTIC_PASSWORD"),
        verify_ssl=params.get("verify_ssl", True),
    )

    exporter = ElasticExporter(config)

    ctx.log("Exporting to Elasticsearch", level="INFO")

    result = exporter.export_context(ctx, scan_id=params.get("scan_id"))

    if result.get("success"):
        ctx.log(f"Elasticsearch export complete: {result.get('indexed', 0)} documents", level="INFO")
    else:
        ctx.log(f"Elasticsearch export failed: {result.get('error')}", level="WARNING")

    ctx.add("elastic_export_result", result)
    return ctx
