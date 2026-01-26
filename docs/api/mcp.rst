MCP Package
===========

The MCP (Model Context Protocol) package provides integration with Claude Code and other AI assistants.

MCP Server
----------

.. automodule:: redops.mcp.server
   :members:
   :undoc-members:
   :show-inheritance:

MCP Tools
---------

.. automodule:: redops.mcp.tools
   :members:
   :undoc-members:
   :show-inheritance:

Tool Reference
--------------

The following MCP tools are available:

redops_scan
~~~~~~~~~~~

Run a security scan on a target.

**Parameters:**

* ``target`` (str): Target domain or URL
* ``preset`` (str): Scan preset (quick, recon, full, ai_enhanced)

redops_check_ip
~~~~~~~~~~~~~~~

Check IP reputation across multiple threat intelligence sources.

**Parameters:**

* ``ip`` (str): IP address to check
* ``sources`` (list): Sources to query (greynoise, abuseipdb)

redops_check_url
~~~~~~~~~~~~~~~~

Check if a URL is known to be malicious.

**Parameters:**

* ``url`` (str): URL to check

redops_cert_transparency
~~~~~~~~~~~~~~~~~~~~~~~~

Search Certificate Transparency logs for subdomains.

**Parameters:**

* ``domain`` (str): Domain to search
* ``include_expired`` (bool): Include expired certificates

redops_asn_lookup
~~~~~~~~~~~~~~~~~

Look up ASN information for an IP or domain.

**Parameters:**

* ``target`` (str): IP, domain, or ASN to look up
* ``include_prefixes`` (bool): Include IP prefixes
* ``include_peers`` (bool): Include peer information

redops_enumerate_subdomains
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Enumerate subdomains for a domain.

**Parameters:**

* ``domain`` (str): Domain to enumerate
* ``use_ct`` (bool): Use Certificate Transparency
* ``threads`` (int): Concurrent threads

redops_export_sarif
~~~~~~~~~~~~~~~~~~~

Export scan results as SARIF for CI/CD integration.

**Parameters:**

* ``scan_data`` (object): Scan results to export
* ``output_path`` (str): Output file path

redops_export_junit
~~~~~~~~~~~~~~~~~~~

Export scan results as JUnit XML.

**Parameters:**

* ``scan_data`` (object): Scan results to export
* ``output_path`` (str): Output file path
* ``fail_on_high`` (bool): Treat high severity as failures

redops_dashboard_summary
~~~~~~~~~~~~~~~~~~~~~~~~

Generate dashboard summary from scan results.

**Parameters:**

* ``scan_data`` (object): Scan results to summarize
