RedOPS Documentation
====================

.. image:: https://img.shields.io/badge/python-3.10+-blue.svg
   :target: https://www.python.org/downloads/

.. image:: https://img.shields.io/badge/license-MIT-green.svg
   :target: https://opensource.org/licenses/MIT

**RedOPS** is an advanced modular AI-assisted reconnaissance, forensics, and exposure-analysis framework. It provides comprehensive security assessment capabilities through a pipeline-based architecture.

.. note::

   This is NOT a hacking tool. It is a professional OSINT + metadata + threat-modeling automation system for authorized security assessments.

Features
--------

* **Pipeline-based Architecture**: Define and execute modular security assessment workflows
* **AI Integration**: Support for multiple AI providers (OpenAI, Anthropic, Google, Groq, Ollama)
* **Threat Intelligence**: Integration with GreyNoise, AbuseIPDB, URLhaus, and more
* **Reconnaissance**: Domain profiling, subdomain enumeration, certificate transparency
* **Reporting**: Multiple output formats (JSON, HTML, PDF, SARIF, JUnit, OSCAL)
* **Web Dashboard**: Real-time scan monitoring with WebSocket updates
* **Plugin System**: Extend functionality with custom modules

Quick Start
-----------

Installation
~~~~~~~~~~~~

.. code-block:: bash

   pip install redops[all]

Basic Usage
~~~~~~~~~~~

.. code-block:: bash

   # Run a quick scan
   redops scan example.com --preset quick

   # Run reconnaissance
   redops scan example.com --preset recon

   # AI-enhanced analysis
   redops scan example.com --preset ai_enhanced

   # Start web dashboard
   redops-web

Documentation
-------------

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   getting-started
   configuration
   cli-reference
   presets

.. toctree::
   :maxdepth: 2
   :caption: Developer Guide

   architecture
   modules
   plugins
   contributing

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/index
   api/core
   api/modules
   api/pipelines
   api/web
   api/mcp

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
