# RedOPS Roadmap — Path to 10/10

> Audit date: 2026-05-30. Based on 5-agent deep analysis of architecture, testing, UX, AI/MCP, and competitive landscape.

## Current Scores

| Area | Score | Key Gap |
|------|-------|---------|
| Architecture | 8.2/10 | Distributed systems hardening |
| Test Coverage | 6/10 | Zero integration tests, active modules untested |
| UX/Dashboard | 6.5/10 | Charts not rendered, accessibility 3/10, mobile broken |
| MCP/AI | 5/10 | No cost tracking, weak prompts, no streaming |
| Competitive | 7/10 | Missing diff mode, attack graphs, Nuclei integration |

---

## Priority 1 — Critical (Do Now)

### Security and Reliability
- [ ] **AI cost management** — Add token counting + budget limits before API calls. Zero controls exist today.
- [ ] **Distributed session store** — Replace in-memory SessionStore with Redis backend (already in docker-compose).
- [ ] **Error handling overhaul** — Replace 249 bare `except Exception` blocks with domain-specific exceptions. Add retry logic with tenacity.
- [ ] **Context pipeline safety** — Add checkpoint/rollback to Context. Mutable dict passed by reference risks corruption.

### Dashboard (User-Facing)
- [ ] **Render actual charts** — Chart.js is loaded but never initialized. Wire SeverityDistributionChart, ModuleDistributionChart, RiskScoreGauge, TimelineChart to dashboard HTML.
- [ ] **Accessibility baseline** — Add ARIA labels, keyboard navigation, focus trapping in modals, skip-nav link. Current score: 3/10 WCAG.
- [ ] **Mobile responsiveness** — Fix modal width (w-96 breaks phones), add responsive table/card view, increase touch targets to 44x44px minimum.

### Testing
- [ ] **Create integration test suite** — CI references tests/integration/ with continue-on-error:true but no tests exist. Remove continue-on-error, add real integration tests.
- [ ] **Active/wireless module tests** — Deauth, evil twin, port scan, arp scan have zero test coverage. Security-critical code.
- [ ] **RF module tests** — All 14 new RF module files need test coverage.
- [ ] **Security control tests** — JWT expiration, API key rotation, SQL injection prevention, credential masking.

---

## Priority 2 — High (Next Sprint)

### AI Intelligence
- [ ] **Versioned prompt library** — Replace hardcoded "you are a cybersecurity analyst" with audience/industry/framework-specific templates in YAML. Add prompt versioning.
- [ ] **Streaming support** — All AI calls are blocking. Add async streaming for real-time dashboard updates.
- [ ] **Conversation memory** — Persist analysis context across AI calls. Every call currently creates fresh context.
- [ ] **Model router with fallback chain** — GPT-4 -> Claude -> Gemini automatic fallback. Cost-aware model selection.
- [ ] **Expand MCP tools to 20+** — Missing: pipeline execution, scan comparison, remediation planning, AI chat, finding correlation, report generation.

### Dashboard UX
- [ ] **Finding triage workflow** — Mark findings as false positive / accepted risk with notes and assignee.
- [ ] **Search/filter/sort controls** — API supports filtering, no UI controls exist.
- [ ] **Scan comparison view** — API endpoint exists but comparison logic is stubbed (returns zeros).
- [ ] **MITRE ATT&CK heatmap** — Exists in HTML reports but not in dashboard. Add clickable heatmap showing coverage gaps.
- [ ] **Real-time scan progress** — Use existing WebSocket infra to show live pipeline visualization with streaming findings.

### Competitive Features
- [ ] **Diff/delta scanning** — Store scan baselines, highlight net-new findings on subsequent scans. reconFTW does this. Table-stakes for continuous monitoring.
- [ ] **Zero-config quickstart** — `pip install redops && redops scan example.com` produces useful output in under 60 seconds with zero configuration.
- [ ] **Example pipeline library** — Add 10+ ready-to-use pipelines: Bug Bounty Recon, Corporate Exposure Audit, Incident Response Triage, Compliance Assessment, Wireless Recon.

---

## Priority 3 — Medium (Backlog)

### Architecture
- [ ] **Secrets management** — Integrate HashiCorp Vault or similar. API keys currently in env vars with no rotation mechanism.
- [ ] **Kubernetes hardening** — Add NetworkPolicy for egress controls, WAF integration.
- [ ] **Docker image pinning** — Replace all `latest` tags with specific versions.
- [ ] **Strict type checking** — Remove `--ignore-missing-imports` from mypy. Add `--strict`.
- [ ] **Conditional pipeline branching** — Add if/else/switch in pipeline YAML (Osmedeus pattern).

### Dashboard
- [ ] **Migrate Alpine.js to HTMX + Jinja2** — Better maintainability, lighter, more testable. Server-rendered HTML with HTMX for partial updates.
- [ ] **Dashboard customization** — Configurable widget layout, saved views per user role.
- [ ] **Notification webhooks** — Slack, email, PagerDuty with escalation chains. WebSocket-only today.
- [ ] **Report format selection in UI** — 7 formats exist (HTML, PDF, Markdown, SARIF, JUnit, OSCAL, Executive) but no UI to choose.
- [ ] **Role-based dashboard views** — CISO view (risk posture, trends) vs analyst view (technical details, raw findings).

### AI
- [ ] **AI threat narrative generator** — Given correlated findings, construct multi-step attack scenario narratives mapped to MITRE ATT&CK. No open-source tool does this well.
- [ ] **AI remediation playbooks** — Step-by-step remediation with copy-paste commands, not just "fix this misconfiguration."
- [ ] **AI false positive detection** — Train/prompt AI to identify likely FPs based on context. Reduces alert fatigue.
- [ ] **Attack chain inference** — AI correlates findings into multi-step attack paths with likelihood scoring.
- [ ] **PII filtering** — Scrub sensitive data before sending to external LLMs.
- [ ] **AI observability** — Metrics on latency, tokens, cost per action, per model, per user.

### MITRE ATT&CK
- [ ] **Official ATT&CK STIX data** — Replace hardcoded technique dictionary with official MITRE ATT&CK STIX bundle. Keeps data current (500+ techniques).
- [ ] **ATT&CK Navigator layer export** — Generate JSON compatible with MITRE ATT&CK Navigator for SOC team overlay.
- [ ] **Detection gap analysis** — Compare mapped techniques against detection coverage to identify blind spots.

---

## Priority 4 — Strategic (Differentiators)

### Platform Features
- [ ] **Nuclei template integration** — Run Nuclei's 8000+ community vulnerability templates as a RedOPS module.
- [ ] **Interactive attack graph** — D3.js/Cytoscape.js force-directed graph in web UI showing entity relationships and attack paths.
- [ ] **Distributed scanning** — Multi-node execution with cloud provisioning (Terraform templates for AWS/GCP/Azure).
- [ ] **Verified exploit paths** — Validation step that confirms exploitability, not just presence. CrowdStrike QuiltWorks pattern.
- [ ] **PTaaS report portal** — Web endpoint where clients view reports, track remediation status, download artifacts. Transforms RedOPS from tool to service.

### Ecosystem
- [ ] **Plugin marketplace/registry** — JSON index of community plugins with `redops plugin install <name>`.
- [ ] **Plugin sandboxing** — Run plugins in subprocess/container isolation.
- [ ] **Plugin scaffold CLI** — `redops plugin scaffold <name>` generates template with tests and docs.
- [ ] **Community template repository** — Separate repo for community-contributed pipelines, plugins, report templates.
- [ ] **Asset criticality scoring** — Crown jewel / business critical / standard / development classification that weights risk scores.
- [ ] **Remediation tracking with SLAs** — Assignee, due date, escalation. Wire into existing Jira/GitHub ticketing modules.
- [ ] **Compliance framework mapping** — Full SOC 2, ISO 27001, PCI DSS, HIPAA, NIST 800-53 control mapping per finding.
- [ ] **GraphQL endpoint** — Complex queries across findings, assets, techniques that REST can't handle efficiently.
- [ ] **External threat feed ingestion** — Consume STIX/TAXII, OTX, abuse.ch feeds and correlate with scan findings.

---

## Quick Wins (< 1 day each)

- [ ] Wire Chart.js to dashboard (charts exist, just not rendered)
- [ ] Add sse-starlette to pyproject.toml dependencies
- [ ] Remove continue-on-error: true from CI integration tests
- [ ] Add .env.example with all required variables
- [ ] Pin Docker image versions
- [ ] Add ARIA labels to dashboard HTML
- [ ] Fix PDF report fpdf2 enum errors
- [ ] Add --strict to mypy CI config
- [ ] ATT&CK Navigator JSON export
- [ ] Add 5+ example pipelines to config/pipelines/

---

## Effort Estimates

| Track | Hours | Impact |
|-------|-------|--------|
| AI/MCP overhaul | ~225h | Cost safety, analysis quality, streaming |
| Dashboard UX | ~120h | Usable product vs prototype |
| Testing | ~100h | Confidence in security-critical code |
| Infrastructure | ~80h | Production hardening |
| Competitive features | ~200h | Market differentiation |
| **Total** | **~725h** | |

---

## Competitive Positioning

RedOPS is already ahead of most open-source recon tools (reconFTW, Osmedeus, SpiderFoot) in:
- AI integration (5 providers, ReAct agent, MCP server)
- Report formats (7 types including OSCAL, SARIF)
- SIEM export (Splunk, Elastic, Datadog)
- Plugin architecture (lifecycle states, hook points)
- Multi-tenancy and auth

To reach 10/10, focus on:
1. **Dashboard must render its own charts** (embarrassing gap)
2. **AI must have cost controls** (financial risk)
3. **Diff/delta scanning** (continuous monitoring is table-stakes)
4. **Attack graph visualization** (makes complex findings comprehensible)
5. **AI threat narratives** (unique differentiator no OSS tool has)
