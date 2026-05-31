# RedOPS Roadmap

**Current version:** 1.5.0 (released 2026-01-26)
**Last updated:** 2026-05-30
**Audit:** Baseline drafted from repo state, audited locally by qwen2.5:14b (Ollama), folded back in.

RedOPS is a modular AI-assisted recon, forensics, and exposure-analysis framework
(Python, FastAPI, ~193K LOC, 5072 tests, 80% coverage gate). This roadmap covers the
path from the current released state through the next two minor releases and a 2.0
horizon. The through-line: a fully-coded **offensive Active Chain is sitting unreleased**,
and the next releases are about shipping it *safely*, not building more.

---

## Where we are

- **Shipped (v1.5.0):** recon/OSINT, metadata forensics, threat intel (ThreatFox,
  MalwareBazaar, AbuseIPDB), threat modeling, reporting, web dashboard, MCP server,
  AI-assisted analysis (OpenAI/Anthropic), compliance/governance.
- **Built but UNRELEASED — the Active Chain:** AI-orchestrated active attack sequence
  (wireless evil-twin + deauth, subnet recon, CVE cross-reference, autonomous Ollama
  agent). ~1047 LOC under `modules/active/` + `modules/ai/`, with `test_wireless.py`,
  `test_network.py`, `test_agent.py` and `config/pipelines/active_chain.json`. Committed
  to `main` but **absent from CHANGELOG, README, and every tagged release.**
- **In flight:** PR #58 adds Qwen-uncensored model presets to the ReAct agent.
- **Maintenance:** 10 open dependabot/CI PRs (#48–#57); recent commits are dominated by
  bumps. Stale remote branch `fix/ci-permissions` (PR #47, already merged) needs deletion.

---

## Milestone 0 — Legal & Safety Gate (BLOCKS v1.6.0)

> Added from the qwen audit: the prior draft treated authorization as a code feature and
> omitted the review that must precede shipping deauth/evil-twin capability at all. This
> gate blocks the release; it is not optional polish.

- [ ] Written legal-boundary review: jurisdiction, authorized-use definition, and the
      explicit set of actions RedOPS will and will **not** perform. Lands in `SECURITY.md`
      + a new `docs/legal-boundaries.md`.
- [ ] Design the authorization mechanism (not just a flag): scope assertion + recorded
      operator consent that every active module checks before executing.
- [ ] Threat-model the misuse case (RedOPS used against an unauthorized network) and
      document the technical controls that make casual misuse hard.
- [ ] Operator walkthrough: a mock authorized-engagement runbook proving the consent flow
      is understood end-to-end (cheap test for the "everyone understands authorized-use"
      assumption).

## Milestone 1 — Ship the Active Chain (v1.6.0)

- [ ] **Authorization gating in code:** no active module (`deauth`, `evil_twin`, …) fires
      without passing the Milestone-0 scope/consent check. Add a test that asserts each
      active module refuses to run absent an authorized-target assertion.
- [ ] **Egress enforcement is tested, not asserted:** add a test that attempts cloud egress
      during an active-chain run and asserts it is blocked (local Ollama only).
- [ ] CHANGELOG `[Unreleased]` → enumerate every active/ai module added.
- [ ] README "Active Chain" section + update the `❌ What RedOPS Does NOT Do` boundary to
      reflect the new capability and its guardrails. Integrate `mobile-wireless-audit-kit.md`
      into the active-chain user guide.
- [ ] **CI for active modules:** split hardware/root-dependent tests (wireless injection)
      from CI-safe unit tests; document what runs in CI vs. only on the dedicated lab rig.
- [ ] Full-chain smoke test on lab hardware (Alfa AWUS036NHA + Kali), runbook checked in.
- [ ] Tag v1.6.0.

## Milestone 2 — Harden the AI agent (v1.6.x → v1.7.0)

> The agent (`modules/ai/agent.py`, `planner.py`, `tools.py`) exists and is being tuned in
> PR #58. This milestone is rails, not construction — and it follows the active-chain
> release, per the audit's ordering note.

- [ ] Land/triage PR #58 (Qwen presets) first so hardening builds on the final agent shape.
- [ ] Action allow-list + dry-run mode for the agent's tool registry.
- [ ] Human-in-the-loop confirmation gate for any state-changing/offensive tool call.
- [ ] Bounded reasoning loop (max steps + cost/time budget) to prevent runaway chains.
- [ ] **Replay/audit log:** persist every agent decision (input context, chosen action,
      result) to a structured log, with a documented post-engagement review checklist.
- [ ] Agent stress/load test under a long attack-surface summary to confirm it neither
      stalls nor destabilizes the host (cheap test for the stability assumption).

## Maintenance lane (continuous, not a milestone)

> Per the audit, dependabot churn is operational hygiene, not roadmap work.

- [ ] Delete stale `fix/ci-permissions` remote branch (PR #47 merged).
- [ ] Triage the 10 open dependabot PRs: admin-merge clean minor bumps, skip major-version
      jumps (upload-artifact 4→7, checkout 4→6, action-gh-release 2→3) pending review.
- [ ] Enable grouped dependabot updates to cut PR noise going forward.
- [ ] Re-evaluate the coverage exclusions added to meet the 80% gate — confirm they exclude
      only genuinely-untestable infra, not real gaps.

## Horizon — v2.0 themes (not yet committed)

- Expanded CVE source beyond the hardcoded home-lab list in `cve_check.py` (audit flags this
  as higher-value than the SDK work below).
- Plugin SDK maturity for third-party active/recon modules.
- Multi-tenant hardening for the web dashboard + API key model.
- Post-release compliance audit: periodic check that deployed usage matches documented
  authorized-use constraints; security review of dependabot-pulled third-party libraries.

---

## Operating constraints

- **Authorized use only.** Active offensive modules are home-lab / authorized-network scope.
- **AI layer runs local** (Ollama) for the active chain — no cloud egress (enforced + tested,
  not assumed — see Milestone 1).
- Tests before commit; conventional commits; 80% coverage gate.

---

## Open assumptions to validate (exploration carry-overs)

| Assumption | Cheap test |
|---|---|
| Operators understand authorized-use policy | Mock authorized-engagement walkthrough (Milestone 0) |
| Ollama agent stays stable under load | Stress test with a large attack-surface summary (Milestone 2) |
| 80% coverage is enough for active modules | Manual adversarial test pass against the live chain on lab hardware |
| Cloud-egress prevention is robust | Simulate an unauthorized egress attempt and assert it's blocked (Milestone 1) |
