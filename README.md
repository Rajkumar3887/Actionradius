<div align="center">
  <img src="docs/actionradius-banner.png" alt="ActionRadius — Blast-Radius Detection for GitHub Actions" width="900">
  
  <h3>Fleet-wide exposure analysis for compromised GitHub Actions dependencies</h3>

  <p align="center">
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python 3.12+"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
    <img src="https://img.shields.io/badge/Tests-180%2F180%20passing-success.svg" alt="Tests">
    <img src="https://img.shields.io/badge/Status-Production%20Ready-green.svg" alt="Status">
  </p>
  <br>

  [🚀 Quick Start](#-quick-start) •
  [✨ Features](#-features) •
  [🧭 Usage Modes](#-usage-modes) •
  [🧮 Scoring Model](#-scoring-model) •
  [🆚 Alternatives](#-why-not-zizmor--poutine)
  
  <br>
  <br> 
  
  Answer "which of my repos are actually exposed right now?" in minutes, not days.
</div>
<br> 

## 🧨 The Problem

On March 19, 2026, attackers hijacked **75 of 76 version tags** on `aquasecurity/trivy-action` — a security scanner used in thousands of CI pipelines — and used it to steal cloud credentials from downstream workflows. They also swapped a SHA pin in Trivy's own release workflow to point at an **orphan commit** in `actions/checkout`, leaving the `# v6.0.2` comment intact so reviewers wouldn't notice.

If you were a security lead that morning, your first question wasn't *"is our workflow YAML well-written"* — zizmor and poutine already answer that. It was:

> **"Which of our repos actually pull this action, at what pin, triggered by what, with access to what secrets — right now?"**

Nobody's tooling answered that question in an hour. ActionRadius does.

<div align="right"><a href="#actionradius">↑ back to top</a></div> 

---

## ⚙️ How It Works

<div align="center">
  <img src="docs/architecture.png" alt="ActionRadius Architecture" width="720">
</div>

ActionRadius connects directly to the GitHub API, inventories your entire organization's workflow files in seconds via the Git Trees API, resolves every mutable tag to its live SHA, evaluates the contextual risk (secrets, permissions, triggers), and outputs a ranked incident-response report with tri-state compromise classification: **COMPROMISED**, **SAFE**, or **UNKNOWN**.

<div align="right"><a href="#actionradius">↑ back to top</a></div> 

---

## ✨ Features

| Feature | What it does |
|---|---|
| **🔍 Zero-Setup Inventory** | Git Trees API (`?recursive=1`) pulls workflows across hundreds of repos without hitting Code Search rate limits |
| **🔗 Live Ref Resolution** | Resolves mutable tags (`@v4`) to their exact 40-char SHAs in real-time |
| **🎯 Compromised Range Matching** | `--bad-from` / `--bad-to` checks if a resolved SHA falls inside a known-bad commit window via the Compare API |
| **🚦 Tri-State Classification** | Every finding is `COMPROMISED`, `SAFE`, or `UNKNOWN` — never silently treated as safe |
| **👻 Orphan Commit Detection** | Flags hidden SHAs not on any branch (the exact technique from the Trivy binary attack) |
| **🐳 Docker Action Support** | Fully parses `uses: docker://` references and correctly scores mutable Docker tags |
| **🕵️ SHA/Comment Mismatch** | Detects when `@SHA # v6.0.2` claims a version tag the SHA doesn't actually match |
| **🧮 Context-Aware Scoring** | Evaluates triggers, permissions, secrets, and runner type alongside compromise status |
| **📡 Curated Incident Feed** | `--target-feed` scans your org against every known-compromised action in one pass |
| **🚨 IOC Hunting** | Searches `run:` blocks for malicious domains (e.g., `aquasecurtiy.org`) |
| **📊 SARIF / HTML / Graphviz** | Multiple report formats including GHAS-compatible SARIF and blast-radius graphs |

<div align="right"><a href="#actionradius">↑ back to top</a></div> 

---

## 🆚 Why Not Zizmor / Poutine?

<details>
<summary><strong>Click to expand — same CI, different job</strong></summary>
<br> 

Zizmor and Poutine are excellent tools for **per-workflow hygiene** — flagging `pull_request_target` with untrusted input, detecting taint in shell expressions, and linting YAML patterns.

ActionRadius solves a **different problem**: fleet-wide incident response. When `trivy-action@0.34.2` was compromised on March 19, zizmor could tell you "this workflow has a risky trigger pattern." It could not tell you:

- Which of your 500 repos currently resolve `trivy-action@0.34.2` to the **poisoned SHA** (`ddb9da44`)
- That the `actions/checkout` SHA pin in your release workflow is an **orphan commit** with a **spoofed version comment** (`# v6.0.2`)
- That the workflow leaking your AWS credentials has `secrets: inherit` + `pull_request_target` + a self-hosted runner

| | Zizmor / Poutine | ActionRadius |
|---|---|---|
| **Scope** | Single workflow file | Entire org / fleet |
| **Question answered** | "Is this YAML risky?" | "Am I exposed right now?" |
| **Ref resolution** | Static | Live, via GitHub API |
| **Compromise check** | ❌ | ✅ Compare-API range matching |
| **Output** | Lint findings | Ranked incident-response report |

ActionRadius answers all three of the questions above. It treats your CI/CD estate as a graph and ranks the blast radius. The two tool families are complementary — ActionRadius even ingests zizmor/poutine SARIF output as an additional signal (see `--external-sarif` below).
</details>

<div align="right"><a href="#actionradius">↑ back to top</a></div> 

---

## 🚀 Quick Start

```bash
git clone https://github.com/Rajkumar3887/Actionradius.git 
cd Actionradius 
python -m venv venv 
source venv/bin/activate  # Windows: .\venv\Scripts\activate 
pip install -e . 
export GITHUB_TOKEN="your_token_here"
```

<div align="right"><a href="#actionradius">↑ back to top</a></div> 

---

## 🧭 Usage Modes

<table> 
<tr><td width="140"><strong>Incident Response</strong></td><td>"Which repos are exposed to <em>this</em> compromise?"</td></tr> 
<tr><td><strong>Curated Feed</strong></td><td>"Show me my exposure to <em>every</em> known incident."</td></tr> 
<tr><td><strong>Legacy Safe-Ref</strong></td><td>"Flag everything except this known-good SHA."</td></tr> 
<tr><td><strong>Drift</strong></td><td>"What changed since yesterday's scan?"</td></tr> 
<tr><td><strong>IOC Hunting</strong></td><td>"Did anything pull from a known malicious domain?"</td></tr> 
</table> 

### Incident Response Mode (Compromised Range)
```bash
# "Which repos are exposed to the Trivy compromise?" 
actionradius scan \
  --org my-org \
  --target aquasecurity/trivy-action \
  --bad-from ddb9da44 \
  --bad-to 76d05ec629db6c6a67e5a1f8a6cbf069d1e4e1de
```

### Curated Feed Mode (All Known Incidents)
```bash
# "Show me my org's exposure to EVERY known-compromised action" 
actionradius scan \
  --org my-org \
  --target-feed data/compromised_feed.json \
  --html report.html
```

### Legacy Safe-Ref Mode
```bash
# "Flag everything except this known-good SHA" 
actionradius scan \
  --org my-org \
  --target actions/checkout \
  --safe-ref 8410ad0602e1e429cee44a835ae97775bbe51671
```

### Drift Mode (CI/CD Scanning)
```bash
# "What changed since yesterday's scan?" 
actionradius diff report-monday.json report-tuesday.json
```
*Outputs NEW findings, RESOLVED findings, and ESCALATED severities.*

### IOC Hunting
```bash
# "Did any workflow pull from the typosquatted C2?" 
actionradius scan \
  --org my-org \
  --ioc-search "aquasecurtiy.org"
```

<div align="right"><a href="#actionradius">↑ back to top</a></div> 

---

## 📋 Report Output

Each finding answers the incident-response question directly:

```text
[CRITICAL] [COMPROMISED] my-org/payment-api:.github/workflows/deploy.yml -> aquasecurity/trivy-action@0.34.2 
  Resolved SHA: ddb9da44... 
  Pin type: mutable_ref 
  Rationale: Mutable pin exposed to compromised commit (+3), Fork-reachable trigger (+3), Inherited secrets (+3)
```

HTML reports split findings into three sections:

| Section | Meaning |
|---|---|
| 🚨 **Currently Compromised** | action resolves to a known-bad SHA right now |
| ⚠️ **Unknown** | cannot confirm safe (API error, unresolvable ref) |
| ✅ **Safe** | provably outside the compromised range |

<div align="right"><a href="#actionradius">↑ back to top</a></div> 

---

## 🧮 Scoring Model

All weights are configurable via `data/weights.yaml`:

| Signal | Default Weight | Rationale |
|---|---|---|
| Orphan commit SHA | +8.0 | Hidden commit not on any branch — strong attack indicator |
| SHA pinned to compromised commit | +8.0 | Directly executing known-bad code |
| Mutable pin + compromised | +3.0 | Tag/branch currently points at bad commit |
| Unknown compromise status | +4.0 | Cannot confirm safe — don't assume it is |
| Fork-reachable trigger | +3.0 | `pull_request_target`, `workflow_run` from forks |
| `secrets: inherit` | +3.0 | All org secrets available to the action |
| Explicit secrets | +2.0 | Named secrets (AWS_KEY, NPM_TOKEN, etc.) |
| Self-hosted runner | +2.0 | Persistent infrastructure access |

Score → severity: `0-1` info · `2-4` medium · `5-7` high · `8+` critical

<div align="right"><a href="#actionradius">↑ back to top</a></div> 

---

## 🤝 Contributing

Issues and pull requests are welcome — whether it's a new scoring signal, a report format, or a bug fix.

## 📄 License

Released under the [MIT License](LICENSE).
