# Project Glasswing Demo

A demonstration of an autonomous, multi-wave vulnerability hunting pipeline powered by
[Claude claude-opus-4-5](https://www.anthropic.com/claude). This repository is a self-contained
reproduction of the *Project Glasswing* methodology, built so that any engineering team
can run it locally against their own codebase in under five minutes.

---

## What Is Project Glasswing?

Project Glasswing was a proof-of-concept security research initiative showing that large
language models can be chained together in a structured "wave" pattern to discover,
confirm, and report critical vulnerabilities in production codebases — with a reliability
and depth that matches or exceeds a junior-to-mid-level human security researcher working
alone.

The core insight is simple: **don't ask one model to do everything**. Instead, use three
successive passes, each with a narrower, more expert prompt:

| Wave | Task | Scope |
|------|------|-------|
| 1 — Triage | Score all files by vulnerability likelihood | Entire codebase (shallow read) |
| 2 — Hunt | Full deep-dive on high-scoring files (parallel agents) | Files scoring ≥ 4 |
| 3 — Validate | Confirm findings are real and critical | All Wave 2 reports |

This mirrors how a real red team operates: broad recon → targeted exploitation → peer review.

---

## What This Repo Demonstrates

- **Wave-based AI orchestration** using the Anthropic Python SDK
- **Parallel agent execution** with `concurrent.futures.ThreadPoolExecutor`
- **Structured JSON output** extracted from model responses for programmatic use
- **A deliberately planted vulnerability** in `target/wallet_api.py` (integer sign inversion
  in a credit wallet transfer — the same class of bug that has caused real-world losses)
- Clean, colour-coded terminal output that a non-security engineer can follow

The fake target is a fictional gaming platform called **PixelForge** with a credit wallet
system. Four of the five files are intentionally clean or carry only minor weaknesses.
One file — `wallet_api.py` — contains a critical logic bug. Watch the pipeline find it.

---

## Disclaimer

> This demo uses **claude-opus-4-5**, Anthropic's publicly available API model.
> The original Project Glasswing research used an internal preview model referred to as
> *Mythos Preview*, which is not accessible through the public API. Results here will
> be directionally equivalent but may differ in specificity or reliability.
>
> The target code is **synthetic and intentionally vulnerable**. Do not deploy it.
> This repository is for educational and demonstration purposes only.

---

## Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.9 + |
| pip | latest |
| Anthropic API key | [platform.anthropic.com](https://platform.anthropic.com) |
| Docker (optional) | 20.10 + |

---

## Quick Start (local Python)

```bash
# 1. Clone and enter the repo
git clone https://github.com/almosttomorrow/glasswing.git
cd glasswing

# 2. Install the Anthropic SDK
pip install anthropic

# 3. Set your API key
cp .env.example .env
# Edit .env and paste your key

export ANTHROPIC_API_KEY=your-key-here   # or: source .env

# 4. Run the pipeline
python3 orchestrator.py
```

Expected runtime: ~60–90 seconds (depends on API latency and number of files scoring ≥ 4).

---

## Quick Start (Docker)

```bash
export ANTHROPIC_API_KEY=your-key-here
bash docker/run.sh
```

The script builds the image and runs the container, injecting your key from the host
environment. No `.env` file needed inside Docker.

---

## Repository Layout

```
glasswing/
├── README.md               ← you are here
├── orchestrator.py         ← the three-wave pipeline
├── .env.example            ← API key template
├── .gitignore
├── target/                 ← synthetic vulnerable codebase (PixelForge)
│   ├── wallet_api.py       ★ contains the planted critical vulnerability
│   ├── auth_service.py     ← weak hashing (MD5), minor issue
│   ├── session_mgr.py      ← weak entropy (random.randint), minor issue
│   ├── inventory_db.py     ← clean
│   └── store_api.py        ← clean
└── docker/
    ├── Dockerfile
    └── run.sh
```

---

## Understanding the Output

The terminal prints three clearly separated sections:

```
════════════════════════════════════════════
  PROJECT GLASSWING DEMO
  Model: claude-opus-4-5
════════════════════════════════════════════

[WAVE 1] Triage — scoring all files...
  wallet_api.py     ████████░░  4/5  ← queued for deep scan
  auth_service.py   ██████░░░░  3/5
  ...

[WAVE 2] Hunting — parallel agents on high-risk files...
  [AGENT] wallet_api.py  → FINDING: integer sign inversion in transfer()

[WAVE 3] Validation — senior review...
  ✔ CONFIRMED  wallet_api.py  |  CRITICAL  |  ...
```

Each confirmed finding includes:
- **File** and **type** of vulnerability
- **Description** of the flaw
- **Exploit example** (what an attacker would do)
- **Severity** and final **verdict**

---

## Extending This to a Real Codebase

Replace `target/` with your own source tree and adjust the glob pattern in
`orchestrator.py` (`TARGET_DIR`). The pipeline is language-agnostic at the triage
stage; Wave 2 prompts can be specialised per file extension if needed.

For large codebases (> 100 files) consider raising the Wave 1 chunk size or batching
files into groups of 10 before scoring.

---

## Security Note

Never commit real API keys. The `.gitignore` excludes `.env`. Always rotate a key
immediately if it is accidentally pushed to a public repository.
