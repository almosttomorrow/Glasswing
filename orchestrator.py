#!/usr/bin/env python3
"""
Project Glasswing Demo — Orchestrator
Three-wave autonomous vulnerability hunting pipeline using claude-opus-4-5.

Wave 1 — Triage:   Score every file in target/ for vulnerability likelihood (1-5).
Wave 2 — Hunt:     Spawn parallel agents to deep-scan files scoring 4 or above.
Wave 3 — Validate: A senior-reviewer agent confirms which findings are real and critical.
"""

import os
import sys
import json
import time
import glob
import re
import concurrent.futures
from pathlib import Path
from typing import Optional

import anthropic

# ── Configuration ─────────────────────────────────────────────────────────────

MODEL = "claude-opus-4-5"
TARGET_DIR = Path(__file__).parent / "target"
TRIAGE_PREVIEW_CHARS = 200   # characters of each file sent in Wave 1
HUNT_SCORE_THRESHOLD = 4     # minimum score to trigger Wave 2 deep scan

# ── ANSI colour helpers ────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BLUE   = "\033[94m"
MAGENTA = "\033[95m"


def c(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes."""
    return "".join(codes) + text + RESET


def score_bar(score: int, max_score: int = 5) -> str:
    """Render a simple block-character progress bar for a score."""
    filled = "█" * score
    empty  = "░" * (max_score - score)
    colour = RED if score >= 4 else (YELLOW if score == 3 else GREEN)
    return c(filled, colour) + c(empty, DIM)


def divider(char: str = "═", width: int = 60) -> str:
    return c(char * width, DIM)


# ── API client ────────────────────────────────────────────────────────────────

def get_client() -> anthropic.Anthropic:
    """Return an Anthropic client, failing fast with a helpful message if no key is set."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(c("\n[ERROR] ANTHROPIC_API_KEY environment variable is not set.", RED, BOLD))
        print("  Set it with:  export ANTHROPIC_API_KEY=your-key-here")
        print("  Or copy .env.example → .env, fill in your key, then: source .env\n")
        sys.exit(1)
    return anthropic.Anthropic(api_key=api_key)


# ── File loading ──────────────────────────────────────────────────────────────

def load_target_files() -> dict[str, str]:
    """Read all .py files from the target directory. Returns {filename: content}."""
    files = {}
    for path in sorted(TARGET_DIR.glob("*.py")):
        files[path.name] = path.read_text(encoding="utf-8")
    return files


# ── Wave 1 — Triage ───────────────────────────────────────────────────────────

TRIAGE_SYSTEM = (
    "You are a security triage analyst. You will be given a list of source files "
    "with short previews. Score each file from 1 to 5 for how likely it is to "
    "contain a critical security vulnerability, where 1 = almost certainly clean "
    "and 5 = almost certainly vulnerable. Reply ONLY with a JSON array of objects, "
    "each with keys: 'file' (string) and 'score' (integer 1-5). No prose, no markdown."
)

def build_triage_prompt(files: dict[str, str]) -> str:
    lines = []
    for name, content in files.items():
        preview = content[:TRIAGE_PREVIEW_CHARS].replace("\n", " ").strip()
        lines.append(f"FILE: {name}\nPREVIEW: {preview}\n")
    return "\n".join(lines)


def wave1_triage(client: anthropic.Anthropic, files: dict[str, str]) -> list[dict]:
    """
    Wave 1: ask the model to score all files 1-5 by vulnerability likelihood.
    Returns a list of {file, score} dicts sorted highest-first.
    """
    print(f"\n{divider()}")
    print(c("  WAVE 1  —  TRIAGE", CYAN, BOLD))
    print(f"{divider()}")
    print(f"  Sending {len(files)} files to {c(MODEL, YELLOW)} for scoring…\n")

    t0 = time.time()
    response = client.messages.create(
        model=MODEL,
        max_tokens=512,
        system=TRIAGE_SYSTEM,
        messages=[{"role": "user", "content": build_triage_prompt(files)}],
    )
    elapsed = time.time() - t0

    raw = response.content[0].text.strip()

    # Parse JSON — strip any accidental markdown fences the model might add
    clean = re.sub(r"^```[a-z]*\n?|```$", "", raw, flags=re.MULTILINE).strip()
    scores = json.loads(clean)

    # Sort highest-score first
    scores.sort(key=lambda x: x["score"], reverse=True)

    print(f"  {'File':<25}  {'Score':<12}  Rating")
    print(f"  {'─'*25}  {'─'*12}  {'─'*25}")
    for entry in scores:
        name  = entry["file"]
        score = entry["score"]
        flag  = c("  ← queued for deep scan", RED) if score >= HUNT_SCORE_THRESHOLD else ""
        print(f"  {name:<25}  {score_bar(score)}  {score}/5{flag}")

    print(f"\n  {c('Wave 1 complete', GREEN)} in {elapsed:.1f}s")
    return scores


# ── Wave 2 — Hunt (parallel agents) ──────────────────────────────────────────

HUNT_SYSTEM = (
    "You are a security researcher performing a thorough code audit. "
    "Analyse the provided source file for critical security vulnerabilities. "
    "If you find one or more critical vulnerabilities, return a JSON object with these keys: "
    "  found (boolean), file (string), type (string), description (string), "
    "  exploit_example (string), severity (string: critical|high|medium|low). "
    "If no critical vulnerability is found, return: {\"found\": false, \"file\": \"<name>\"}. "
    "Reply ONLY with the JSON object. No prose, no markdown code fences."
)

def hunt_single_file(args: tuple) -> dict:
    """
    Worker function executed in a subprocess pool.
    Receives (api_key, filename, content) and returns the parsed finding dict.
    """
    api_key, filename, content = args
    client = anthropic.Anthropic(api_key=api_key)
    prompt = f"File: {filename}\n\n```python\n{content}\n```"

    t0 = time.time()
    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=HUNT_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    elapsed = time.time() - t0

    raw = response.content[0].text.strip()
    clean = re.sub(r"^```[a-z]*\n?|```$", "", raw, flags=re.MULTILINE).strip()
    finding = json.loads(clean)
    finding["_elapsed"] = round(elapsed, 1)
    return finding


def wave2_hunt(files: dict[str, str], high_risk: list[str]) -> list[dict]:
    """
    Wave 2: spawn one parallel agent per high-risk file.
    Returns a list of finding dicts (found=True entries only get forwarded to Wave 3).
    """
    print(f"\n{divider()}")
    print(c("  WAVE 2  —  HUNT  (parallel agents)", MAGENTA, BOLD))
    print(f"{divider()}")
    print(f"  Launching {len(high_risk)} parallel agent(s) on high-risk files…\n")

    api_key = os.environ["ANTHROPIC_API_KEY"]
    work_items = [(api_key, fname, files[fname]) for fname in high_risk]

    findings = []
    t0 = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(high_risk)) as pool:
        future_map = {pool.submit(hunt_single_file, item): item[1] for item in work_items}

        for future in concurrent.futures.as_completed(future_map):
            fname = future_map[future]
            try:
                result = future.result()
                elapsed = result.get("_elapsed", "?")
                if result.get("found"):
                    severity = result.get("severity", "unknown").upper()
                    sev_colour = RED if severity == "CRITICAL" else YELLOW
                    print(
                        f"  {c('[AGENT]', CYAN, BOLD)} {fname:<25} "
                        f"→ {c('FINDING', RED, BOLD)}: "
                        f"{result.get('type', 'unknown')} "
                        f"[{c(severity, sev_colour)}] "
                        f"({elapsed}s)"
                    )
                else:
                    print(
                        f"  {c('[AGENT]', CYAN, BOLD)} {fname:<25} "
                        f"→ {c('clean', GREEN)} ({elapsed}s)"
                    )
                findings.append(result)
            except Exception as exc:
                print(f"  {c('[AGENT]', CYAN, BOLD)} {fname:<25} → {c(f'ERROR: {exc}', RED)}")

    total = time.time() - t0
    found_count = sum(1 for f in findings if f.get("found"))
    print(f"\n  {c('Wave 2 complete', GREEN)} in {total:.1f}s  "
          f"— {c(str(found_count), RED if found_count else GREEN)} finding(s) to validate")
    return findings


# ── Wave 3 — Validation ───────────────────────────────────────────────────────

VALIDATE_SYSTEM = (
    "You are a senior security engineer performing a final validation pass. "
    "You will receive a list of potential vulnerability findings from junior researchers. "
    "For each finding, assess whether it is a real, exploitable, critical issue or a false positive. "
    "Return a JSON array of objects, each with keys: "
    "  confirmed (boolean), file (string), verdict (string), impact (string). "
    "Reply ONLY with the JSON array. No prose, no markdown code fences."
)

def wave3_validate(client: anthropic.Anthropic, findings: list[dict]) -> list[dict]:
    """
    Wave 3: send all Wave 2 findings to a senior validator agent.
    Returns a list of {confirmed, file, verdict, impact} dicts.
    """
    print(f"\n{divider()}")
    print(c("  WAVE 3  —  VALIDATION", YELLOW, BOLD))
    print(f"{divider()}")

    positive_findings = [f for f in findings if f.get("found")]
    if not positive_findings:
        print(f"  {c('No findings to validate.', DIM)}")
        return []

    print(f"  Submitting {len(positive_findings)} finding(s) for senior review…\n")

    # Serialize finding reports, stripping internal metadata
    clean_findings = [
        {k: v for k, v in f.items() if not k.startswith("_")}
        for f in positive_findings
    ]
    prompt = json.dumps(clean_findings, indent=2)

    t0 = time.time()
    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=VALIDATE_SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    elapsed = time.time() - t0

    raw = response.content[0].text.strip()
    clean = re.sub(r"^```[a-z]*\n?|```$", "", raw, flags=re.MULTILINE).strip()
    verdicts = json.loads(clean)

    confirmed_count = sum(1 for v in verdicts if v.get("confirmed"))

    for v in verdicts:
        confirmed = v.get("confirmed", False)
        icon   = c("✔ CONFIRMED", GREEN, BOLD) if confirmed else c("✘ REJECTED ", DIM)
        fname  = v.get("file", "unknown")
        impact = v.get("impact", "")
        verdict_text = v.get("verdict", "")
        print(f"  {icon}  {fname:<25}  {c(verdict_text, WHITE)}")
        if confirmed and impact:
            print(f"  {'':>14}  Impact: {c(impact, YELLOW)}")

    print(f"\n  {c('Wave 3 complete', GREEN)} in {elapsed:.1f}s  "
          f"— {c(str(confirmed_count), RED if confirmed_count else GREEN)} "
          f"confirmed critical finding(s)")
    return verdicts


# ── Main ──────────────────────────────────────────────────────────────────────

def print_header() -> None:
    width = 60
    print("\n" + c("═" * width, CYAN))
    title = "PROJECT GLASSWING DEMO"
    pad = (width - len(title)) // 2
    print(c(" " * pad + title, CYAN, BOLD))
    model_line = f"Model: {MODEL}"
    pad2 = (width - len(model_line)) // 2
    print(c(" " * pad2 + model_line, YELLOW))
    print(c("═" * width, CYAN))
    print(c("  Autonomous three-wave vulnerability hunting pipeline", DIM))
    print(c("  Target: PixelForge gaming platform (synthetic)", DIM))
    print()


def print_summary(scores: list[dict], findings: list[dict], verdicts: list[dict]) -> None:
    print(f"\n{divider('═')}")
    print(c("  FINAL SUMMARY", BOLD, WHITE))
    print(f"{divider('═')}")
    high_risk = [s["file"] for s in scores if s["score"] >= HUNT_SCORE_THRESHOLD]
    print(f"  Files scanned  : {len(scores)}")
    print(f"  High-risk files: {len(high_risk)}  ({', '.join(high_risk) or 'none'})")
    print(f"  Findings found : {sum(1 for f in findings if f.get('found'))}")
    confirmed = [v for v in verdicts if v.get("confirmed")]
    print(f"  Confirmed crits: {c(str(len(confirmed)), RED if confirmed else GREEN, BOLD)}")
    if confirmed:
        print()
        for v in confirmed:
            print(f"  {c('★', RED)}  {v['file']}  —  {v['verdict']}")
    print()


def main() -> None:
    print_header()

    client = get_client()
    files  = load_target_files()

    if not files:
        print(c(f"[ERROR] No .py files found in {TARGET_DIR}", RED))
        sys.exit(1)

    print(f"  Loaded {c(str(len(files)), CYAN)} files from {c(str(TARGET_DIR), CYAN)}\n")

    # ── Wave 1
    scores = wave1_triage(client, files)

    high_risk_files = [s["file"] for s in scores if s["score"] >= HUNT_SCORE_THRESHOLD]

    # ── Wave 2
    findings: list[dict] = []
    if high_risk_files:
        findings = wave2_hunt(files, high_risk_files)
    else:
        print(f"\n{c('No files scored ≥ ' + str(HUNT_SCORE_THRESHOLD) + ' — skipping Wave 2.', DIM)}")

    # ── Wave 3
    verdicts = wave3_validate(client, findings)

    # ── Summary
    print_summary(scores, findings, verdicts)


if __name__ == "__main__":
    main()
