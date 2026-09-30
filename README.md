# hexhammer

English | [简体中文](README.zh-CN.md)

Autonomous penetration testing engine. Give it an authorized target — it runs the full chain from reconnaissance to evidence. Give it a CVE ID — it pulls the upstream patch, analyzes the root cause, builds a PoC, and verifies it on a local lab.

## What It Does

**Autonomous Penetration Testing**

```
Target → Recon → Exploit → Foothold → Privilege Escalation → Lateral Movement → Evidence Report
```

The engine decides each step autonomously: fingerprinting services, selecting attack paths, crafting payloads, analyzing results, and adapting strategy. Every action is logged with replayable request/response evidence.

**Vulnerability Reproduction & Weapon Research**

```
CVE ID → Fetch upstream patch diff → Root cause analysis → Build PoC → Local lab verification → Weapon library
```

Automated 1-day weaponization: reverse-engineer the vulnerability from the fix, not from public exploits.

**Attack & Defense Loop**

```
Pentest → Vulnerability report + fix recommendations → You patch → Same engine re-tests → Verify fix
```

Beyond finding bugs — it verifies your fixes too.

**Interactive Chat**

```bash
hexhammer chat
```
Type a message, it acts. Drop a URL, a code snippet, or a CVE ID — it analyzes what you give it. Streaming output, real-time tool call visibility.

## Capability Matrix

| Domain | Coverage |
|---|---|
| Web | OpenAPI enumeration, auth bypass / injection / XSS / SSRF, WAF evasion |
| Multi-stage Pentest | Foothold → privesc → lateral movement, AD chain (Kerberos / ADCS / ACL / relay) |
| Binary | checksec, disassembly, ROP, stack overflow exploitation |
| Cloud | SSRF → cloud metadata → credential access, bucket enumeration, local credential hunting |
| Evasion | WAF filter analysis, encoding bypass, payload transformation |
| Exploitation | CVE intel aggregation, patch diffing, PoC construction, lab verification |

## Installation

```bash
# Clone
git clone https://github.com/Aimer-zero/hexhammer.git && cd hexhammer

# Install dependencies (Python 3.10+)
uv sync

# Configure LLM
cp .env.example .env
# Edit .env with your API key (OpenAI-compatible / deepseek / Anthropic)

# Check external tool dependencies (missing tools won't block)
uv run hexhammer doctor
```

## Usage

### Autonomous Scan

```bash
# Recon only (read-only)
uv run hexhammer scan --target <ip> --mode recon

# Web/API pentest
uv run hexhammer scan --target <ip> --mode webapp

# Full chain + RCE proof (evidence only, auto-restore)
uv run hexhammer scan --target <ip> --mode chain --authorize-rce-proof
```

**Authorization levels** (default read-only):
- Default: passive probes + harmless verification
- `--authorize-rce-proof`: command execution for evidence (id/echo level, no persistence, auto-restore)
- Interactive mode supports `/target <ip>` to switch targets mid-session

### Interactive Chat

```bash
uv run hexhammer chat
```

Commands: `exit` quit · `clear` reset session · `/target <ip>` switch target

### Experience Review

The engine distills reusable insights after each mission. Human approval gates the knowledge library:

```bash
uv run hexhammer review <mission-dir>                 # View pending
uv run hexhammer review <mission-dir> --approve-all   # Approve into library
```

### Output

Each scan produces:
- `notes.md` — full process + conclusions
- `flags.json` — findings with replayable evidence
- `timeline.jsonl` — every step logged
- `cost.json` — token consumption

## Tool Surface (20 tools)

| Category | Tools |
|---|---|
| Filesystem | read / write / edit / grep / find / ls |
| Shell | bash (guarded) |
| HTTP | http (structured + logged) / bypass403 (variant enumeration) |
| Encoding | encode (base64/hex/url/html/rot13/unicode chaining) |
| Recon | nmap (rate-capped) / osint (4-source passive) |
| Injection | sqlmap (guarded) / jwt (decode/crack/forge) |
| Cloud | cloud (metadata / credentials / buckets) |
| Binary | binary (checksec / symbols / disasm / gadgets) |
| Weapon | cve (intel aggregator) / weapon (patch diff / PoC library) |
| Audit | audit (sink scanner / call-chain tracer) / hypothesis (hypothesis tree) |
| Reporting | finding (evidence-based) / loot |

## Cost

deepseek-chat: ~¥0.5–2 per mission (90%+ cache hit rate).

## Project Structure

```
src/hexhammer/
├── solver/          Agent loop (tool calls + redrive + compaction)
├── control/         Orchestration (two-phase + PassClock budget + crash recovery)
├── tools/           20 tools
├── run/             CLI (scan / chat / doctor / review)
├── experience.py    Experience library (distill → review → inject)
├── observer.py      Outer-loop observer (coverage map distillation)
├── playbooks.py     Domain knowledge assembly (6 playbooks + 7 skills)
└── eval/            Local A/B test suite

resources/
├── playbooks/       Domain handbooks (web/pentest/binary/cloud/evasion/exploit)
├── skills/          Methodology skills (waf-bypass/ssrf-chain/cve-repro/weapon-research)
└── experience/      Experience library (distilled from live ops, human-reviewed)
```

## ⚠️ Risk & Liability

**This project is for authorized security research and penetration testing only.**

- **You must have written authorization** to test any target
- Unauthorized penetration testing is a **criminal offense** in most jurisdictions
- Engine probes may trigger target-side defenses (IP bans / alerts / legal action)
- Reports may contain sensitive information — handle with care
- **The user assumes full legal responsibility.** Developers are not liable for misuse.

**Best practices:**
- Only use against assets you own or have explicit written permission to test
- Test in isolated environments (local labs / dedicated test segments)
- Keep `.env` API keys secure (already gitignored)
- Review engine output for false positives before submitting to stakeholders

## License

Apache-2.0
