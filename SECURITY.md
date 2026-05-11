# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **Multi-Modal Garak**,
please report it privately. Do **not** open a public GitHub issue.

**Email:** security@vinzabe.dev (or open a GitHub Security Advisory)

Please include:
- A clear description of the issue
- Steps to reproduce (PoC preferred)
- The version / commit SHA you tested against
- Any suggested mitigation

We aim to acknowledge new reports within **72 hours** and to publish a
fix or mitigation within **30 days** for high-severity issues.

## Scope

In scope:
- AssetServer path traversal / SSRF
- Asset URLs leaking outside the configured `--asset-host`
- Detector bypass (model leaks a canary but `leak` detector misses it)
- Probe payloads escaping the test environment
- HTML / JSON report XSS
- Auth issues on AssetServer

Out of scope:
- Probes are designed to attack model APIs by design — that is the
  intent
- Issues requiring root on the host running the runner
- Vendor model behaviors (file an issue with the model vendor; we
  publish observations only)

## Critical operational warnings

This tool **generates and serves attack payloads** (jailbreak text
embedded in images, audio with hidden instructions, etc.) and points
LLM endpoints at them. Misuse can:

- Trigger your model vendor's abuse / safety review systems
- Violate the vendor's Acceptable Use Policy
- Get your API key suspended

**Before running:**
1. Read your vendor's Red-Teaming / Safety Testing policy
2. Use a dedicated test account / sandboxed API key — never your prod key
3. Rate-limit probes (`--limit`) on first runs
4. Do not point this at third-party models without permission

The default `LLM_BASE_URL` is intentionally **not set** — you must
configure it explicitly.

## Threat model

This is a **defensive red-teaming tool**. We assume:
- The operator has authorization to test the target endpoint
- The AssetServer runs on a trusted network segment
- The operator handles probe outputs as TLP:AMBER (may contain
  jailbroken model output)

## Hardening checklist for production deployments

- [ ] Bind AssetServer to `127.0.0.1` unless the model truly needs
      remote fetch — most model APIs accept inline base64 (`--inline-base64`)
- [ ] Use `--asset-port` with a fixed port behind a reverse proxy
      with auth, not direct internet exposure
- [ ] Rotate API keys after each campaign
- [ ] Store reports as TLP:AMBER (they contain successful jailbreaks)
- [ ] Run probes in a CI environment isolated from production data
- [ ] Subscribe to your model vendor's abuse-detection notifications
      and respond promptly

## Supply chain

- All Python deps are pinned via `requirements.txt`
- Image generation uses Pillow; audio uses stdlib `wave`; video uses
  Pillow's APNG support — minimal native deps
- The shared `llm_client.py` is vendored

## Contact

Responsible disclosure: **g@abejar.net**
