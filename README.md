# Multi-Modal Garak

NVIDIA's `garak` extended into the visual/audio/video domain. Generates
adversarial **images, audio, and video** payloads, sends them to a
multimodal model alongside textual prompts, and scores responses with
canary-based leak detectors and refusal-language detectors.

## Probe families

| Family | What it does |
|---|---|
| `image_text_overlay` | Renders attacker text directly in the image (most common bypass) |
| `image_typographic` | Big colored word-art carrying jailbreaks |
| `image_steganographic` | Hides instructions in PNG `tEXt` chunks (and EXIF) |
| `image_visual_misdirection` | Innocent picture + low-contrast injection |
| `audio_metadata` | WAV with attacker text appended after audio data |
| `audio_synth` | Synthesized tones (incl. ultrasonic) |
| `video_frame_injection` | Multi-frame APNG with payload on every frame |
| `text_baseline` | Pure-text controls (compare cross-modal vs text-only) |

## Detectors

- `refusal` — refusal-language fingerprint
- `leak` — canary tokens (`PWNED`, `ACCESS-GRANTED-…`, `COMPROMISED`, `DAN`-with-confirmation)
- `leak_or_refusal` — tri-state verdict: `VULN_LEAK` / `SAFE_REFUSED` / `AMBIGUOUS`

## Install

```bash
git clone https://github.com/vinzabe/multimodal-garak.git
cd multimodal-garak
pip install -r requirements.txt
```

## Configure

```bash
export LLM_BASE_URL="https://your-llm-endpoint/v1"
export LLM_API_KEY="sk-..."
export LLM_VISION_MODEL="gpt-4o-mini"
```

## CLI

```bash
# Run every probe against the default vision model
python -m mmgarak.cli run -o report.html

# Restrict to specific families
python -m mmgarak.cli run --families image_text_overlay image_steganographic \
    --limit 5 -o subset.html

# JSON for CI
python -m mmgarak.cli run --format json -o report.json

# List probes
python -m mmgarak.cli list-probes
```

## How the asset hosting works
Most multimodal endpoints fetch images by URL. `mmgarak` ships an in-process
HTTP server (`asset_server.py`) that publishes generated assets on a random
port and hands the URL to the model. Stop the runner -> server stops.

For deployments where the model can't reach `127.0.0.1`, set
`--asset-host 0.0.0.0` and a fixed `--asset-port`. If your gateway/router
strips multimodal content blocks (some aggregator gateways do — including
the one used in the test fixtures), the framework reports `AMBIGUOUS`
(model couldn't see asset). Point at a real native multimodal endpoint
(e.g. Anthropic vision, Gemini Vision direct, GPT-4V) for full coverage.

## Test

```bash
python tests/test_mmgarak.py
```

11/11 tests pass.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability disclosure policy.

## License

MIT — see [LICENSE](./LICENSE).
