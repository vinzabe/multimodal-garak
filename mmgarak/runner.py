"""Probe runner: builds assets, hosts them, sends multimodal prompts, scores."""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any


# --- standalone-repo shim: add project root to sys.path ---
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_PROJECT_ROOT = _os.path.normpath(_os.path.join(_HERE, '..'))

sys.path.insert(0, _PROJECT_ROOT)

from llm_client import DEFAULT_VISION_MODEL, LLMClient

from .asset_server import AssetServer
from .detectors import detect_leak_or_refusal
from .probes import Probe


@dataclass
class ProbeRun:
    probe_id: str
    family: str
    asset_kind: str
    asset_url: str | None
    prompt_text: str
    response: str
    verdict: str
    leak: dict
    refusal: dict
    latency_ms: int
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "probe_id": self.probe_id,
            "family": self.family,
            "asset_kind": self.asset_kind,
            "asset_url": self.asset_url,
            "prompt_text": self.prompt_text,
            "response": self.response,
            "verdict": self.verdict,
            "leak": self.leak,
            "refusal": self.refusal,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


@dataclass
class RunReport:
    model: str
    started_at: float
    finished_at: float
    runs: list[ProbeRun]

    def summary(self) -> dict:
        by_family: dict[str, dict[str, int]] = {}
        verdict_counts: dict[str, int] = {}
        for r in self.runs:
            verdict_counts[r.verdict] = verdict_counts.get(r.verdict, 0) + 1
            f = by_family.setdefault(r.family, {})
            f[r.verdict] = f.get(r.verdict, 0) + 1
        total = len(self.runs)
        leaks = verdict_counts.get("VULN_LEAK", 0)
        return {
            "model": self.model,
            "duration_s": round(self.finished_at - self.started_at, 2),
            "total_probes": total,
            "verdicts": verdict_counts,
            "vulnerability_rate": round(leaks / max(total, 1), 3),
            "by_family": by_family,
        }

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary(),
            "runs": [r.to_dict() for r in self.runs],
        }


class ProbeRunner:
    def __init__(self, client: LLMClient | None = None,
                 model: str | None = None,
                 asset_server: AssetServer | None = None,
                 inline_base64: bool = False) -> None:
        self.client = client or LLMClient()
        self.model = model or os.environ.get("LLM_VISION_MODEL", DEFAULT_VISION_MODEL)
        self.asset_server = asset_server
        self._owns_server = asset_server is None
        # If True, inline image data as data: URIs instead of using HTTP host.
        self.inline_base64 = inline_base64

    def __enter__(self):
        if self.asset_server is None:
            self.asset_server = AssetServer()
            self.asset_server.start()
        return self

    def __exit__(self, *exc):
        if self._owns_server and self.asset_server is not None:
            self.asset_server.stop()

    def _build_messages(self, probe: Probe, asset_url: str | None) -> list[dict]:
        if probe.asset_kind == "none" or asset_url is None:
            return [{"role": "user", "content": probe.prompt_text}]
        # OpenAI-style multimodal content
        content: list[dict] = [{"type": "text", "text": probe.prompt_text}]
        if probe.asset_kind == "image" or probe.asset_kind == "video":
            content.append({"type": "image_url", "image_url": {"url": asset_url}})
        elif probe.asset_kind == "audio":
            # Many endpoints accept audio_url; we use it as a hint and
            # also reference the URL in the prompt text so the model knows.
            content.append({"type": "input_audio",
                            "input_audio": {"data": asset_url, "format": "wav"}})
        return [{"role": "user", "content": content}]

    def run_one(self, probe: Probe) -> ProbeRun:
        import base64
        t0 = time.time()
        asset_url = None
        err = None
        try:
            if probe.asset_kind != "none":
                data = probe.builder()
                if self.inline_base64 and probe.asset_kind == "image":
                    mime = "image/png" if probe.asset_ext == "png" else \
                           f"image/{probe.asset_ext}"
                    asset_url = (f"data:{mime};base64,"
                                 f"{base64.b64encode(data).decode()}")
                else:
                    assert self.asset_server is not None
                    asset_url = self.asset_server.publish(data,
                                                          ext=probe.asset_ext)
            msgs = self._build_messages(probe, asset_url)
            resp = self.client.chat(msgs, model=self.model, max_tokens=300,
                                    temperature=0.0)
            text = resp.content
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            text = ""
        verdict_d = detect_leak_or_refusal(text)
        return ProbeRun(
            probe_id=probe.id, family=probe.family,
            asset_kind=probe.asset_kind, asset_url=asset_url,
            prompt_text=probe.prompt_text, response=text,
            verdict=verdict_d["verdict"],
            leak=verdict_d["leak"], refusal=verdict_d["refusal"],
            latency_ms=int((time.time() - t0) * 1000),
            error=err,
        )

    def run_all(self, probes: list[Probe]) -> RunReport:
        started = time.time()
        runs: list[ProbeRun] = []
        for p in probes:
            runs.append(self.run_one(p))
        return RunReport(model=self.model,
                         started_at=started, finished_at=time.time(),
                         runs=runs)
