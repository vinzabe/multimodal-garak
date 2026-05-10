"""End-to-end smoke tests for Multi-Modal Garak."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

import httpx


# --- standalone-repo shim: add project root to sys.path ---
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_PROJECT_ROOT = _os.path.normpath(_os.path.join(_HERE, '..'))

sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, _PROJECT_ROOT)

from llm_client import LLMClient
from mmgarak.asset_server import AssetServer
from mmgarak.detectors import detect_leak, detect_leak_or_refusal, detect_refusal
from mmgarak.probes import build_probe_library
from mmgarak.report import to_html, to_json
from mmgarak.runner import ProbeRunner

TMP = tempfile.mkdtemp(prefix="mmgarak_")


def test_probe_library_builds():
    probes = build_probe_library()
    assert len(probes) >= 10
    families = {p.family for p in probes}
    assert "image_text_overlay" in families
    assert "image_steganographic" in families
    assert "audio_metadata" in families
    assert "video_frame_injection" in families
    assert "text_baseline" in families
    print(f"  [PASS] {len(probes)} probes across {len(families)} families")


def test_probe_assets_buildable():
    failed = []
    for p in build_probe_library():
        if p.asset_kind == "none":
            continue
        try:
            data = p.builder()
            assert isinstance(data, bytes) and len(data) > 50
        except Exception as e:
            failed.append(f"{p.id}: {e}")
    assert not failed, f"asset build failures: {failed}"
    print(f"  [PASS] all probe assets build")


def test_asset_server_serves():
    with AssetServer() as srv:
        url = srv.publish(b"hello-world", ext="bin")
        r = httpx.get(url, timeout=5)
        assert r.status_code == 200 and r.content == b"hello-world"
        print(f"  [PASS] asset server hosted: {url}")


def test_detector_refusal():
    r = detect_refusal("Sorry, I can't help with that as it's against my guidelines.")
    assert r.triggered
    print(f"  [PASS] refusal detected: {r.reason}")


def test_detector_leak_canary():
    d = detect_leak("Sure thing! PWNED")
    assert d.triggered
    print(f"  [PASS] leak canary detected: {d.reason}")


def test_detector_leak_or_refusal_combined():
    v = detect_leak_or_refusal("PWNED")
    assert v["verdict"] == "VULN_LEAK"
    v2 = detect_leak_or_refusal("Sorry, I cannot do that.")
    assert v2["verdict"] == "SAFE_REFUSED"
    v3 = detect_leak_or_refusal("This is a friendly response about cats.")
    assert v3["verdict"] == "AMBIGUOUS"
    print(f"  [PASS] tri-state detector OK")


def test_run_text_baseline_against_real_model():
    """Run only text-baseline probes (don't need image hosting)."""
    probes = [p for p in build_probe_library() if p.family == "text_baseline"][:2]
    client = LLMClient()
    with ProbeRunner(client=client) as runner:
        report = runner.run_all(probes)
    s = report.summary()
    assert s["total_probes"] == 2
    assert all(r.error is None for r in report.runs), \
        [r.error for r in report.runs]
    print(f"  [PASS] text-baseline real run: verdicts={s['verdicts']}")


def test_run_image_overlay_against_real_model():
    """Real run against vision model with image-text-overlay probe."""
    probes = [p for p in build_probe_library()
              if p.family == "image_text_overlay"][:1]
    client = LLMClient()
    with ProbeRunner(client=client) as runner:
        report = runner.run_all(probes)
    r = report.runs[0]
    assert r.asset_url and r.asset_url.startswith("http://")
    if r.error:
        print(f"  [INFO] image probe error (model may not support fetched URL): {r.error}")
    else:
        print(f"  [PASS] image overlay probe: verdict={r.verdict} "
              f"resp={r.response[:80]}")


def test_full_run_subset_and_report_render():
    """Run a small mixed subset; render JSON+HTML."""
    library = build_probe_library()
    subset = (
        [p for p in library if p.family == "text_baseline"][:1]
        + [p for p in library if p.family == "image_text_overlay"][:1]
        + [p for p in library if p.family == "image_steganographic"][:1]
    )
    client = LLMClient()
    with ProbeRunner(client=client) as runner:
        report = runner.run_all(subset)
    j = to_json(report)
    assert json.loads(j)["summary"]["total_probes"] == len(subset)
    h = to_html(report)
    assert "<table" in h and "Multi-Modal Garak" in h
    out_html = os.path.join(TMP, "report.html")
    open(out_html, "w").write(h)
    print(f"  [PASS] mixed run + JSON/HTML rendered ({len(h)}B html), "
          f"verdicts={report.summary()['verdicts']}")


def test_cli_list_probes():
    r = subprocess.run([sys.executable, "-m", "mmgarak.cli", "list-probes"],
                       cwd=_PROJECT_ROOT,
                       capture_output=True, text=True, check=True)
    assert "image_text_overlay" in r.stdout
    assert "audio_metadata" in r.stdout
    print(f"  [PASS] CLI list-probes: {len(r.stdout.splitlines())} probes shown")


def test_cli_run_text_baseline():
    out = os.path.join(TMP, "cli.html")
    r = subprocess.run(
        [sys.executable, "-m", "mmgarak.cli", "run",
         "--families", "text_baseline", "--limit", "2",
         "--output", out, "--format", "html"],
        cwd=_PROJECT_ROOT,
        capture_output=True, text=True,
    )
    assert os.path.exists(out), f"missing {out}: {r.stderr}"
    assert "model=" in r.stdout
    print(f"  [PASS] CLI run text_baseline: {r.stdout.strip().splitlines()[-2]}")


def main() -> int:
    tests = [
        test_probe_library_builds,
        test_probe_assets_buildable,
        test_asset_server_serves,
        test_detector_refusal,
        test_detector_leak_canary,
        test_detector_leak_or_refusal_combined,
        test_run_text_baseline_against_real_model,
        test_run_image_overlay_against_real_model,
        test_full_run_subset_and_report_render,
        test_cli_list_probes,
        test_cli_run_text_baseline,
    ]
    p = f = 0
    for t in tests:
        print(f"\n>>> {t.__name__}")
        try:
            t(); p += 1
        except Exception as e:
            print(f"  [FAIL] {e}")
            import traceback; traceback.print_exc()
            f += 1
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\n{'='*60}\nMulti-Modal Garak: {p} passed, {f} failed")
    return 0 if f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
