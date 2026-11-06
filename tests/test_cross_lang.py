"""Cross-language test: proofs built by the browser prover (frontend/zkp.js, run under Node)
must verify with the Python verifier, byte for byte."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from zkauction.crypto.bid_proof import verify_bid
from zkauction.crypto.params import H, to_hex
from zkauction.crypto.reveal_proof import verify_reveal
from zkauction.crypto.transcript import hash_int

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")


@pytest.fixture(scope="module")
def js_output():
    if NODE is None:
        pytest.skip("node not installed")
    out = subprocess.run([NODE, str(ROOT / "scripts" / "js_prove.mjs"), "auc-js", "640"],
                         capture_output=True, text=True, timeout=60, cwd=ROOT)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_js_parameters_and_transcript_match(js_output):
    assert js_output["h"] == to_hex(H)
    assert int(js_output["vector"], 16) == hash_int("abc", 5, "")


def test_js_bid_verifies_in_python(js_output):
    req = js_output["request"]
    C, pk = verify_bid("auc-js", req["bidder"], req["commitment"], req["proof"])
    rv = js_output["reveal"]
    verify_reveal("auc-js", req["bidder"], C, pk, rv["value"], rv["randomness"], rv["proof"])
    assert js_output["opening_ok"] is True
