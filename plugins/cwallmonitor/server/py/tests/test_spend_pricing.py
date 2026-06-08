"""Cross-runtime pricing parity for /spend, against compat/vectors/spend_pricing.json.

Each runtime builds a PriceTable from the vector's `prices`, then for every
case asserts the per-model wire USD and the firmware cents match. The
half-cent case also pins _round2() to half-up — Python's built-in round() is
banker's rounding and would diverge from the Go/JS runtimes."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from cwm_mcp.pricing import PriceTable, Rate
from cwm_mcp.spend import Bundle, _round2


def _find_compat(rel: str) -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "compat" / rel
        if cand.exists():
            return cand
    pytest.skip(f"compat/{rel} not available (standalone checkout)", allow_module_level=True)


COMPAT = _find_compat("vectors/spend_pricing.json")


def test_spend_pricing_vectors():
    data = json.loads(COMPAT.read_text())
    assert data["cases"], "compat spend cases empty"

    rates = {
        k: Rate(v["input"], v["output"], v["cache_read"], v["cache_creation"])
        for k, v in data["prices"].items()
    }
    table = PriceTable(rates, "fallback", False)

    for c in data["cases"]:
        tok = c["tokens"]
        b = Bundle(
            input=tok["input_tokens"],
            output=tok["output_tokens"],
            cache_read=tok["cache_read_tokens"],
            cache_creation=tok["cache_creation_tokens"],
        )
        wire_usd = _round2(table.cost_for(c["model"], b))
        cents = math.floor(wire_usd * 100 + 0.5)
        assert wire_usd == c["expected_usd"], f'usd for {c["note"]} ({c["model"]})'
        assert cents == c["expected_cents"], f'cents for {c["note"]} ({c["model"]})'
