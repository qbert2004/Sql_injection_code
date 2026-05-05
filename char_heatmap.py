"""
Character-Level Attribution Heatmap — SQL Injection Detector
=============================================================
Uses occlusion-based attribution: for each character position in the query,
we mask it and measure how much the injection score changes.

High positive delta  → this character CAUSES the injection detection.
High negative delta  → this character PREVENTS detection (makes it look safer).

This is fundamentally different from SHAP (tree-based decomposition) or LIME
(linear surrogate) — it operates directly on the raw character sequence and
shows WHERE in the string the danger lives.

Produces:
  heatmap_report.html            — interactive HTML with coloured SQL text
  heatmap_<name>.png             — matplotlib heatmap per example

Usage:
    python char_heatmap.py
    python char_heatmap.py --query "' OR 1=1--"
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

# ── Test queries ───────────────────────────────────────────────────────────────
EXAMPLES = [
    ("Boolean injection",       "' OR '1'='1' --"),
    ("UNION exfiltration",      "' UNION SELECT username, password FROM users--"),
    ("Time-based blind",        "1'; WAITFOR DELAY '0:0:5'--"),
    ("Admin comment truncation","admin'--"),
    ("Stacked query DROP",      "1'; DROP TABLE users;--"),
    ("Encoded obfuscation",     "' OR 0x313d31--"),
    ("Safe login",              "alice@example.com"),
    ("Safe search",             "laptop stand buy online"),
    ("Safe with apostrophe",    "O'Brien"),
    ("Complex SELECT",          "SELECT * FROM orders WHERE id=1 AND status='shipped'"),
]

MASK_CHAR = " "   # replace character with space for occlusion


def _load_detector():
    """Import and initialise SQLInjectionEnsemble."""
    try:
        from sql_injection_detector import SQLInjectionEnsemble
        return SQLInjectionEnsemble()
    except Exception as e:
        raise RuntimeError(f"Could not load detector: {e}")


def _score(detector, text: str) -> float:
    """Return raw injection probability (0–1)."""
    try:
        r = detector.detect(text)
        # confidence is always 0-1 (model probability)
        confidence = r.get("confidence", 0.0)
        if confidence and float(confidence) > 0:
            return float(confidence)
        # fallback: score field; normalise if on 0-100 scale
        score = float(r.get("score", 0.0))
        return score if score <= 1.0 else score / 100.0
    except Exception:
        return 0.0


def occlusion_attribution(detector, query: str, window: int = 1) -> tuple[np.ndarray, float]:
    """
    For each character position, replace a window of `window` chars with MASK_CHAR
    and record how the injection score changes from the baseline.

    Returns:
        deltas   — shape (len(query),), positive = this position raises the score
        baseline — unmasked score
    """
    baseline = _score(detector, query)
    n = len(query)
    deltas = np.zeros(n)

    for i in range(n):
        # mask character i (and up to window-1 neighbours)
        lo = max(0, i - window // 2)
        hi = min(n, lo + window)
        masked = query[:lo] + MASK_CHAR * (hi - lo) + query[hi:]
        masked_score = _score(detector, masked)
        deltas[i] = baseline - masked_score   # positive: removing this char LOWERS score → it was dangerous

    return deltas, baseline


def plot_heatmap(query: str, deltas: np.ndarray, baseline: float,
                 title: str, out_path: Path):
    """
    Horizontal bar showing each character coloured by its attribution.
    Red  = dangerous character (high positive delta)
    Green = safe/anchoring character (high negative delta)
    White = neutral
    """
    n = len(query)
    max_abs = max(np.abs(deltas).max(), 1e-6)
    norm_deltas = deltas / max_abs           # normalise to [-1, 1]

    # colour map: green → white → red
    cmap = mcolors.LinearSegmentedColormap.from_list(
        "sqli_heat", ["#27ae60", "#ffffff", "#e74c3c"]
    )

    fig_width = max(10, n * 0.22 + 2)
    fig, axes = plt.subplots(2, 1, figsize=(fig_width, 3.5),
                             gridspec_kw={"height_ratios": [1, 0.35]})

    ax = axes[0]
    # Draw coloured rectangles for each character
    for i, (ch, nd) in enumerate(zip(query, norm_deltas)):
        color = cmap((nd + 1) / 2)
        rect = plt.Rectangle([i, 0], 1, 1, color=color, ec="white", lw=0.5)
        ax.add_patch(rect)
        text_color = "black" if abs(nd) < 0.6 else "white"
        ax.text(i + 0.5, 0.5, ch if ch != " " else "·",
                ha="center", va="center", fontsize=max(7, min(11, 220 // n)),
                color=text_color, fontfamily="monospace")

    ax.set_xlim(0, n)
    ax.set_ylim(0, 1)
    ax.axis("off")
    injection_pct = baseline * 100
    verdict = "INJECTION" if injection_pct > 50 else "SAFE"
    v_color = "#e74c3c" if verdict == "INJECTION" else "#27ae60"
    ax.set_title(
        f'{title}\n'
        f'Baseline score: {injection_pct:.1f}%   Verdict: {verdict}\n'
        f'Character attribution — red = raises injection score, green = lowers it',
        fontsize=9, color="#2c3e50",
    )

    # colour bar (delta axis)
    ax2 = axes[1]
    gradient = np.linspace(-1, 1, 256).reshape(1, -1)
    ax2.imshow(gradient, aspect="auto", cmap=cmap, extent=[-1, 1, 0, 0.4])
    ax2.set_xlim(-1, 1)
    ax2.set_ylim(0, 0.4)
    ax2.set_yticks([])
    ax2.set_xticks([-1, -0.5, 0, 0.5, 1])
    ax2.set_xticklabels(["Safe\n(–1)", "–0.5", "Neutral\n(0)", "+0.5", "Danger\n(+1)"],
                        fontsize=8)
    ax2.set_title("Attribution scale", fontsize=8, pad=2)

    fig.tight_layout(pad=0.5)
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [saved] {out_path.name}  score={injection_pct:.1f}%")


def _char_html(ch: str, nd: float) -> str:
    """Return an HTML <span> for one character with background colour."""
    # nd in [-1, 1]; map to RGB
    if nd > 0:      # danger
        r, g, b = 231, 76,  60
        alpha = nd * 0.85
    elif nd < 0:    # safe
        r, g, b = 39, 174, 96
        alpha = abs(nd) * 0.7
    else:
        r, g, b, alpha = 200, 200, 200, 0.15
    bg = f"rgba({r},{g},{b},{alpha:.2f})"
    display = ch if ch not in (" ", "\t") else "&nbsp;"
    tooltip = f"Δ={nd:+.3f}"
    return (
        f'<span title="{tooltip}" '
        f'style="background:{bg};padding:2px 1px;border-radius:2px;'
        f'font-family:monospace;font-size:14px;white-space:pre">{display}</span>'
    )


def build_html_report(records: list[dict]) -> str:
    """Build a self-contained HTML report with all heatmaps."""
    rows = ""
    for r in records:
        query   = r["query"]
        deltas  = r["deltas"]
        baseline = r["baseline"]
        max_abs = max(np.abs(deltas).max(), 1e-6)
        norm    = deltas / max_abs
        verdict = "INJECTION" if baseline > 0.5 else "SAFE"
        v_color = "#e74c3c" if verdict == "INJECTION" else "#27ae60"

        char_spans = "".join(_char_html(ch, nd) for ch, nd in zip(query, norm))

        rows += f"""
        <tr>
          <td style="padding:10px;vertical-align:top;font-size:13px;white-space:nowrap">
            {r['name']}
          </td>
          <td style="padding:10px;vertical-align:top;
                     font-weight:700;color:{v_color};font-size:14px">
            {verdict}
          </td>
          <td style="padding:10px;vertical-align:top;font-size:13px">
            {baseline*100:.1f}%
          </td>
          <td style="padding:10px">
            <div style="line-height:2.2;word-break:break-all">{char_spans}</div>
          </td>
        </tr>
        """

    legend = "".join(
        f'<span style="background:rgba({r},{g},{b},0.7);padding:3px 8px;'
        f'border-radius:3px;font-size:12px;margin-right:8px">{label}</span>'
        for (r, g, b), label in [
            ((231, 76, 60),  "Danger — raises injection score"),
            ((200, 200, 200), "Neutral"),
            ((39, 174, 96),  "Anchor — lowers injection score"),
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Character Attribution Heatmap — SQL Injection</title>
<style>
  body  {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
           background:#f4f6f9; margin:0; padding:24px; }}
  h1    {{ color:#2c3e50; border-bottom:3px solid #e74c3c; padding-bottom:10px; }}
  .sub  {{ color:#7f8c8d; margin-top:-10px; margin-bottom:24px; font-size:14px; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
           box-shadow:0 2px 12px rgba(0,0,0,.08); border-radius:8px;
           overflow:hidden; }}
  th    {{ background:#2c3e50; color:#fff; padding:12px; text-align:left;
           font-size:13px; }}
  tr:hover td {{ background:rgba(231,76,60,.04)!important; }}
  .legend {{ margin-top:20px; }}
</style>
</head>
<body>
<h1>Character-Level Attribution Heatmap — SQL Injection Detector</h1>
<p class="sub">
  Occlusion-based attribution: each character is masked one-by-one and the
  change in injection score is measured. Red = this character raises the danger
  score (remove it → safer). Green = this character actually anchors safety.
  Hover over a character to see its exact Δ attribution value.
</p>
<table>
  <thead>
    <tr>
      <th>Description</th>
      <th>Verdict</th>
      <th>Score</th>
      <th>Character Attribution (hover for Δ values)</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
<div class="legend">{legend}</div>
</body>
</html>
"""


def run(custom_query: str | None = None):
    print("[heatmap] Loading detector …")
    detector = _load_detector()

    out_dir = ROOT / "models"
    out_dir.mkdir(exist_ok=True)

    examples = EXAMPLES.copy()
    if custom_query:
        examples = [("Custom query", custom_query)] + examples

    records = []
    print(f"[heatmap] Computing character attributions for {len(examples)} queries …\n")

    for k, (name, query) in enumerate(examples):
        print(f"  [{k+1}/{len(examples)}] {name!r} …", end=" ", flush=True)
        deltas, baseline = occlusion_attribution(detector, query, window=1)

        out_png = out_dir / f"heatmap_{k+1:02d}.png"
        plot_heatmap(query, deltas, baseline, name, out_png)

        records.append({
            "name":     name,
            "query":    query,
            "deltas":   deltas,
            "baseline": baseline,
        })

    html = build_html_report(records)
    out_html = ROOT / "heatmap_report.html"
    out_html.write_text(html, encoding="utf-8")
    print(f"\n[saved] {out_html}")
    print("[done]  Open heatmap_report.html in a browser to explore.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", default=None, help="Custom SQL query to analyse")
    args = parser.parse_args()
    run(args.query)
