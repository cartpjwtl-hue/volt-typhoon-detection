#!/usr/bin/env python3
"""Research monitor for the Volt Typhoon detection pack.

Queries the arXiv API for the pack's topic set, diffs the results against the arXiv IDs already
cited in docs/RESEARCH.md, and rewrites the machine-managed block between the RESEARCH-MONITOR
markers with:
  * ADDS    - candidate papers not yet listed (for human review / promotion into the curated part)
  * REMOVED - IDs cited in the curated sections that arXiv no longer resolves (withdrawn/replaced)

Stdlib only (urllib / xml.etree / re) so it runs on a bare GitHub Actions runner with no pip install.
Exit code 0 always; the calling workflow decides what to do with any diff.
"""

from __future__ import annotations

import datetime as _dt
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

RESEARCH_MD = Path(__file__).resolve().parent.parent / "docs" / "RESEARCH.md"
BEGIN = "<!-- RESEARCH-MONITOR:BEGIN -->"
END = "<!-- RESEARCH-MONITOR:END -->"

# Topic set that defines "relevant to this project". Keep these tight so the candidate list stays
# signal-rich; broaden deliberately, not accidentally.
QUERIES = [
    'all:"Volt Typhoon"',
    'all:"living off the land" AND cat:cs.CR',
    'all:"credential dumping" AND cat:cs.CR',
    'all:"LSASS" AND cat:cs.CR',
    'abs:"ATT&CK" AND abs:detection AND cat:cs.CR',
    'all:"provenance" AND all:"APT" AND cat:cs.CR',
    'all:"endpoint detection" AND all:"evasion" AND cat:cs.CR',
]
MAX_PER_QUERY = 15
ARXIV_ID_RE = re.compile(r"\b(\d{4}\.\d{4,5})(v\d+)?\b")
ATOM = "{http://www.w3.org/2005/Atom}"


def _fetch(query: str) -> bytes:
    url = "http://export.arxiv.org/api/query?" + urllib.parse.urlencode(
        {
            "search_query": query,
            "start": 0,
            "max_results": MAX_PER_QUERY,
            "sortBy": "submittedDate",
            "sortOrder": "descending",
        }
    )
    req = urllib.request.Request(url, headers={"User-Agent": "volt-typhoon-research-monitor/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (fixed arxiv host)
        return resp.read()


def _parse(feed: bytes) -> list[dict]:
    out = []
    root = ET.fromstring(feed)
    for entry in root.findall(f"{ATOM}entry"):
        raw_id = (entry.findtext(f"{ATOM}id") or "").strip()
        m = ARXIV_ID_RE.search(raw_id)
        if not m:
            continue
        out.append(
            {
                "id": m.group(1),
                "title": " ".join((entry.findtext(f"{ATOM}title") or "").split()),
                "published": (entry.findtext(f"{ATOM}published") or "")[:10],
            }
        )
    return out


def _arxiv_resolves(arxiv_id: str) -> bool:
    """True if arXiv still returns an entry for this id (withdrawn papers stop resolving)."""
    try:
        feed = _fetch(f"id_list:{arxiv_id}")
    except Exception:
        return True  # network hiccup -> do not falsely flag as removed
    return bool(_parse(feed))


def main() -> int:
    text = RESEARCH_MD.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        print(f"ERROR: markers not found in {RESEARCH_MD}", file=sys.stderr)
        return 0

    curated = text.split(BEGIN)[0]  # only the human-curated part counts as "already listed"
    listed_ids = {m.group(1) for m in ARXIV_ID_RE.finditer(curated)}

    # ----- discover candidates -----
    found: dict[str, dict] = {}
    for q in QUERIES:
        try:
            for paper in _parse(_fetch(q)):
                found.setdefault(paper["id"], paper)
        except Exception as exc:  # keep going; partial results are fine
            print(f"warn: query failed ({q}): {exc}", file=sys.stderr)
        time.sleep(3)  # be polite to the arXiv API

    candidates = sorted(
        (p for pid, p in found.items() if pid not in listed_ids),
        key=lambda p: p["published"],
        reverse=True,
    )

    # ----- check curated IDs still resolve -----
    removed = [cid for cid in sorted(listed_ids) if not _arxiv_resolves(cid)]

    # ----- render the managed block -----
    today = _dt.date.today().isoformat()
    lines = ["### Candidate papers (auto-discovered, pending review)", ""]
    if candidates:
        lines.append("| arXiv | Published | Title |")
        lines.append("|---|---|---|")
        for p in candidates[:40]:
            title = p["title"].replace("|", r"\|")
            lines.append(f"| [{p['id']}](https://arxiv.org/abs/{p['id']}) | {p['published']} | {title} |")
    else:
        lines.append("_No new candidates since the last run._")
    lines.append("")
    if removed:
        lines.append("### ⚠ Cited IDs that no longer resolve on arXiv (review — withdrawn/replaced?)")
        lines.append("")
        for rid in removed:
            lines.append(f"- `arXiv:{rid}`")
        lines.append("")
    lines.append(f"_Last run: {today} · {len(candidates)} candidate(s), {len(removed)} removal flag(s)._")

    block = f"{BEGIN}\n" + "\n".join(lines) + f"\n{END}"
    new_text = re.sub(
        re.escape(BEGIN) + r".*?" + re.escape(END),
        lambda _m: block,
        text,
        flags=re.DOTALL,
    )
    if new_text != text:
        RESEARCH_MD.write_text(new_text, encoding="utf-8")
        print(f"updated {RESEARCH_MD} ({len(candidates)} candidates, {len(removed)} removals)")
    else:
        print("no change")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
