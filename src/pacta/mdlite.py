"""mdlite - a deliberately small Markdown renderer (stdlib only).

Renders exactly the subset the lab manual uses: ATX headings (# ## ###),
paragraphs, **bold**, *italic*, `code`, fenced code blocks, unordered and
ordered lists, blockquotes, tables, horizontal rules, and [links](...).
Text is HTML-escaped first; code spans are protected from inline rules.

Why not a library: the cockpit is standard-library-only by law, and a
small renderer whose whole grammar fits on one screen is auditable in a
way a dependency is not. The test suite renders the real manual through
this and asserts no raw Markdown artifacts leak into the HTML.
"""
from __future__ import annotations

import html
import re


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "section"


def _inline(text: str) -> str:
    """Inline rules over an already HTML-escaped string.

    Code spans are stashed as placeholder tokens first, so bold/italic/link
    rules can span across them (e.g. **never edits `policy.json` alone**)
    while code content itself stays untouched by those rules."""
    codes: list[str] = []

    def stash(m: re.Match[str]) -> str:
        codes.append(m.group(1))
        return f"\x00{len(codes) - 1}\x00"

    text = re.sub(r"`([^`]+)`", stash, text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<![*\w])\*([^*\n]+)\*(?![*\w])", r"<em>\1</em>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', text)
    for idx, code in enumerate(codes):
        text = text.replace(f"\x00{idx}\x00", f"<code>{code}</code>")
    return text


def render(md: str) -> tuple[str, list[tuple[int, str, str]]]:
    """Render markdown -> (html, toc) where toc = [(level, text, anchor)]."""
    lines = md.splitlines()
    out: list[str] = []
    toc: list[tuple[int, str, str]] = []
    seen_slugs: dict[str, int] = {}
    para: list[str] = []
    i = 0

    def flush_para() -> None:
        if para:
            out.append(f"<p>{_inline(html.escape(' '.join(para)))}</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # fenced code block
        if stripped.startswith("```"):
            flush_para()
            i += 1
            code: list[str] = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i])
                i += 1
            i += 1  # closing fence
            out.append(f"<pre class='cmd'>{html.escape(chr(10).join(code))}</pre>")
            continue

        # heading
        m = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if m:
            flush_para()
            level = len(m.group(1))
            text = m.group(2).strip()
            base = _slug(re.sub(r"[*`\[\]()]", "", text))
            n = seen_slugs.get(base, 0)
            seen_slugs[base] = n + 1
            anchor = base if n == 0 else f"{base}-{n}"
            if level in (2, 3):
                toc.append((level, re.sub(r"[*`]", "", text), anchor))
            out.append(f"<h{level} id='{anchor}'>{_inline(html.escape(text))}</h{level}>")
            i += 1
            continue

        # horizontal rule
        if re.match(r"^-{3,}$", stripped):
            flush_para()
            out.append("<hr>")
            i += 1
            continue

        # blockquote
        if stripped.startswith(">"):
            flush_para()
            quote: list[str] = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip().lstrip(">").strip())
                i += 1
            out.append("<blockquote><p>"
                       + _inline(html.escape(" ".join(q for q in quote if q)))
                       + "</p></blockquote>")
            continue

        # table
        if stripped.startswith("|") and i + 1 < len(lines) and \
                re.match(r"^\|[\s:|-]+\|$", lines[i + 1].strip()):
            flush_para()
            def cells(row: str) -> list[str]:
                return [c.strip() for c in row.strip().strip("|").split("|")]
            head = cells(stripped)
            i += 2
            rows: list[list[str]] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(cells(lines[i].strip()))
                i += 1
            thead = "".join(f"<th>{_inline(html.escape(c))}</th>" for c in head)
            body = "".join(
                "<tr>" + "".join(f"<td>{_inline(html.escape(c))}</td>" for c in r)
                + "</tr>" for r in rows)
            out.append(f"<div class='tablewrap'><table><tr>{thead}</tr>{body}</table></div>")
            continue

        # lists (one level)
        m_ul = re.match(r"^[-*]\s+(.*)$", stripped)
        m_ol = re.match(r"^\d+[.)]\s+(.*)$", stripped)
        if m_ul or m_ol:
            flush_para()
            tag = "ul" if m_ul else "ol"
            items: list[str] = []
            while i < len(lines):
                s = lines[i].strip()
                m2 = re.match(r"^[-*]\s+(.*)$", s) if tag == "ul" else \
                    re.match(r"^\d+[.)]\s+(.*)$", s)
                if m2:
                    items.append(m2.group(1))
                    i += 1
                elif s and not re.match(r"^([-*]|\d+[.)])\s", s) and \
                        lines[i].startswith(("  ", "\t")) and items:
                    items[-1] += " " + s  # continuation line
                    i += 1
                else:
                    break
            lis = "".join(f"<li>{_inline(html.escape(item))}</li>" for item in items)
            out.append(f"<{tag}>{lis}</{tag}>")
            continue

        # blank line ends a paragraph
        if not stripped:
            flush_para()
            i += 1
            continue

        para.append(stripped)
        i += 1

    flush_para()
    return "".join(out), toc
