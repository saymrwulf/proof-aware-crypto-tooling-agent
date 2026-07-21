"""uikit - shared presentation primitives for the warden cockpit.

Pure string builders and the one stylesheet. No wallet imports, no I/O:
this module can be reasoned about (and tested) as text in, text out.
The cockpit's two laws live in walletui's docstring; every helper here
exists to serve them - provenance lines, loud failure panels, glossary
links, per-panel explainers.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

STYLE = """
 :root{--ink:#1c2430;--ink2:#5a6675;--line:#dde2e9;--ok:#1e7f4f;--okbg:#e2f2e9;
       --bad:#a3242c;--badbg:#fbe4e6;--warn:#a86a10;--warnbg:#fdf0da;
       --accent:#3b4d8f;--accentbg:#eef0f7;--bg:#f8f9fa}
 *{box-sizing:border-box}
 body{font-family:system-ui,sans-serif;max-width:62rem;margin:0 auto;
      padding:1.4rem 1.2rem 4rem;color:var(--ink);line-height:1.55;background:var(--bg)}
 h1{font-size:1.35rem;margin:.2rem 0 0}
 h2{font-size:1.05rem;margin:1.6rem 0 .5rem}
 h3{font-size:.95rem;margin:1rem 0 .3rem}
 code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#eef0f3;
      border-radius:4px;padding:.08rem .3rem;font-size:.88em}
 .sub{color:var(--ink2);font-size:.85rem;margin:.3rem 0 .6rem}
 .navrow{display:flex;gap:.5rem;flex-wrap:wrap;align-items:stretch;margin:.45rem 0}
 .navtag{font-size:.62rem;font-weight:700;letter-spacing:.08em;color:var(--ink2);
      align-self:center;min-width:6.2rem}
 .navrow a{color:var(--accent);text-decoration:none;border:1px solid var(--line);
      background:#fff;border-radius:6px;padding:.3rem .6rem;font-size:.82rem;
      display:flex;flex-direction:column;line-height:1.25;min-width:6.4rem}
 .navrow a.here{border-color:var(--accent);font-weight:600;background:var(--accentbg)}
 .navrow a .navsub{font-size:.65rem;color:var(--ink2);font-weight:400}
 .banner{background:var(--warnbg);border:1px solid var(--warn);color:var(--warn);
      border-radius:6px;padding:.45rem .8rem;font-size:.82rem;font-weight:600}
 .banner a{color:var(--warn)}
 .lead{font-size:.92rem;margin:.9rem 0 .2rem}
 .verdict{border-radius:8px;padding:.8rem 1.1rem;margin:.8rem 0;border:1px solid}
 .verdict strong{font-size:1.05rem;letter-spacing:.02em}
 .verdict p{margin:.3rem 0 0;font-size:.88rem;font-weight:400}
 .verdict.ok{background:var(--okbg);border-color:var(--ok);color:var(--ok)}
 .verdict.warn{background:var(--warnbg);border-color:var(--warn);color:var(--warn)}
 .verdict.bad{background:var(--badbg);border-color:var(--bad);color:var(--bad)}
 .panel{background:#fff;border:1px solid var(--line);border-radius:8px;
      padding:.9rem 1.1rem;margin:.7rem 0}
 .panel.bad{border-color:var(--bad);background:var(--badbg)}
 .prov{color:var(--ink2);font-size:.72rem;margin-top:.6rem;border-top:1px dashed var(--line);
      padding-top:.35rem}
 .pill{display:inline-block;border-radius:9px;padding:.06rem .55rem;font-size:.76rem;
      font-weight:700}
 .pill.ok{background:var(--okbg);color:var(--ok)}
 .pill.bad{background:var(--badbg);color:var(--bad)}
 .pill.warn{background:var(--warnbg);color:var(--warn)}
 a.help{display:inline-block;width:1.05rem;height:1.05rem;line-height:1.05rem;text-align:center;
      border-radius:50%;background:var(--accentbg);color:var(--accent);font-size:.72rem;
      font-weight:700;text-decoration:none;vertical-align:.15em}
 details.explain{margin-top:.55rem;font-size:.82rem}
 details.explain summary{cursor:pointer;color:var(--accent);font-weight:600;font-size:.78rem}
 details.explain .expl{color:var(--ink2);margin:.4rem 0 0;padding:.5rem .7rem;
      background:var(--accentbg);border-radius:6px}
 details.explain .expl ul{margin:.3rem 0;padding-left:1.1rem}
 details.explain .expl li{margin:.15rem 0}
 .plain{font-size:.88rem;margin:.3rem 0 .6rem}
 .empty{color:var(--ink2);font-size:.88rem;background:var(--accentbg);border-radius:6px;
      padding:.5rem .8rem}
 pre{overflow-x:auto}
 pre.cmd{background:#1c2430;color:#e8ecf2;border-radius:6px;padding:.55rem .8rem;
      font-size:.78rem;line-height:1.5;font-family:ui-monospace,Menlo,Consolas,monospace}
 .tablewrap{overflow-x:auto}
 table{border-collapse:collapse;width:100%;font-size:.88rem;background:#fff}
 td,th{border:1px solid var(--line);padding:.4rem .6rem;text-align:left;vertical-align:top}
 th{background:var(--accentbg)}
 ul.diag{margin:.4rem 0 0;padding-left:1.2rem}
 ul.diag li{font-size:.85rem;margin:.2rem 0}
 dl.gloss dt{font-weight:700;margin-top:.8rem}
 dl.gloss dd{margin:.15rem 0 0 0;font-size:.88rem;color:var(--ink)}
 textarea{width:100%;min-height:7.5rem;font-family:ui-monospace,monospace;font-size:.8rem;
      border:1px solid var(--line);border-radius:6px;padding:.5rem}
 button{background:var(--accent);color:#fff;border:0;border-radius:6px;
      padding:.5rem 1.1rem;font-size:.9rem;cursor:pointer}
 .btnlink{display:inline-block;background:var(--accent);color:#fff;border-radius:6px;
      padding:.45rem 1rem;font-size:.88rem;text-decoration:none}
 .muted{color:var(--ink2);font-size:.85rem}
 .mono{font-family:ui-monospace,monospace}
 .breakany{overflow-wrap:anywhere}
 /* bridge */
 .strip{display:flex;gap:.45rem;flex-wrap:wrap;margin:.8rem 0}
 .chip{border:1px solid var(--line);background:#fff;border-radius:8px;
      padding:.3rem .7rem;font-size:.82rem}
 .chip b{font-weight:700}
 .crew{display:grid;grid-template-columns:repeat(auto-fill,minmax(17rem,1fr));
      gap:.7rem;margin:.7rem 0}
 .stationcard{background:#fff;border:1px solid var(--line);border-radius:8px;
      padding:.8rem .95rem;border-left:4px solid var(--role,#3b4d8f);
      display:flex;flex-direction:column;gap:.35rem}
 .stationcard .q{color:var(--ink2);font-size:.82rem;font-style:italic}
 .stationcard .live{font-size:.8rem}
 .stationcard .take{margin-top:auto;font-size:.84rem;font-weight:600;
      color:var(--accent);text-decoration:none}
 .monogram{display:inline-block;min-width:1.9rem;height:1.9rem;line-height:1.9rem;
      text-align:center;border-radius:6px;font-weight:800;font-size:.8rem;
      background:var(--roletint,#eef0f7);color:var(--role,#3b4d8f)}
 .rolehead{display:flex;align-items:center;gap:.6rem;margin:.9rem 0 .2rem;
      padding:.7rem .9rem;background:#fff;border:1px solid var(--line);
      border-radius:8px;border-left:5px solid var(--role,#3b4d8f)}
 .rolehead h2{margin:0;font-size:1.15rem}
 .rolehead .q{color:var(--ink2);font-size:.85rem;font-style:italic}
 .duty{margin:.55rem 0 .9rem}
 .duty .why{font-size:.85rem;color:var(--ink2);margin:.15rem 0 .3rem}
 .never li{margin:.25rem 0;font-size:.88rem}
 .hand{display:grid;grid-template-columns:1fr 1fr;gap:.7rem}
 @media(max-width:40rem){.hand{grid-template-columns:1fr}}
 .hand .hcol{background:var(--accentbg);border-radius:6px;padding:.5rem .8rem;
      font-size:.86rem}
 .hand .hcol b{display:block;margin-bottom:.2rem;font-size:.78rem;
      letter-spacing:.05em}
"""


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def esc(value: Any) -> str:
    return html.escape(str(value))


def help_link(anchor: str) -> str:
    """A small ? that jumps to the glossary entry for a term."""
    return (f'<a class="help" href="/guide#{anchor}" '
            f'title="what does this mean? — explained in the guide">?</a>')


def explain(body: str) -> str:
    """The per-panel interpretation aid: always present, opt-in detail."""
    return (f'<details class="explain"><summary>How to read this panel</summary>'
            f'<div class="expl">{body}</div></details>')


def provenance(via: str) -> str:
    return (f'<div class="prov">recomputed {esc(now_utc())} via <code>{esc(via)}</code>'
            f' — nothing on this panel is cached or asserted.</div>')


def failed_panel(what: str, via: str, error: Exception) -> str:
    return (
        f'<div class="panel bad"><span class="pill bad">FAILED TO VERIFY</span> '
        f"<strong>{esc(what)}</strong> could not be recomputed: "
        f"<code>{esc(f'{type(error).__name__}: {error}')}</code>. "
        f"A cockpit that cannot verify shows red, never a stale green. "
        f"<span class='muted'>What to do: check that the wallet directory still exists and is "
        f"readable, then reload. If this persists, inspect from the command line with "
        f"<code>pacta wallet status</code>.</span>"
        f"{provenance(via)}</div>"
    )


def cmd_block(command: str) -> str:
    """A copy-paste command block: the no-AI drill in executable form."""
    return f'<pre class="cmd">{esc(command)}</pre>'
