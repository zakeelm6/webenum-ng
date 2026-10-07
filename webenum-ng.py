#!/usr/bin/env python3
"""
webenum-ng : l'equivalent web de enum4linux-ng.

Un seul orchestrateur qui enchaine les outils web (fingerprint ->
decouverte de contenu -> scan de vulns -> outils specifiques au CMS),
en parallele, s'adapte a ce qui est installe, puis ecrit un rapport
Markdown + un resume console.

Stdlib uniquement. Usage:
    ./webenum-ng.py http://10.129.44.80
    ./webenum-ng.py 10.10.10.10 -w big.txt -t 80 --full
    ./webenum-ng.py target --only fingerprint,content --dry-run

Tout est passif-ish par defaut (enum). N'utilise que sur des cibles
que tu es autorise a tester (labs, CTF, missions).
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------- couleurs
class C:
    on = sys.stdout.isatty()
    R = "\033[31m" if on else ""
    G = "\033[32m" if on else ""
    Y = "\033[33m" if on else ""
    B = "\033[34m" if on else ""
    M = "\033[35m" if on else ""
    CY = "\033[36m" if on else ""
    GR = "\033[90m" if on else ""
    BOLD = "\033[1m" if on else ""
    X = "\033[0m" if on else ""


def log(msg: str) -> None:
    print(f"{C.CY}[*]{C.X} {msg}")


def ok(msg: str) -> None:
    print(f"{C.G}[+]{C.X} {msg}")


def warn(msg: str) -> None:
    print(f"{C.Y}[!]{C.X} {msg}")


def err(msg: str) -> None:
    print(f"{C.R}[-]{C.X} {msg}")


DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]


def pick_wordlist(explicit: str | None) -> str | None:
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        # nom court -> cherche dans seclists web-content
        cand = Path("/usr/share/seclists/Discovery/Web-Content") / explicit
        if cand.is_file():
            return str(cand)
        warn(f"wordlist introuvable: {explicit}, fallback sur les defauts")
    for w in DEFAULT_WORDLISTS:
        if Path(w).is_file():
            return w
    return None


# ---------------------------------------------------------------- cible
@dataclass
class Target:
    raw: str
    url: str = ""
    scheme: str = ""
    host: str = ""
    port: int = 0

    def normalize(self) -> None:
        raw = self.raw.strip()
        if "://" not in raw:
            raw = "http://" + raw
        u = urlparse(raw)
        self.scheme = u.scheme
        self.host = u.hostname or ""
        self.port = u.port or (443 if u.scheme == "https" else 80)
        self.url = f"{u.scheme}://{u.netloc}"

    def probe(self) -> None:
        """Trouve le schema/port vivant si l'utilisateur n'a pas precise."""
        if "://" in self.raw:  # l'utilisateur a ete explicite, on respecte
            self.url = self.raw.rstrip("/")
            return
        for scheme, port in (("https", 443), ("http", 80)):
            test = f"{scheme}://{self.host}:{port}"
            rc = subprocess.run(
                ["curl", "-skL", "-o", "/dev/null", "-m", "8",
                 "-w", "%{http_code}", test],
                capture_output=True, text=True,
            )
            code = rc.stdout.strip()
            if code and code != "000":
                self.scheme, self.port = scheme, port
                self.url = test
                ok(f"vivant: {test} (HTTP {code})")
                return
        warn("aucun port web standard ne repond (80/443), on garde http://")
        self.url = f"http://{self.host}"


# ---------------------------------------------------------------- outils
@dataclass
class Tool:
    name: str
    bin: str
    category: str
    build: object  # ctx -> list[str]  (argv)
    highlights: object = None  # str -> list[str]
    applies: object = None  # ctx -> bool
    timeout: int = 1800


def grep_lines(patterns: list[str], text: str, limit: int = 25) -> list[str]:
    out, seen = [], set()
    rx = [re.compile(p, re.I) for p in patterns]
    for line in text.splitlines():
        s = line.strip()
        if not s or s in seen:
            continue
        if any(r.search(s) for r in rx):
            out.append(s)
            seen.add(s)
            if len(out) >= limit:
                break
    return out


def extra_headers(ctx: dict) -> list[str]:
    """Headers HTTP additionnels (auth basic + cookie de session)."""
    hs = []
    if ctx.get("basic_b64"):
        hs.append(f"Authorization: Basic {ctx['basic_b64']}")
    if ctx.get("cookie"):
        hs.append(f"Cookie: {ctx['cookie']}")
    return hs


def h_flags(ctx: dict) -> list[str]:
    """Flags -H "k: v" pour les outils qui parlent ce dialecte (ffuf/ferox/nuclei...)."""
    out: list[str] = []
    for h in extra_headers(ctx):
        out += ["-H", h]
    return out


def build_registry() -> list[Tool]:
    return [
        Tool(
            "whatweb", "whatweb", "fingerprint",
            build=lambda ctx: ["whatweb", "-a", "3", "--color=never", ctx["url"]],
            highlights=lambda t: grep_lines([r"\[\d{3}", r"WordPress", r"Joomla",
                                             r"Drupal", r"Apache", r"nginx",
                                             r"PHP", r"Server"], t, 15),
        ),
        Tool(
            "httpx", "httpx", "fingerprint",
            applies=lambda ctx: is_pd_httpx(),
            build=lambda ctx: ["httpx", "-u", ctx["url"], "-title", "-tech-detect",
                               "-status-code", "-server", "-no-color", "-silent"]
                              + h_flags(ctx),
            highlights=lambda t: t.strip().splitlines()[:10],
        ),
        Tool(
            "nmap-http", "nmap", "fingerprint",
            build=lambda ctx: ["nmap", "-Pn", "-sV", "--script",
                               "http-enum,http-headers,http-title",
                               "-p", str(ctx["port"]), ctx["host"]],
            highlights=lambda t: grep_lines([r"^\|", r"open", r"http-"], t, 30),
            timeout=900,
        ),
        Tool(
            "feroxbuster", "feroxbuster", "content",
            applies=lambda ctx: bool(ctx["wordlist"]),
            build=lambda ctx: ["feroxbuster", "-u", ctx["url"], "-w", ctx["wordlist"],
                               "-t", str(ctx["threads"]), "-q", "--no-state", "-k",
                               "-o", ctx["raw"]]
                              + (["-d", "1"] if ctx["fast"] else ["-d", "2"])
                              + h_flags(ctx),
            highlights=lambda t: grep_lines([r"^\s*\d{3}\s"], t, 40),
        ),
        Tool(
            "ffuf", "ffuf", "content",
            applies=lambda ctx: bool(ctx["wordlist"]) and not shutil.which("feroxbuster"),
            build=lambda ctx: ["ffuf", "-u", f"{ctx['url']}/FUZZ", "-w", ctx["wordlist"],
                               "-t", str(ctx["threads"]), "-mc",
                               "200,204,301,302,307,401,403,405", "-s"]
                              + h_flags(ctx),
            highlights=lambda t: t.strip().splitlines()[:40],
        ),
        Tool(
            "nuclei", "nuclei", "vuln",
            build=lambda ctx: ["nuclei", "-u", ctx["url"], "-nc", "-silent",
                               "-duc", "-ni", "-timeout", "10", "-retries", "1",
                               "-severity",
                               "low,medium,high,critical" if not ctx["fast"]
                               else "high,critical"]
                              + (["-tags", ctx["nuclei_tags"]]
                                 if ctx.get("nuclei_tags") and not ctx.get("all_templates")
                                 else [])
                              + h_flags(ctx),
            highlights=lambda t: t.strip().splitlines()[:40],
        ),
        Tool(
            "nikto", "nikto", "vuln",
            applies=lambda ctx: not ctx["fast"],
            build=lambda ctx: ["nikto", "-h", ctx["url"], "-ask", "no",
                               "-nointeractive"]
                              + (["-id", ctx["basic"]] if ctx.get("basic") else []),
            highlights=lambda t: grep_lines([r"^\+ "], t, 40),
            timeout=2400,
        ),
        # --- phase ACTIVE (exploit leger, seulement si --active) ---
        Tool(
            "sqlmap", "active", "active",
            applies=lambda ctx: ctx["active"],
            build=lambda ctx: ["sqlmap", "-u", ctx["url"], "--batch",
                               "--crawl=2", "--forms", "--level=2", "--risk=2",
                               "--random-agent", "--flush-session",
                               "--answers=follow=Y"]
                              + (["--cookie", ctx["cookie"]] if ctx.get("cookie") else [])
                              + sum((["--header", h] for h in extra_headers(ctx)
                                     if not h.lower().startswith("cookie")), []),
            highlights=lambda t: grep_lines(
                [r"is vulnerable", r"injectable", r"back-end DBMS",
                 r"available databases", r"parameter '.*' is", r"\bPayload:"], t, 40),
            timeout=2400,
        ),
        Tool(
            "dalfox", "active", "active",
            applies=lambda ctx: ctx["active"],
            build=lambda ctx: ["dalfox", "url", ctx["url"], "--silence",
                               "--no-color", "--mining-dom", "--mining-dict",
                               "--skip-bav"]
                              + (["-C", ctx["cookie"]] if ctx.get("cookie") else [])
                              + sum((["-H", h] for h in extra_headers(ctx)
                                     if not h.lower().startswith("cookie")), []),
            highlights=lambda t: grep_lines(
                [r"\[POC\]", r"\[VULN\]", r"triggered", r"reflected", r"\[G\]"], t, 40),
            timeout=1800,
        ),
        # --- specifiques CMS (se declenchent via detect_cms) ---
        Tool(
            "wpscan", "wpscan", "cms",
            applies=lambda ctx: ctx["cms"] == "wordpress",
            build=lambda ctx: ["wpscan", "--url", ctx["url"], "--no-banner",
                               "--no-update", "--random-user-agent",
                               "--enumerate", "ap,at,u",
                               "--format", "cli-no-color"]
                              + (["--http-auth", ctx["basic"]] if ctx.get("basic") else [])
                              + (["--cookie-string", ctx["cookie"]] if ctx.get("cookie") else []),
            highlights=lambda t: grep_lines([r"\[!\]", r"\[\+\]", r"vuln", r"User\(s\)"], t, 40),
        ),
        Tool(
            "joomscan", "joomscan", "cms",
            applies=lambda ctx: ctx["cms"] == "joomla",
            build=lambda ctx: ["joomscan", "-u", ctx["url"]],
            highlights=lambda t: grep_lines([r"\[\+\]", r"CVE", r"vuln"], t, 40),
        ),
        Tool(
            "droopescan", "droopescan", "cms",
            applies=lambda ctx: ctx["cms"] == "drupal",
            build=lambda ctx: ["droopescan", "scan", "drupal", "-u", ctx["url"]],
            highlights=lambda t: grep_lines([r"\[", r"found", r"CVE"], t, 40),
        ),
    ]


_PD_HTTPX: bool | None = None


def is_pd_httpx() -> bool:
    """True seulement si httpx == ProjectDiscovery (pas le client python httpx)."""
    global _PD_HTTPX
    if _PD_HTTPX is None:
        _PD_HTTPX = False
        if shutil.which("httpx"):
            try:
                p = subprocess.run(["httpx", "-version"], capture_output=True,
                                   text=True, timeout=10)
                blob = (p.stdout + p.stderr).lower()
                _PD_HTTPX = "projectdiscovery" in blob or "httpx version" in blob
            except Exception:  # noqa: BLE001
                _PD_HTTPX = False
    return _PD_HTTPX


def detect_cms(fingerprint_text: str) -> str:
    t = fingerprint_text.lower()
    if "wordpress" in t or "wp-content" in t or "wp-json" in t:
        return "wordpress"
    if "joomla" in t:
        return "joomla"
    if "drupal" in t:
        return "drupal"
    return ""


# tag nuclei -> signatures a chercher dans le fingerprint
TAG_MAP: dict[str, list[str]] = {
    "wordpress": ["wordpress", "wp-content", "wp-json"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "dell": ["openmanage", "dell inc", "omsa", "rxmon"],
    "iis": ["iis", "microsoft-iis", "asp.net", "x-aspnet"],
    "apache": ["apache"],
    "nginx": ["nginx"],
    "tomcat": ["tomcat", "coyote"],
    "jenkins": ["jenkins"],
    "php": ["php/", "x-powered-by: php"],
    "jira": ["jira"],
    "confluence": ["confluence"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "exposures": [],  # toujours utile (fichiers/clefs exposes)
    "misconfiguration": [],  # toujours utile
}


def detect_products(fingerprint_text: str) -> str:
    """Tags nuclei a lancer, deduits du fingerprint (+ 2 tags generiques utiles)."""
    t = fingerprint_text.lower()
    tags = {"exposures", "misconfiguration"}
    for tag, sigs in TAG_MAP.items():
        if any(s in t for s in sigs):
            tags.add(tag)
    return ",".join(sorted(tags))


# ---------------------------------------------------------------- execution
@dataclass
class Result:
    tool: str
    category: str
    cmd: list[str]
    rc: int = -1
    seconds: float = 0.0
    raw: str = ""
    highlights: list[str] = field(default_factory=list)
    skipped: str = ""


def run_tool(tool: Tool, ctx: dict) -> Result:
    cmd = tool.build(ctx)
    res = Result(tool.name, tool.category, cmd)
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=tool.timeout)
        res.rc = p.returncode
        res.raw = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
        # feroxbuster ecrit deja dans ctx["raw"]; on relit si vide
        if tool.name == "feroxbuster" and Path(ctx["raw"]).is_file():
            res.raw = Path(ctx["raw"]).read_text(errors="replace") or res.raw
    except subprocess.TimeoutExpired:
        res.rc = 124
        res.raw = f"[timeout apres {tool.timeout}s]"
    except Exception as e:  # noqa: BLE001
        res.rc = 1
        res.raw = f"[erreur: {e}]"
    res.seconds = round(time.time() - t0, 1)
    if tool.highlights:
        try:
            res.highlights = [h for h in tool.highlights(res.raw) if h]
        except Exception:  # noqa: BLE001
            res.highlights = []
    return res


def main() -> int:
    ap = argparse.ArgumentParser(
        description="webenum-ng : orchestrateur de reconnaissance web tout-en-un")
    ap.add_argument("target", help="URL ou IP/host (ex: http://site ou 10.10.10.10)")
    ap.add_argument("-w", "--wordlist", help="wordlist dir discovery (chemin ou nom court seclists)")
    ap.add_argument("-t", "--threads", type=int, default=50, help="threads par outil (def 50)")
    ap.add_argument("-o", "--outdir", help="dossier de sortie (def: ./webenum-<host>-<ts>)")
    ap.add_argument("-j", "--jobs", type=int, default=4, help="outils en parallele (def 4)")
    ap.add_argument("--fast", action="store_true", help="rapide: profondeur reduite, nikto off, nuclei high+")
    ap.add_argument("--full", action="store_true", help="complet: tout, profondeur max")
    ap.add_argument("--creds", metavar="USER:PASS",
                    help="auth HTTP basic injectee dans les scans (ferox/ffuf/nuclei/nikto/wpscan)")
    ap.add_argument("--cookie", metavar="NAME=VAL",
                    help="cookie de session pour scans authentifies (ex: 'PHPSESSID=abc')")
    ap.add_argument("--active", action="store_true",
                    help="phase EXPLOIT legere : sqlmap (SQLi, --crawl+forms) + dalfox (XSS). "
                         "Envoie des payloads offensifs : cibles autorisees uniquement.")
    ap.add_argument("--nuclei-tags", metavar="t1,t2",
                    help="force les tags nuclei (sinon auto-detectes depuis le fingerprint)")
    ap.add_argument("--all-templates", action="store_true",
                    help="nuclei charge TOUS les templates (lent) au lieu du ciblage par produit")
    ap.add_argument("--only", help="categories a lancer, csv: fingerprint,content,vuln,cms")
    ap.add_argument("--skip", help="categories a sauter, csv")
    ap.add_argument("--no-open", action="store_true",
                    help="ne pas ouvrir le rapport HTML dans le navigateur a la fin")
    ap.add_argument("--dry-run", action="store_true", help="affiche les commandes sans executer")
    args = ap.parse_args()

    tgt = Target(args.target)
    tgt.normalize()

    banner = f"{C.BOLD}{C.M}webenum-ng{C.X} {C.GR}// recon web orchestree{C.X}"
    print(banner)
    log(f"cible brute : {args.target}")
    if not args.dry_run:
        tgt.probe()
    else:
        tgt.url = tgt.url

    host_slug = re.sub(r"[^a-zA-Z0-9._-]", "_", tgt.host or "target")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = Path(args.outdir or f"webenum-{host_slug}-{ts}")
    if not args.dry_run:
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "raw").mkdir(exist_ok=True)

    wordlist = pick_wordlist(args.wordlist)
    if wordlist:
        log(f"wordlist    : {wordlist}")
    else:
        warn("aucune wordlist trouvee -> phase content desactivee (installe seclists ou passe -w)")

    only = {c.strip() for c in args.only.split(",")} if args.only else None
    skip = {c.strip() for c in args.skip.split(",")} if args.skip else set()

    basic = basic_b64 = None
    if args.creds:
        if ":" not in args.creds:
            err("--creds attend le format USER:PASS")
            return 2
        basic = args.creds
        basic_b64 = base64.b64encode(basic.encode()).decode()
        ok("auth basic activee pour les scans")
    if args.cookie:
        ok(f"cookie de session : {args.cookie.split('=')[0]}=...")

    ctx = {
        "url": tgt.url, "host": tgt.host, "port": tgt.port,
        "wordlist": wordlist, "threads": args.threads,
        "fast": args.fast and not args.full,
        "raw": str(outdir / "raw" / "feroxbuster.txt"),
        "cms": "", "basic": basic, "basic_b64": basic_b64,
        "cookie": args.cookie, "active": args.active,
        "nuclei_tags": args.nuclei_tags or "",
        "all_templates": args.all_templates,
    }
    if args.active:
        warn(f"{C.BOLD}mode --active : envoi de payloads SQLi/XSS. "
             f"Cible autorisee uniquement.{C.X}")

    registry = build_registry()

    def selected(tool: Tool) -> tuple[bool, str]:
        if not shutil.which(tool.bin):
            return False, "non installe"
        if only and tool.category not in only:
            return False, "exclu (--only)"
        if tool.category in skip:
            return False, "exclu (--skip)"
        if tool.applies and not tool.applies(ctx):
            return False, "condition non remplie"
        return True, ""

    # ---- PHASE 1 : fingerprint (parallele, sert a cibler la suite) ----
    results: list[Result] = []
    fp_text = ""
    log(f"{C.BOLD}phase 1 : fingerprint{C.X}")
    fp_run = []
    for tool in [t for t in registry if t.category == "fingerprint"]:
        good, why = selected(tool)
        if not good:
            print(f"  {C.GR}- skip {tool.name} ({why}){C.X}")
            results.append(Result(tool.name, tool.category, [], skipped=why))
            continue
        if args.dry_run:
            print(f"  {C.GR}$ {' '.join(tool.build(ctx))}{C.X}")
            continue
        fp_run.append(tool)

    if fp_run:
        with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = {ex.submit(run_tool, t, ctx): t for t in fp_run}
            for fut in cf.as_completed(futs):
                t = futs[fut]
                r = fut.result()
                (outdir / "raw" / f"{t.name}.txt").write_text(r.raw, errors="replace")
                results.append(r)
                fp_text += "\n" + r.raw
                print(f"  {C.G}done{C.X} {t.name} ({r.seconds}s)")
                for h in r.highlights[:5]:
                    print(f"    {C.G}>{C.X} {h[:140]}")

    ctx["cms"] = detect_cms(fp_text)
    if ctx["cms"]:
        ok(f"CMS detecte : {C.BOLD}{ctx['cms']}{C.X}")
    # ciblage nuclei : tags auto depuis le fingerprint (sauf override / all-templates)
    if not ctx["nuclei_tags"] and not ctx["all_templates"] and not args.dry_run:
        ctx["nuclei_tags"] = detect_products(fp_text)
    if ctx["nuclei_tags"] and not ctx["all_templates"]:
        ok(f"templates nuclei cibles : {C.BOLD}{ctx['nuclei_tags']}{C.X}")

    # ---- PHASES 2-4 : content / vuln / cms en parallele ----
    parallel = [t for t in registry if t.category in ("content", "vuln", "cms", "active")]
    todo = []
    for tool in parallel:
        good, why = selected(tool)
        if not good:
            print(f"  {C.GR}- skip {tool.name} ({why}){C.X}")
            results.append(Result(tool.name, tool.category, [], skipped=why))
            continue
        if args.dry_run:
            print(f"  {C.GR}$ {' '.join(tool.build(ctx))}{C.X}")
            continue
        todo.append(tool)

    if todo and not args.dry_run:
        log(f"{C.BOLD}phases 2-4 : {len(todo)} scans en parallele (j={args.jobs}){C.X}")
        with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = {ex.submit(run_tool, t, ctx): t for t in todo}
            for fut in cf.as_completed(futs):
                t = futs[fut]
                r = fut.result()
                (outdir / "raw" / f"{t.name}.txt").write_text(r.raw, errors="replace")
                results.append(r)
                tag = C.G if r.rc == 0 else C.Y
                print(f"  {tag}done{C.X} {t.name} "
                      f"({r.seconds}s, {len(r.highlights)} highlights)")

    if args.dry_run:
        ok("dry-run termine, rien n'a ete execute")
        return 0

    # ---- rapport ----
    recs = recommend(ctx, results)
    report = write_report(outdir, tgt, ctx, results, wordlist, recs)
    report_html = write_html(outdir, tgt, ctx, results, wordlist, recs)
    print_summary(results, ctx)
    print_recs(recs)
    ok(f"rapport md   : {C.BOLD}{report}{C.X}")
    ok(f"rapport html : {C.BOLD}{report_html}{C.X}")
    ok(f"sorties brutes : {outdir / 'raw'}")
    if not args.no_open:
        open_report(report_html)
    return 0


def open_report(path: Path) -> None:
    """Ouvre le rapport HTML dans le navigateur par defaut, sans bloquer."""
    uri = path.resolve().as_uri()
    try:
        if shutil.which("xdg-open"):
            subprocess.Popen(["xdg-open", uri],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            import webbrowser
            webbrowser.open(uri)
        log(f"ouverture du rapport dans le navigateur ({C.GR}--no-open pour desactiver{C.X})")
    except Exception as e:  # noqa: BLE001
        warn(f"ouverture auto impossible ({e}), ouvre manuellement : {path}")


PRIO_COLOR = {"HIGH": C.R, "MED": C.Y, "LOW": C.GR}


def print_recs(recs: list[Rec]) -> None:
    print()
    print(f"{C.BOLD}=== PROCHAINES ETAPES ==={C.X}")
    for r in recs:
        col = PRIO_COLOR.get(r.prio, "")
        print(f"  {col}[{r.prio}]{C.X} {C.BOLD}{r.title}{C.X}")
        print(f"        {r.action}")


def write_report(outdir: Path, tgt: Target, ctx: dict,
                 results: list[Result], wordlist: str | None,
                 recs: list[Rec]) -> Path:
    lines = [
        f"# webenum-ng : {tgt.url}",
        "",
        f"- Date : {datetime.now():%Y-%m-%d %H:%M}",
        f"- Host : `{tgt.host}`  Port : `{tgt.port}`  Scheme : `{tgt.scheme}`",
        f"- CMS detecte : `{ctx['cms'] or 'aucun'}`",
        f"- Wordlist : `{wordlist or 'n/a'}`",
        "",
        "## Prochaines etapes",
        "",
    ]
    for r in recs:
        lines.append(f"- [ ] **[{r.prio}] {r.title}** : {r.action}")
    lines += [
        "",
        "## Resume",
        "",
        "| Outil | Categorie | RC | Temps | Findings |",
        "|---|---|---|---|---|",
    ]
    for r in sorted(results, key=lambda x: (x.category, x.tool)):
        if r.skipped:
            lines.append(f"| {r.tool} | {r.category} | skip | - | _{r.skipped}_ |")
        else:
            lines.append(f"| {r.tool} | {r.category} | {r.rc} | {r.seconds}s | {len(r.highlights)} |")
    lines.append("")

    for cat in ("fingerprint", "content", "vuln", "cms", "active"):
        chunk = [r for r in results if r.category == cat and r.highlights]
        if not chunk:
            continue
        lines.append(f"## {cat}")
        lines.append("")
        for r in chunk:
            lines.append(f"### {r.tool}")
            lines.append("```")
            lines.extend(r.highlights)
            lines.append("```")
            lines.append("")
    report = outdir / "report.md"
    report.write_text("\n".join(lines))
    # json machine-friendly
    (outdir / "report.json").write_text(json.dumps(
        {"target": tgt.url, "cms": ctx["cms"],
         "next_steps": [{"prio": r.prio, "title": r.title, "action": r.action}
                        for r in recs],
         "results": [{"tool": r.tool, "category": r.category, "rc": r.rc,
                      "seconds": r.seconds, "skipped": r.skipped,
                      "highlights": r.highlights} for r in results]},
        indent=2))
    return report


@dataclass
class Rec:
    prio: str  # HIGH / MED / LOW
    title: str
    action: str


# (priorite, regex a chercher dans les findings, titre, action concrete)
REC_RULES: list[tuple[str, str, str, str]] = [
    ("HIGH", r"\.git[/\b]", "Repertoire .git expose",
     "Dumpe le code source : git-dumper http://CIBLE/.git/ ./src, puis grep creds/secrets/historique."),
    ("HIGH", r"\.env\b", "Fichier .env expose",
     "Recupere-le : il contient souvent DB creds, API keys, secret de session."),
    ("HIGH", r"phpmyadmin", "phpMyAdmin accessible",
     "Teste creds par defaut (root / vide), puis SQL -> RCE (SELECT ... INTO OUTFILE un webshell)."),
    ("HIGH", r"openmanage|dell inc|\bomsa\b|rxmon|:1311", "Dell OpenManage expose",
     "Verifie CVE-2020-5377 / CVE-2021-21518 (lecture de fichier non authentifiee). "
     "searchsploit openmanage. Souvent : lire un web.config -> creds -> RDP/WinRM."),
    ("HIGH", r"/manager/html|tomcat", "Tomcat Manager",
     "Teste tomcat/tomcat & admin/admin, puis deploie un .war malveillant (msfvenom) pour un shell."),
    ("HIGH", r"jenkins", "Jenkins expose",
     "Si la console Groovy est accessible -> RCE directe; sinon cherche /script ou un job buildable."),
    ("HIGH", r"webdav|allow:.*\bput\b|\bdav\b", "WebDAV / verbe PUT",
     "Upload un webshell : curl -X PUT http://CIBLE/shell.php --data-binary @shell.php (ou cadaver)."),
    ("HIGH", r"you have an error in your sql|sql syntax|warning.*mysql", "Erreur SQL visible",
     "Injection probable : sqlmap -u 'http://CIBLE/page?id=1' --batch --dbs --risk=2 --level=3."),
    ("HIGH", r"wp-login|wp-admin|wp-content|wordpress", "WordPress detecte",
     "wpscan --url http://CIBLE --enumerate u pour les users, puis --passwords rockyou.txt; teste aussi xmlrpc.php."),
    ("MED", r"/administrator\b|joomla", "Joomla detecte",
     "Enumere via joomscan, teste /administrator avec creds par defaut, cherche des composants vulnerables."),
    ("MED", r"drupal", "Drupal detecte",
     "droopescan scan drupal; verifie la version pour Drupalgeddon (CVE-2018-7600 / 7602)."),
    ("MED", r"/admin\b|/login\b|/signin\b|/portal\b|/auth\b", "Page d'authentification",
     "Teste creds par defaut, puis brute ciblee (hydra / Burp Intruder). Attention au lockout."),
    ("MED", r"upload|fileupload|/files/", "Endpoint d'upload",
     "Teste les bypass d'extension (.phtml, double ext, null byte, magic bytes, Content-Type) pour un webshell."),
    ("MED", r"index of|directory listing", "Listing de repertoire actif",
     "Navigue les dossiers pour des fichiers sensibles : backups, configs, cles, dumps."),
    ("MED", r"\.bak\b|\.old\b|\.zip\b|\.tar|\.sql\b|\.save\b|backup", "Fichiers de backup exposes",
     "Telecharge-les : code source, creds DB, ou anciens mots de passe souvent dedans."),
    ("MED", r"robots\.txt|disallow", "robots.txt present",
     "Visite chaque entree Disallow : ce sont des chemins que l'admin veut cacher (souvent interessants)."),
    ("MED", r"phpinfo", "phpinfo() expose",
     "Lis chemins absolus, modules, variables d'env; utile pour LFI/RCE et fuite de secrets."),
    ("MED", r"swagger|openapi|graphql|/api/|/v1/|/v2/", "Surface API",
     "Enumere les endpoints (swagger/openapi), teste IDOR/authz cassee, fuzz les parametres (arjun, ffuf)."),
    ("MED", r"\b403\b|forbidden", "403 sur des chemins",
     "Tente le bypass 403 : headers (X-Original-URL, X-Forwarded-For), tricks de path (//, /./, %2e, ;/), autres verbes HTTP."),
    ("LOW", r"\b401\b|unauthorized", "401 auth requise",
     "Teste basic auth par defaut, ou relance le scan avec --creds/--cookie une fois des creds obtenus."),
    ("LOW", r"apache/|nginx/|openssh|php/\d|iis/", "Versions de service identifiees",
     "Passe chaque version a searchsploit pour des CVE connues."),
]


def recommend(ctx: dict, results: list[Result]) -> list[Rec]:
    corpus = "\n".join(
        h for r in results if not r.skipped for h in r.highlights).lower()
    # ajoute le fingerprint brut (tech/server) au corpus
    for r in results:
        if r.category == "fingerprint" and not r.skipped:
            corpus += "\n" + r.raw.lower()

    recs: list[Rec] = []
    seen: set[str] = set()

    def add(prio: str, title: str, action: str) -> None:
        if title not in seen:
            recs.append(Rec(prio, title, action))
            seen.add(title)

    # findings nuclei high/critical = priorite absolue
    for r in results:
        if r.tool == "nuclei" and r.highlights:
            if re.search(r"\b(critical|high)\b", " ".join(r.highlights), re.I):
                add("HIGH", "Nuclei : vuln high/critical",
                    "Identifie le template/CVE, lance searchsploit dessus, verifie le PoC puis exploite.")
            else:
                add("MED", "Nuclei : findings a trier",
                    "Relis chaque match (misconfig, exposition, info leak) et decide lesquels sont exploitables.")

    for prio, rx, title, action in REC_RULES:
        if re.search(rx, corpus, re.I):
            add(prio, title, action)

    # CMS detecte explicitement (meme si le texte ne matche pas)
    cms_map = {
        "wordpress": ("WordPress detecte", "wpscan --url http://CIBLE --enumerate u, puis brute --passwords rockyou.txt; teste xmlrpc.php."),
        "joomla": ("Joomla detecte", "joomscan -u http://CIBLE, teste /administrator, cherche des composants vulnerables."),
        "drupal": ("Drupal detecte", "droopescan scan drupal; verifie la version pour Drupalgeddon."),
    }
    if ctx.get("cms") in cms_map:
        t, a = cms_map[ctx["cms"]]
        add("HIGH", t, a)

    if not recs:
        add("LOW", "Rien d'exploitable remonte",
            "Elargis : wordlist plus grosse (-w big.txt), extensions (-x php,txt,bak), "
            "recursion (--full), fuzzing de vhosts (ffuf Host:) et de parametres (arjun).")
    else:
        add("LOW", "Toujours en complement",
            "Lance Burp/ZAP pour la logique metier et l'auth, et fuzz les parametres caches (arjun/paramspider).")

    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    recs.sort(key=lambda x: order.get(x.prio, 9))
    return recs


SEV_RX = re.compile(r"\b(critical|high|medium|low|info)\b", re.I)


def write_html(outdir: Path, tgt: Target, ctx: dict,
               results: list[Result], wordlist: str | None,
               recs: list[Rec]) -> Path:
    def esc(s: str) -> str:
        return html.escape(s)

    def sev_class(line: str) -> str:
        m = SEV_RX.search(line)
        return f"sev-{m.group(1).lower()}" if m else ""

    done = [r for r in results if not r.skipped]
    rows = ""
    for r in sorted(results, key=lambda x: (x.category, x.tool)):
        if r.skipped:
            rows += (f"<tr class='skip'><td>{esc(r.tool)}</td><td>{esc(r.category)}</td>"
                     f"<td>skip</td><td>-</td><td>{esc(r.skipped)}</td></tr>")
        else:
            cls = "ok" if r.rc == 0 else "warnrc"
            rows += (f"<tr class='{cls}'><td>{esc(r.tool)}</td><td>{esc(r.category)}</td>"
                     f"<td>{r.rc}</td><td>{r.seconds}s</td><td>{len(r.highlights)}</td></tr>")

    sections = ""
    for cat in ("fingerprint", "content", "vuln", "cms", "active"):
        chunk = [r for r in done if r.category == cat and r.highlights]
        if not chunk:
            continue
        sections += f"<h2>{esc(cat)}</h2>"
        for r in chunk:
            body = "".join(
                f"<div class='line {sev_class(h)}'>{esc(h)}</div>" for h in r.highlights)
            sections += (f"<details open><summary>{esc(r.tool)} "
                         f"<span class='badge'>{len(r.highlights)}</span></summary>"
                         f"<div class='block'>{body}</div></details>")

    recs_html = ""
    if recs:
        items = ""
        for r in recs:
            items += (f"<li class='rec r-{r.prio.lower()}'>"
                      f"<span class='pri'>{r.prio}</span>"
                      f"<b>{esc(r.title)}</b><div class='act'>{esc(r.action)}</div></li>")
        recs_html = f"<h2>Prochaines etapes</h2><ul class='recs'>{items}</ul>"

    auth = []
    if ctx.get("basic"):
        auth.append("basic auth")
    if ctx.get("cookie"):
        auth.append("cookie")
    auth_s = ", ".join(auth) or "aucune"

    doc = f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>webenum-ng : {esc(tgt.host)}</title>
<style>
:root{{--bg:#0d1117;--card:#161b22;--line:#21262d;--fg:#e6edf3;--mut:#8b949e;
--acc:#a371f7;--ok:#3fb950;--warn:#d29922}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:24px}}
.wrap{{max-width:1000px;margin:0 auto}}
h1{{font-size:22px;margin:0 0 4px}}h1 .mut{{color:var(--mut);font-weight:400;font-size:15px}}
h2{{margin:28px 0 10px;color:var(--acc);border-bottom:1px solid var(--line);padding-bottom:6px}}
.meta{{color:var(--mut);margin:0 0 18px;font-size:13px}}
.meta b{{color:var(--fg)}}
table{{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:8px;overflow:hidden;font-size:13px}}
th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line)}}
th{{color:var(--mut);font-weight:600}}
tr.skip td{{color:var(--mut)}}tr.ok td:nth-child(3){{color:var(--ok)}}
tr.warnrc td:nth-child(3){{color:var(--warn)}}
details{{background:var(--card);border:1px solid var(--line);border-radius:8px;
margin:10px 0;padding:4px 14px}}
summary{{cursor:pointer;font-weight:600;padding:8px 0}}
.badge{{background:var(--acc);color:#fff;border-radius:10px;padding:1px 8px;
font-size:11px;margin-left:6px}}
.block{{padding:4px 0 10px}}
.line{{padding:2px 8px;border-left:3px solid transparent;white-space:pre-wrap;
word-break:break-word;font-size:13px}}
.sev-critical{{border-color:#f85149;background:#f851491a}}
.sev-high{{border-color:#f85149;background:#f851491a}}
.sev-medium{{border-color:var(--warn);background:#d299221a}}
.sev-low{{border-color:#58a6ff;background:#58a6ff1a}}
.sev-info{{border-color:var(--mut)}}
.recs{{list-style:none;padding:0;margin:0}}
.rec{{background:var(--card);border:1px solid var(--line);border-left-width:4px;
border-radius:8px;padding:10px 14px;margin:8px 0}}
.rec .pri{{display:inline-block;font-size:11px;font-weight:700;padding:1px 8px;
border-radius:10px;margin-right:8px;color:#fff}}
.rec .act{{color:var(--mut);font-size:13px;margin-top:4px}}
.r-high{{border-left-color:#f85149}}.r-high .pri{{background:#f85149}}
.r-med{{border-left-color:var(--warn)}}.r-med .pri{{background:var(--warn);color:#000}}
.r-low{{border-left-color:var(--mut)}}.r-low .pri{{background:var(--mut)}}
footer{{color:var(--mut);font-size:12px;margin-top:30px;text-align:center}}
</style></head><body><div class="wrap">
<h1>webenum-ng <span class="mut">// {esc(tgt.url)}</span></h1>
<p class="meta">{datetime.now():%Y-%m-%d %H:%M} &middot; host <b>{esc(tgt.host)}</b> &middot;
port <b>{tgt.port}</b> &middot; CMS <b>{esc(ctx['cms'] or 'aucun')}</b> &middot;
auth <b>{esc(auth_s)}</b> &middot; wordlist <b>{esc(Path(wordlist).name if wordlist else 'n/a')}</b></p>
{recs_html}
<table><thead><tr><th>Outil</th><th>Categorie</th><th>RC</th><th>Temps</th><th>Findings</th></tr></thead>
<tbody>{rows}</tbody></table>
{sections}
<footer>webenum-ng &middot; a n'utiliser que sur des cibles autorisees</footer>
</div></body></html>"""
    out = outdir / "report.html"
    out.write_text(doc)
    return out


def print_summary(results: list[Result], ctx: dict) -> None:
    print()
    print(f"{C.BOLD}=== RESUME ==={C.X}")
    interesting = []
    for r in results:
        if r.skipped or not r.highlights:
            continue
        if r.category in ("vuln", "cms"):
            interesting.extend(r.highlights[:6])
    if interesting:
        print(f"{C.Y}Findings notables :{C.X}")
        for h in interesting[:20]:
            print(f"  {C.R}!{C.X} {h[:160]}")
    else:
        print(f"{C.GR}pas de finding vuln/cms remonte (verifie les sorties brutes){C.X}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        err("interrompu")
        sys.exit(130)
