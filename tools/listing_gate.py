#!/usr/bin/env python3
"""Listing gate: nothing in ``records/`` merges before it is actually checked.

Owner rule, 2026-11-18: a listing must be checked BEFORE its pull request can
merge -- "a required backlink artifact, plus checks in index/shadowbroker/
reputation, health check, and looks for poisoned domains".

This gate runs on every pull request that adds or changes a record and produces
one verdict per record:

  artifact   the listed page carries its backlink artifact (well-known, link
             rel=aithernet, meta aithernet, or a visible link to its entry)
  health     HTTPS answers 2xx in 15 s, TLS verifies (not expired, hostname
             matches), the final host is the record's host (or its www), the
             page has a <title>, and it is not a parked/for-sale page
  poisoned   Cloudflare filtered-vs-standard DoH and Quad9 filtered-vs-
             unfiltered: a filtered-only block is a malicious verdict
  reputation RDAP registration age (< configured days needs a maintainer
             label), OTX pulses, OpenPhish/malware-filter membership, URLhaus
             (keyless skip: it requires a key, and no new CI secret is created)
  lookalike  typosquat / homoglyph / IDN confusable / brand-on-another-domain
             against every listed host and the protected list in gate_config.json

Every network rule has a pure counterpart in ``reputation.py`` /
``artifact_check.py`` and a test with a fixture; tests never touch the network.

    python tools/listing_gate.py --base origin/main --head FETCH_HEAD
    python tools/listing_gate.py --records records/pufferparty.org.json
    python tools/listing_gate.py --post-comment     # CI: one sticky PR comment

Exit 0 every record passed (skipped sources are reported, never hidden),
1 a record failed a rule, 2 the gate could not judge (bad refs / no records).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import artifact_check  # noqa: E402
import gate_net  # noqa: E402
import reputation as rep  # noqa: E402

PASS, FAIL, SKIP = rep.PASS, rep.FAIL, rep.SKIP
DEFAULT_CONFIG = Path(__file__).resolve().parent / "gate_config.json"
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_COMMENT_MARKER = "<!-- listing-gate:start -->"


@dataclass
class RuleResult:
    record: str
    rule: str
    status: str
    reason: str

    def line(self) -> str:
        return f"  {self.rule:<11} {self.status.upper():<5} {self.reason}"


@dataclass
class Record:
    id: str
    kind: str
    url: str
    path: str
    raw: dict


@dataclass
class Context:
    config: dict
    existing_hosts: List[str]
    labels: List[str]
    timeout: float = 15.0
    offline: bool = False
    get: object = gate_net.fetch
    get_json: object = gate_net.fetch_json
    dns_a: object = gate_net.dns_query_a
    tls: object = gate_net.tls_check
    feeds: dict = field(default_factory=dict)

    @property
    def age_label_accepted(self) -> bool:
        return self.config.get("accept_age_label", "") in self.labels


# ── records and git ──────────────────────────────────────────────────────────

def parse_record(path: str, raw: dict) -> Record:
    return Record(id=str(raw.get("id") or ""), kind=str(raw.get("kind") or ""),
                  url=str(raw.get("url") or ""), path=path, raw=raw)


def parse_name_status(text: str) -> "List[Tuple[str, str]]":
    """``git diff --name-status`` output -> [(status letter, new path)]."""
    out: "List[Tuple[str, str]]" = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0]:
            out.append((parts[0][0], parts[-1].strip()))
    return out


def git(repo: "Path | str", *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                          text=True, encoding="utf-8")
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {proc.stderr.strip()[:200]}")
    return proc.stdout


def changed_record_paths(repo: "Path | str", base: str, head: str) -> "List[Tuple[str, str]]":
    diff = git(repo, "diff", "--name-status", "--diff-filter=AMR", "--find-renames",
               f"{base}...{head}", "--", "records")
    return [(s, p) for s, p in parse_name_status(diff) if p.endswith(".json")]


def read_blob(repo: "Path | str", ref: str, path: str) -> dict:
    return json.loads(git(repo, "show", f"{ref}:{path}"))


def records_at_ref(repo: "Path | str", ref: str) -> "List[Record]":
    out: "List[Record]" = []
    listing = git(repo, "ls-tree", "-r", "--name-only", ref, "--", "records")
    for path in listing.splitlines():
        if not path.endswith(".json"):
            continue
        try:
            out.append(parse_record(path, read_blob(repo, ref, path)))
        except (RuntimeError, ValueError):
            continue
    return out


def records_on_disk(root: "Path | str") -> "List[Record]":
    out: "List[Record]" = []
    for path in sorted(Path(root).rglob("records/*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append(parse_record(str(path.relative_to(root)).replace("\\", "/"), raw))
    return out


def load_targets(args) -> "Tuple[List[Record], List[str]]":
    """(records to judge, hosts already listed). Raises RuntimeError if unjudgeable."""
    root = Path(args.root)
    if args.records:
        targets = []
        for path in args.records:
            full = root / path
            targets.append(parse_record(path, json.loads(full.read_text(encoding="utf-8"))))
        if args.base:
            existing = records_at_ref(root, args.base)
        else:
            existing = records_on_disk(root)
    else:
        if not args.base or not args.head:
            raise RuntimeError("need --base and --head, or explicit --records")
        changed = changed_record_paths(root, args.base, args.head)
        targets = []
        for status, path in changed:
            if status == "D":
                continue
            targets.append(parse_record(path, read_blob(root, args.head, path)))
        existing = records_at_ref(root, args.base)
    existing_hosts = [gate_net.host_of(r.url) for r in existing if r.url]
    return targets, [h for h in existing_hosts if h]


# ── health (pure inspection over fetched facts) ──────────────────────────────

def html_title(html: str) -> str:
    match = _TITLE.search(html or "")
    return " ".join(match.group(1).split()) if match else ""


def parked_marker(html: str, markers: Sequence[str]) -> str:
    lowered = (html or "").lower()
    for marker in markers:
        if marker.lower() in lowered:
            return marker
    return ""


def same_host(record_host: str, final_host: str) -> bool:
    def bare(host: str) -> str:
        return host[4:] if host.startswith("www.") else host

    return bool(record_host) and bare(record_host) == bare(final_host or "")


def inspect_health(url: str, page: gate_net.Fetch, tls: gate_net.TLSResult,
                   config: dict) -> "Tuple[str, str]":
    """Combine what the fetcher saw into one verdict. Pure."""
    parts = urlsplit(url or "")
    record_host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not record_host:
        return FAIL, "the record needs an https url to be health-checked"
    if not tls.ok:
        return FAIL, f"TLS: {tls.reason}"
    if page.error:
        return FAIL, f"page did not answer: {page.error}"
    if not page.ok:
        return FAIL, f"HTTP {page.status} (need 2xx)"
    final_host = (urlsplit(page.final_url).hostname or "").lower()
    if not same_host(record_host, final_host):
        return FAIL, (f"redirected off the record's host: final host {final_host or '?'} "
                      f"(a block or parked page is not the listing)")
    title = html_title(page.body)
    if not title:
        return FAIL, "page has no <title>"
    marker = parked_marker(page.body, config.get("parked_markers", []))
    if marker:
        return FAIL, f"parked/for-sale page marker: {marker!r}"
    return PASS, (f"https {page.status} on {final_host}, title {title[:60]!r}, "
                  f"TLS {tls.reason}")


def health_rule(rec: Record, ctx: Context) -> RuleResult:
    if not rec.url:
        return RuleResult(rec.id, "health", FAIL,
                          "record has no url; artifact and health cannot be judged")
    if ctx.offline:
        return RuleResult(rec.id, "health", SKIP, "offline: not fetched")
    host = gate_net.host_of(rec.url)
    page = ctx.get(rec.url, timeout=ctx.timeout)
    tls = ctx.tls(host, timeout=min(ctx.timeout, 10)) if host else gate_net.TLSResult(
        False, "no host")
    status, reason = inspect_health(rec.url, page, tls, ctx.config)
    return RuleResult(rec.id, "health", status, reason)


# ── artifact ─────────────────────────────────────────────────────────────────

def artifact_rule(rec: Record, ctx: Context) -> RuleResult:
    if rec.kind in ctx.config.get("discord_exempt_kinds", []):
        return RuleResult(rec.id, "artifact", PASS,
                          f"kind {rec.kind!r} is checked by its own bot")
    if not rec.url:
        return RuleResult(rec.id, "artifact", FAIL, "record has no url to look at")
    if ctx.offline:
        return RuleResult(rec.id, "artifact", SKIP, "offline: not fetched")
    page, art = artifact_check.probe(rec.id, rec.url, get=ctx.get, timeout=ctx.timeout)
    if art.ok:
        return RuleResult(rec.id, "artifact", PASS, f"{art.form}: {art.reason}")
    detail = art.reason
    if page.error:
        detail = f"page did not answer ({page.error}); {detail}"
    return RuleResult(rec.id, "artifact", FAIL, detail)


# ── reputation ───────────────────────────────────────────────────────────────

def reputation_rules(rec: Record, ctx: Context) -> "List[RuleResult]":
    host = gate_net.host_of(rec.url)
    if not host:
        return [RuleResult(rec.id, "reputation", FAIL, "record has no host to look up")]
    if ctx.offline:
        return [RuleResult(rec.id, "reputation", SKIP, "offline: not looked up")]

    out: "List[RuleResult]" = []
    dns_status, dns_reason = rep.check_dns(host, get_json=ctx.get_json, dns_a=ctx.dns_a,
                                           timeout=ctx.timeout)
    out.append(RuleResult(rec.id, "dns", dns_status, dns_reason))

    age, age_reason, _payload = rep.check_rdap(host, ctx.config, get_json=ctx.get_json,
                                               timeout=ctx.timeout)
    age_status, age_detail = rep.rdap_age_verdict(
        age, int(ctx.config.get("max_domain_age_days", 30)), ctx.age_label_accepted)
    out.append(RuleResult(rec.id, "rdap-age", age_status, f"{age_detail}; {age_reason}"))

    otx_status, otx_reason = rep.check_otx(host, get_json=ctx.get_json,
                                           timeout=ctx.timeout)
    out.append(RuleResult(rec.id, "otx", otx_status, otx_reason))

    feeds = ctx.feeds or rep.load_feeds()
    feed_status, feed_reason = rep.feeds_verdict(host, feeds.get("openphish"),
                                                 feeds.get("domains"))
    out.append(RuleResult(rec.id, "phishing", feed_status, feed_reason))

    urlhaus_status, urlhaus_reason = rep.check_urlhaus(host, timeout=ctx.timeout)
    out.append(RuleResult(rec.id, "urlhaus", urlhaus_status, urlhaus_reason))
    return out


def lookalike_rule(rec: Record, ctx: Context) -> RuleResult:
    host = gate_net.host_of(rec.url)
    if not host:
        return RuleResult(rec.id, "lookalike", FAIL, "record has no host to compare")
    status, reason = rep.lookalike_verdict(host, ctx.existing_hosts, ctx.config)
    return RuleResult(rec.id, "lookalike", status, reason)


def judge(rec: Record, ctx: Context) -> "List[RuleResult]":
    results: "List[RuleResult]" = []
    for rule in (lambda r: artifact_rule(r, ctx), lambda r: health_rule(r, ctx)):
        try:
            results.append(rule(rec))
        except Exception as exc:  # noqa: BLE001 - a broken rule never crashes the gate
            results.append(RuleResult(rec.id, "error", FAIL,
                                      f"{type(exc).__name__}: {exc}"))
    try:
        results.extend(reputation_rules(rec, ctx))
    except Exception as exc:  # noqa: BLE001
        results.append(RuleResult(rec.id, "reputation", FAIL,
                                  f"{type(exc).__name__}: {exc}"))
    try:
        results.append(lookalike_rule(rec, ctx))
    except Exception as exc:  # noqa: BLE001
        results.append(RuleResult(rec.id, "lookalike", FAIL,
                                  f"{type(exc).__name__}: {exc}"))
    return results


def overall(results: Sequence[RuleResult]) -> str:
    if any(r.status == FAIL for r in results):
        return FAIL
    if not results:
        return SKIP
    return PASS


# ── output ───────────────────────────────────────────────────────────────────

def render_table(records: Sequence[Record], results: Sequence[RuleResult]) -> str:
    by_id: "Dict[str, List[RuleResult]]" = {}
    for result in results:
        by_id.setdefault(result.record, []).append(result)
    lines = []
    for rec in records:
        lines.append(f"{rec.id}  ({rec.path})")
        for result in by_id.get(rec.id, []):
            lines.append(result.line())
        record_results = by_id.get(rec.id, [])
        lines.append(f"  -> {overall(record_results).upper()}")
        lines.append("")
    verdict = overall(results)
    failed = sum(1 for r in results if r.status == FAIL)
    skipped = sum(1 for r in results if r.status == SKIP)
    lines.append(f"listing-gate: {len(records)} record(s), {failed} failed rule(s), "
                 f"{skipped} skipped -> {verdict.upper()}")
    return "\n".join(lines)


_FIX = {
    "artifact": "serve /.well-known/aithernet.json listing this id, or put a "
                "<link rel=\"aithernet\" href=\"https://index.aitherium.com/r/<id>\"> "
                "(or meta / visible link) on the page",
    "health": "fix the site: https, valid certificate, same host after redirects, "
              "a real page with a <title>, not a parked page",
    "dns": "the domain is blocked by a filtering resolver as malicious; remove it",
    "rdap-age": "the domain is newer than the configured age; a maintainer must "
                "add the listing-age-accepted label to accept it",
    "otx": "OTX reports many threat pulses; remove the listing",
    "phishing": "the host is on an active phishing feed; remove the listing",
    "urlhaus": "URLhaus lists the host; remove the listing",
    "lookalike": "the host imitates a listed or protected domain; use the real domain",
}


def render_summary(records: Sequence[Record], results: Sequence[RuleResult],
                   marker: str = _COMMENT_MARKER) -> str:
    verdict = overall(results)
    lines = [marker, "## Listing gate", "",
             f"**Verdict: {verdict.upper()}** — {len(records)} record(s) checked "
             f"in `records/`.", "",
             "| record | rule | verdict | why |", "|---|---|---|---|"]
    for rec in records:
        for result in (r for r in results if r.record == rec.id):
            why = result.reason.replace("|", "\\|")
            lines.append(f"| `{rec.id}` | {result.rule} | {result.status.upper()} | {why} |")
    failures = [r for r in results if r.status == FAIL]
    if failures:
        lines += ["", "### What to fix", ""]
        for result in failures:
            fix = _FIX.get(result.rule, "fix the rule's finding")
            lines.append(f"- **{result.record} / {result.rule}**: {fix}")
    skipped = [r for r in results if r.status == SKIP]
    if skipped:
        lines += ["", "### Not judged (reported, not a pass)", ""]
        for result in skipped:
            lines.append(f"- `{result.record}` / {result.rule}: {result.reason}")
    lines += ["", "Rule code: `tools/listing_gate.py`, `tools/reputation.py`, "
                  "`tools/artifact_check.py`. How to satisfy each rule: "
                  "`CONTRIBUTING.md`."]
    return "\n".join(lines)


# ── sticky PR comment ────────────────────────────────────────────────────────

def find_marker_comment(comments: Iterable[dict], marker: str) -> "Optional[dict]":
    for comment in comments:
        if str(comment.get("body") or "").startswith(marker):
            return comment
    return None


def _api(method: str, path: str, token: str, body: "Optional[dict]" = None):
    import urllib.error
    import urllib.request

    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        f"https://api.github.com{path}", method=method, data=data,
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "User-Agent": artifact_check.INDEX_BASE,
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return json.loads(resp.read(262144).decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GitHub API {method} {path}: {exc.code}") from exc


def upsert_comment(repo: str, pr: int, body: str, token: str,
                   api=_api) -> "Tuple[bool, str]":
    marker = body.splitlines()[0] if body else _COMMENT_MARKER
    comments = api("GET", f"/repos/{repo}/issues/{pr}/comments?per_page=100", token) or []
    existing = find_marker_comment(comments, marker)
    if existing:
        api("PATCH", f"/repos/{repo}/issues/comments/{existing['id']}", token,
            {"body": body})
        return True, f"updated comment {existing['id']}"
    api("POST", f"/repos/{repo}/issues/{pr}/comments", token, {"body": body})
    return True, "created comment"


# ── CLI ──────────────────────────────────────────────────────────────────────

def build_context(args, targets: Sequence[Record], existing_hosts: List[str]) -> Context:
    config = rep.load_config(args.config)
    labels = []
    if args.labels_json:
        try:
            labels = list(json.loads(args.labels_json))
        except ValueError:
            labels = []
    ctx = Context(config=config, existing_hosts=existing_hosts, labels=labels,
                  timeout=float(args.timeout), offline=args.offline)
    if not args.offline:
        try:
            ctx.feeds = rep.load_feeds()
        except Exception:  # noqa: BLE001 - feeds down is a skip, not a crash
            ctx.feeds = {"openphish": None, "domains": None}
    return ctx


def main(argv: "Optional[Sequence[str]]" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    ap.add_argument("--base", help="base ref/sha to diff from")
    ap.add_argument("--head", help="head ref/sha to judge")
    ap.add_argument("--records", nargs="*", help="explicit record paths (relative to root)")
    ap.add_argument("--labels-json", default="", help="JSON array of PR label names")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--offline", action="store_true", help="skip every network rule")
    ap.add_argument("--summary", help="write the markdown summary here")
    ap.add_argument("--json", help="write the machine-readable verdicts here")
    ap.add_argument("--post-comment", action="store_true",
                    help="create/update the sticky PR comment (needs GITHUB_TOKEN)")
    ap.add_argument("--comment-file",
                    help="post/update the sticky PR comment from this markdown file")
    ap.add_argument("--pr", type=int, help="PR number (default: GITHUB_REF/event)")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        import unittest
        loader = unittest.TestLoader()
        suite = loader.discover(str(Path(__file__).resolve().parents[1] / "tests"))
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        return 0 if result.wasSuccessful() else 1

    if args.comment_file:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        if not (token and args.repo and args.pr):
            print("comment: not posted (need GITHUB_TOKEN, --repo and --pr)")
            return 0
        try:
            body = Path(args.comment_file).read_text(encoding="utf-8")
            ok, detail = upsert_comment(args.repo, args.pr, body, token)
            print(f"comment: {detail}")
        except (OSError, RuntimeError) as exc:
            print(f"comment: NOT POSTED: {exc}")
        return 0

    try:
        targets, existing_hosts = load_targets(args)
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"could not judge: {exc}")
        return 2
    if not targets:
        print("listing-gate: no added or changed records; nothing to judge")
        return 0

    ctx = build_context(args, targets, existing_hosts)
    results: "List[RuleResult]" = []
    for rec in targets:
        results.extend(judge(rec, ctx))

    print(render_table(targets, results))
    summary = render_summary(targets, results, ctx.config.get("comment_marker",
                                                              _COMMENT_MARKER))
    if args.summary:
        Path(args.summary).write_text(summary + "\n", encoding="utf-8")
        print(f"summary: {args.summary}")
    if args.json:
        Path(args.json).write_text(json.dumps(
            [r.__dict__ for r in results], indent=2) + "\n", encoding="utf-8")
        print(f"json: {args.json}")

    if args.post_comment:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        pr = args.pr or (int(os.environ["PR_NUMBER"]) if os.environ.get("PR_NUMBER")
                         else 0)
        if not (token and args.repo and pr):
            print("comment: not posted (need GITHUB_TOKEN, --repo and --pr)")
        else:
            try:
                ok, detail = upsert_comment(args.repo, pr, summary, token)
                print(f"comment: {detail}")
            except RuntimeError as exc_noauth:
                print(f"comment: NOT POSTED: {exc_noauth}")

    return 0 if overall(results) != FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
