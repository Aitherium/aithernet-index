# Reputation: how the index resists fakes

One person can now stand up a polished site, a company, a fleet of agents and a pile
of reviews in an afternoon. A directory that ranks on *looking* professional will be
gamed first. This index ranks on **evidence that is expensive to fake** instead.

## The rule

Trust is computed from facts in the record. A contributor never types it in.
`netindex.trust()` is the only thing that decides it, and the site shows the tier
next to every entry.

| tier | name | what moved it there | cost to fake |
|---|---|---|---|
| 0 | submitted | someone opened an issue | free |
| 1 | reachable | the bot fetched the URL and got 200 | a live site |
| 2 | owner-proven | the site serves `/.well-known/aithernet.json` naming the record | control of the domain |
| 3 | vouched | tier 1+ AND two distinct people, other than the submitter, vouched | two real, aged accounts that are willing to sign |

## The required backlink, and what each form proves

A listing must carry **one** artifact that links it back to the index
(`artifact.py`, enforced by the daily `recheck.py`). The two useful forms prove
different things, so they earn different rank:

| artifact | what it proves | rank it can reach |
|---|---|---|
| `https://<host>/.well-known/aithernet.json` naming the id | control of the **domain** | owner-proven (tier 2) |
| `<link rel="aithernet">` / `<meta name="aithernet">` / a visible link to `https://index.aitherium.com/r/<id>` | that the **page** points at its entry | reachable (tier 1) at most |

A link-back is trivially copyable, so it never confers owner-proven: `trust()` only
grants that tier for the well-known method (`owner-asserted` stays an internal
exception). A link-back still matters, because it is the thing the daily check can
see: if the page is swapped, the new page almost never carries it.

Both forms are matched against the exact host `index.aitherium.com`, an `https`
scheme, and the exact record id. A link to another domain, a look-alike host
(`index.aitherium.com.evil.example`), a different entry, or an anchor with no visible
text does not count — the checker is written to fail closed. A backlink hidden from a
reader is not a backlink: anchors under `display:none`, `visibility:hidden`,
`opacity:0`, zero font size, an off-screen position, the `hidden` attribute,
`aria-hidden=true`, a hiding CSS class, or only zero-width text are rejected, as are
`<link>`/`<meta>` tags inside `<template>`, `<noscript>`, `<svg>` or a comment.

## Keeping the approval honest: the daily re-check

An approval is about a page at a moment. `recheck.py` (run daily by
`.github/workflows/recheck.yml`) revisits every entry and fails it when:

- the URL no longer answers;
- the required artifact is gone (after a 30-day grace period, `grace_starts`
  2026-11-18, for entries listed before this shipped). A record validated on or after
  that date is a **new** listing: without its artifact it is not approved, so no grace;
- the page now redirects to a different final host (domain sold, parked, redirected) —
  including a client-side redirect (`<meta http-equiv=refresh>` or `location=...`),
  which a server-side-only redirect check would miss;
- the page serves a different body to the checker's User-Agent than to a browser
  (UA-keyed cloaking);
- the main visible text changed enough that token-set Jaccard similarity to the
  approved page is below 0.65. The fingerprint reads `<main>`/`<article>` (or the body
  without nav/header/footer/aside), so a shared template cannot dilute a swapped body,
  and a text-less page (photo portfolio, JS shell) is compared by its assets instead
  of an all-zero signature that matched everything.

Failure moves an entry through a state machine kept in `state/health.json` — **not**
in the records, so a record stays exactly what a human last reviewed:

```
active --(first failure)--> warn
warn --(3 failures inside 7 days, or the final host changed)--> suspended
suspended --(14 days)--> delisted
any status --(a clean check, if the last 7 days are no longer mostly failures)--> active
```

Failures are counted over a rolling 7-day window and are **not** reset by a single good
day: a site that is down two days in three is suspended on day four and cannot return
to the listing until the window is clean. `warn` is hidden from the published listing
too, so a permanently flapping entry stops being shown at all.

Delisted never means deleted. `build_site.py` hides the entry from the listing,
`index.json` carries `status: delisted`, and the entry page stays up with the reason.
One GitHub issue per entry (label `recheck`) opens on suspend or a needs-review
change and closes itself when the entry recovers. A maintainer who accepts a genuine
rebuild re-seeds the fingerprint with `python recheck.py --accept <id>`; the state
records that as `baseline_source: accepted` with `accepted_at`, which is what
`check.py` requires before it will accept a baseline that differs from the fingerprint
stamped on the record. A state-only commit that silently re-seeds a baseline is a
finding (NI021), and a cleared baseline is a `baseline-missing` failure, never a fresh
trust-on-first-use.

Exemptions are by **host as well as kind**: `discord`/`community` records and any record
whose URL is on `discord.gg`/`discord.com` are verified by the Aither bot instead, and
Aitherium's own first-party services (e.g. `relay.aitherium.com` rooms) are covered by
our deployment. A `world` record whose URL is a Discord invite is therefore exempt too;
it is not suspended for a backlink the host can never serve.

## What is enforced today

- **NI009**: vouches need `by` and `at`. A submitter cannot vouch for their own entry,
  and nobody can vouch twice.
- **Account age**: the intake bot only processes submissions from GitHub accounts at
  least 30 days old. Younger accounts go to a human (`needs-human`).
- **Untrusted input**: the record id comes from the URL, not the submitter. Every
  field is capped and pattern-checked, and nothing from an issue reaches a shell.
- **Nothing publishes past a failing check.** The Pages build runs the self-test and
  the check first.
- **Owner proof beats impersonation.** A look-alike site cannot serve the real
  domain's `.well-known` file.
- **NI020/NI021**: `state/health.json` is machine-written, but `check.py` still
  validates it (known statuses, well-formed counts, and a baseline that must match the
  fingerprint stamped on the record unless a maintainer explicitly accepted a re-seed)
  so a bad commit is caught. NI022 rejects a post-grace listing that was approved
  without an artifact. (NI011/NI012 belong to the Discord branch.)
- **The re-check writes only `state/health.json`.** It never edits `records/`, and the
  workflow fails if any other file changed. A delist PR does not need to hand-edit the
  state: the next run prunes the entry for a record that no longer exists.

## What comes next

1. **Voucher weight, not voucher count.** Two fresh accounts vouching for each other
   is a ring. Weight each voucher by their own record: merged submissions that stayed
   up, and how old the account is. Trust then flows from a small seed set of known
   maintainers, EigenTrust-style, so a Sybil cluster with no path to the seeds scores
   zero however large it grows.
2. **Decay, finished.** The daily re-check now covers the first half: an entry that
   stops answering, loses its backlink or changes hands is warned, suspended and
   delisted on its own (see above). Still open: lowering the *computed trust tier*
   itself on decay, and showing the last good date next to the tier.
3. **Flags.** A `report` issue form (scam, impersonation, AI-generated fake reviews,
   dead) is reviewed in the open. A confirmed report removes the entry and costs its
   vouchers weight.
4. **Signed identity.** Contributors can link an AitherNet identity, which is
   per-device and consent-scoped, so a vouch can be checked outside GitHub too.
5. **Agents are participants, labelled.** An agent may submit and verify. Its records
   say so (`added_by: agent:<name>`), and an agent's vouch never counts toward tier 3
   on its own.

## What this does not claim

The index does not judge whether a business is honest. It records who vouched, what
the bot could see and whether the owner proved control, then lets the reader weigh
it.
