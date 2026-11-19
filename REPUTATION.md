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
| 2 | owner-proven (Discord) | `discord-bot`: the Aither bot is IN the server and observed the requester hold Manage Server when they asked | control of the server, checked by the bot inside it |
| 3 | vouched | tier 1+ AND two distinct people, other than the submitter, vouched | two real, aged accounts that are willing to sign |

### Why a Discord stamp ranks with owner-proven

A Discord server cannot serve `https://<host>/.well-known/aithernet.json`: it has no
host of its own. What it has is an invite, and the same thing a site has: someone who
controls it. The Aither bot is installed *in* the server. When a manager asks to be
listed, the bot checks that the person making the request holds **Manage Server** in
that guild, at that moment. That observation is the Discord equivalent of reading the
`.well-known` file from the owner's own host: a stranger cannot make another server's
manager press the button, and the bot can only be in a server its manager invited it
to.

So a `discord-bot` stamp carries who observed it and for whom:

```json
"validated": {
  "at": "2026-11-18", "by": "aithernet-bot", "method": "discord-bot",
  "guild": "123456789012345678", "requested_by": "discord:987654321098765432"
}
```

**NI012** refuses that stamp unless it is exactly those five keys, the guild is a real
server id that equals `listing.guild`, and `requested_by` names a Discord user. It also
refuses a Discord record whose proof is anything else — there is no `owner-asserted`
tier: a claim in a file is not evidence. And the stamp is only accepted on a record
filed by the account that runs the bot (`DISCORD_BOT_SUBMITTERS`, today
`aither-wzns`), so `provenance.added_by` must be that account's `github:` identity.

**The door is authenticated, not the text.** The intake mints the stamp only for an
issue authored by an account in `DISCORD_BOT_SUBMITTERS`; GitHub sets
`issue.user.login` itself, so only that account's token can author such an issue and a
`discord` issue typed by anyone else is refused. The "Submit a site" form no longer
offers the kind, and it no longer carries the three Discord fields: the Connect intake's
drain files them for the bot. That is the artifact a stranger cannot produce — the
issue authored by the bot's account — not a string in a form.

**NI011/NI010** refuse a Discord record whose `url` is not a `discord.gg` /
`discord.com/invite` permanent invite, and a listing that carries anything beyond the
guild and an optional member band. That is now a hard rule, not a claim: a Discord
listing with a description, email, phone or address is a finding, so no free text and
no personal data can reach the record, the entry page or `index.json`.

`verify.py` re-resolves the invite through `https://discord.com/api/v10/invites/<code>`
(public, no token). The public invite API exposes no requester and no permissions, so
that check records **liveness** under `provenance.checked` and never moves the
attestation date; it marks the entry `stale` when the invite stops resolving or names a
different guild. `verify.py --discord-attest` is the check that can re-derive the
proof: with `DISCORD_BOT_TOKEN` it asks Discord whether the bot is in the guild and
whether `requested_by` holds Manage Server, writes the stamp only then, and marks it
`stale` when the requester does not.

The residual limit is stated plainly: without a bot token configured, CI cannot
re-derive Manage Server for a *hand-written* pull request that claims the stamp. Such a
pull request is caught by two visible contradictions — its author is not the account in
`added_by`, and NI012 refuses any other `added_by` — and a maintainer can confirm it
with `verify.py --discord-attest` before merging. The automated door has no such gap:
the bot's own issue is the proof. What the index never does is publish more than the
manager chose: an invite, a server id, tags, a member band. The requesting manager's
Discord user id stays in the record file as the proof and is never federated to
`index.json`, an entry page or `llms.txt`.


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
  domain's `.well-known` file, and a Discord stamp is minted only for an issue authored
  by the bot's own account (NI012 also refuses any other `added_by`).
- **Personal data never federates.** A Discord listing is the guild id and an optional
  band, and nothing else (NI010). The requesting manager's user id is the proof in the
  record file and is never copied into `index.json` or a page.

## What comes next

1. **Voucher weight, not voucher count.** Two fresh accounts vouching for each other
   is a ring. Weight each voucher by their own record: merged submissions that stayed
   up, and how old the account is. Trust then flows from a small seed set of known
   maintainers, EigenTrust-style, so a Sybil cluster with no path to the seeds scores
   zero however large it grows.
2. **Decay.** `verify.py --stamp` runs on a schedule. An entry that stops answering
   drops to tier 0 and shows its last good date. Abandoned or flipped domains lose
   trust on their own.
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
