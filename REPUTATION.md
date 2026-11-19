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
server id that equals `listing.guild`, and `requested_by` names a Discord user. **NI011**
refuses a Discord record whose `url` is not a `discord.gg` / `discord.com/invite`
permanent invite, and a listing that carries anything beyond the guild and an optional
member band (no member lists, no personal data). `verify.py` re-resolves the invite
through `https://discord.com/api/v10/invites/<code>` (public, no token) and marks the
entry `stale` when the invite stops resolving or names a different guild.

The residual limit is stated plainly: the index records that the bot made the
observation. A forged issue could claim a guild id and manager id, so the listed facts
are only as good as the single door the bot files through, reviewed like every other
contribution. What it never does is publish more than the manager chose: an invite, a
server id, tags, a member band.


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
