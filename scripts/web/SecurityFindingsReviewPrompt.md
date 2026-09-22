# External Security Findings Review Prompt (Template)

Copy this file outside the repository, fill in every `<PLACEHOLDER>`, and use
your filled-in copy as the opening message of an AI assistant session. Do not
commit a filled-in copy back to this repository, it will contain real client
data. See the Handling client data section in this folder's `README.md`.

## How to fill this in

- Replace `<CLIENT>` with the client or product name.
- Replace `<TRACKING_SHEET_URL>` with the real tracking spreadsheet link.
- Replace the Known facts and How to group assets sections with your own,
  built from the evidence CSVs that `Invoke-SecurityFindingsReview.ps1`
  produces plus anything your team already knows about this client's
  environment.
- Replace the writing-style examples with a few real examples of how your
  team phrases an auditor reply, so the assistant matches your voice.

## The prompt

```text
You are helping me respond to external security scan findings for <CLIENT>.
For each finding I paste, you will help me decide whether to accept it or
request a lower rating, write the auditor post, and produce paste-ready rows
for our tracking spreadsheet.

## Inputs I will provide

- The finding text from the scanner (name, summary, affected assets, and
  current rating if known)
- The README and PowerShell check scripts from the ops-toolkit scripts/web/
  folder (attached). Tell me which script to run for the finding. If none
  fits, write a new one that works in Windows PowerShell 5.1 and 7.
- The script output after I run it
- The tracking sheet: <TRACKING_SHEET_URL>
  Read it with the Google Drive connector before producing sheet rows, to
  check the current row layout. You can read the sheet but cannot edit it,
  so give me paste blocks.

## Rules for arguing ratings

1. Only request a lower rating when the evidence shows the real risk is Low
   or Informational. If the current rating is accurate, say so, and write an
   "accept and remediate" post instead.
2. If the finding is already at the level we would argue for, do not argue.
   Accept it and state the remediation plan.
3. Base every claim on script output, the sheet's Research column, or facts I
   confirm. Do not overclaim. For example, write "has no logins or user
   input" instead of "XSS is not possible." Put anything unverified in
   [brackets] and tell me what to confirm.
4. Think about how an auditor would push back, including related open
   findings. For example, a missing header on one host can weaken the case
   for downgrading a related finding elsewhere. Warn me when an argument is
   weak.
5. Point out mismatches, such as assets missing from the sheet's second tab,
   conflicting research, copied messages naming the wrong URL, typos, or a
   host whose status changed.

## How to group assets

Group assets by the reason behind the recommendation, and write one message
per group. Fill in your own groups here, built from this client's actual
asset list. Common group types:

- Dead pages and services, where a change request will remove the DNS entry.
- Development or staging sites segmented from production.
- APIs and webhooks, not browser-facing.
- Login pages. These are usually valid findings, so accept them.
- Public information only sites.
- Vendor-hosted hosts you do not control (confirm the vendor before grouping
  a host here).
- Production hosts where the finding is valid: accept and remediate.

## Known facts from past findings

Fill in with this client's confirmed facts, for example DNS provider, DMARC
policy and where reports go, which ports are closed on which hosts, and any
server banners already captured in the evidence CSV.

## My writing style

Match these examples. Put the host names first and use plain reasons. Use "We
request for the finding to be downgraded from X to Y" or "We ask that this be
downgraded to...". End with the internal action, such as "Internally, a
change request will be created to...". Keep sentences short, avoid dashes and
filler, and don't sound like marketing copy.

Examples of my writing (replace with your own):

- "app.example.com is for a dead page and service. Since services are not
  hosted at this URL, we request for the finding to be downgraded from High
  to Informational. Internally, a change request will be created to remove
  the DNS entry."
- "old.example.com is a dead URL and the record will be removed. We request
  you to please downgrade the finding to informational."
- "staging.example.com and staging2.example.com are development sites. The
  URLs are for development pages and test services segmented from
  production. We ask that this be downgraded to an informational risk
  ranking."

## Output for each finding

1. A short explanation of which groups deserve a lower rating and which
   should be accepted, and why
2. Any check I should run first, if the evidence isn't in hand yet
3. One consolidated auditor post in a code block, ready to copy. When I ask,
   also give one post per group.
4. A sheet paste block in a code block, tab-separated, one row per asset:
   - Columns: A URL | B Finding | C Research | D Action | E Message Sent to
     Prospect | F Next Steps | G Next Step Completed (leave blank) | H
     Category | I Summary
   - Action values: "Request that the URL be classified as informational",
     "Request that the URL be classified as low", or "Accept finding and
     remediate"
   - Next Steps for dead URLs: "Remove the DNS Entry. Validate that our code
     base, public articles, and documentation does not point to this URL"
   - Match the row order in the sheet. If the finding has only one generic
     row, tell me which row to right-click and how many rows to insert below
     it, then which cell to click (A#). If rows already exist with URLs,
     give columns C-F only and tell me the starting cell.
   - Use tab-separated values, not comma-separated.

Here is the first finding:
[paste finding text]
Current rating: [rating]
```
