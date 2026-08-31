# Certified Information Security Assessment Value Check

This note evaluates whether the Certified Information Security assessment platform
suggests useful, independently designed improvements to ops-toolkit's evidence-pack
and reporting scripts.

## Decision

The platform adds modest value as a comparison point for evidence scope, traceability,
and report language. It does not justify turning ops-toolkit into a NIST CSF 2.0 or
ISO/IEC 27001 assessment product.

The useful follow-up is to make the existing technical evidence pack more explicit
about what was observed, across which population, from which artifacts, and with what
limitations. The platform's proprietary methodology, mappings, scoring, prompts, UI,
evidence catalog, and report format should not be copied, adapted, or integrated.

## Investigation boundary

- Reviewed the public assessment page and version 2.5.42.96 user guide on 2026-08-29.
- Opened one anonymous NIST CSF 2.0 assessment and one anonymous ISO 27001 assessment
  using only fictional organizations and a fictional assessor. No client, personal,
  tenant, credential, or sensitive information was entered.
- Reviewed only the product behavior needed to understand its scope and evidence
  expectations. No proprietary question set, mapping, scoring logic, evidence catalog,
  UI, or report layout was copied or transcribed.
- Compared those observations with the 20 custom controls in
  `Export-SecurityControlEvidencePack.ps1`, both scripts under `scripts\logging`, and
  `Export-CoverageReconciliation.ps1`.
- Used the official NIST and ISO overview material to separate framework expectations
  from product-specific choices. NIST describes CSF 2.0 as a non-prescriptive taxonomy
  of outcomes and makes organizational scope, current and target profiles, priorities,
  and action planning part of applying it. ISO describes ISO/IEC 27001 as a holistic,
  risk-based management system spanning people, policies, and technology.

## What already holds up well

- `NotAssessed` is a first-class result and is counted separately from `NotMet`.
  Collector failure, unread state, and an optional collector that did not run do not
  become good news.
- Coverage reconciliation distinguishes an unread authority from an authority that was
  read and returned no matching machine. This is stronger than a simple evidence
  present or absent flag.
- The logging collector measures retained history from the oldest surviving event and
  reports unread or empty history as `Unmeasured`. It does not infer retention from
  configured log size.
- The Defender for Endpoint collector refuses to write a partial paged inventory and
  distinguishes reporting, silent, inactive, and unmeasured devices.
- Raw collector output stays beside the control summary, collector failures are logged,
  and local-only collector scope is called out.
- Controls that cannot honestly be established from configuration, including restore
  testing, incident-response exercises, and training completion, remain
  `NotAssessed` with an attachment request instead of receiving synthetic evidence.

These are worth preserving. In particular, `NotAssessed` should not be replaced by a
single incomplete or zero score. An unread source, an observed control failure, and an
explicitly out-of-scope control have different meanings.

## Evidence-pack gaps found

### Scope and population

- The pack records the operator-supplied targets and their count but does not identify
  the authoritative in-scope population, exclusions, successfully read targets, or
  failed targets for each control.
- `EDR-01` asks whether endpoint protection is running on all endpoints but grades a
  local `Get-MpComputerStatus` reading. The separate Defender management-plane
  inventory and coverage reconciliation are not incorporated into the pack.
- Coverage reconciliation proves whether multiple inventories agree, but it does not
  carry asset owner, business service, criticality, information classification, or an
  approved exclusion reason. Agreement among incomplete sources is still incomplete.

### Evidence traceability and integrity

- A control points to a collector directory, not to the exact artifact and records that
  support the finding.
- The pack does not record the script revision, collector parameters with secrets
  redacted, source system, collection time per artifact, evidence freshness, or a hash
  manifest for the generated files.
- `AssessedAt` reflects control assembly time. It does not distinguish when the source
  state was observed from when the pack was assembled.
- There is no evidence inventory that distinguishes expected, produced, unread,
  operator-supplied, and deliberately out-of-scope evidence.

### Technical observation versus control effectiveness

- `Met` can read as a framework or audit conclusion even though the pack is a
  point-in-time technical snapshot. It cannot establish that a process is documented,
  owned, reviewed, consistently followed, measured, and improved over time.
- Some questions are broader than their evidence. `PATCH-01` asks about a defined
  patch window but reads update health. `CFG-01` asks about a documented configuration
  standard but verifies selected desired-state settings. `MFA-01` asks about enforcement
  while its primary evidence is method registration and enforcement is handled by a
  separate Conditional Access control.
- The current four statuses have no explicit `NotApplicable` outcome. Scope exclusions
  should remain distinct from `NotAssessed`, but only when an operator supplies a
  rationale. They must never be inferred from a collector returning nothing.

### Missing technical evidence areas

- No evidence-pack control establishes the complete asset population before claiming
  estate-wide coverage.
- Endpoint EDR coverage, agent health, silence, and inventory reconciliation exist as
  collectors but are not summarized as evidence-pack controls.
- Local event generation and retention are covered. Delivery to central storage,
  successful ingestion, queryability, protected access, time synchronization, alert
  review, and escalation are not established.
- Windows update health is not a vulnerability-management program. There is no evidence
  for vulnerability discovery, prioritization, exceptions, or remediation against an
  approved window.
- The pack has intentionally narrow technical coverage of governance, risk treatment,
  policy lifecycle, supplier risk, people, physical security, secure development, data
  lifecycle, incident handling, and recovery. That is acceptable if the report says it
  is a technical evidence supplement rather than a comprehensive assessment.

## Candidate controls worth considering

These are independent ops-toolkit control concepts, not adaptations of the platform's
control set or mappings.

- `AST-01`: Is the in-scope endpoint population defined and reconciled across every
  required authority, with unread authorities and approved exclusions explicit?
- `EDR-03`: Does the EDR management plane show that the expected endpoint population is
  onboarded, healthy, and reporting within the operator's threshold?
- `LOG-03`: Are required endpoint events reaching the intended central destination and
  remaining queryable for the required period?
- `LOG-04`: Are clock synchronization, log access, integrity protection, alert review,
  and escalation evidenced rather than inferred from local channel configuration?
- `VULN-01`: Are vulnerabilities identified, risk-prioritized, and remediated or
  formally excepted within an approved window?
- `EVI-01`: Can each control result be traced to dated source artifacts, collection
  context, coverage, limitations, and integrity hashes?

`AST-01`, `EDR-03`, and `EVI-01` can mostly reuse collectors and report machinery that
already exist. `LOG-03`, `LOG-04`, and `VULN-01` need named data sources before they are
implementable and should not begin as generic abstractions.

## Report improvements worth considering

- Open with a scope and limitations statement that calls the pack a point-in-time
  technical evidence snapshot, not a NIST maturity rating, ISO conformity decision,
  audit opinion, certification-readiness report, or substitute for assessor judgment.
- Replace or qualify `Met` with language such as `Evidence supports` or `Observed as
  configured` so the result does not imply organization-wide process effectiveness.
  Keep `NotMet`, `Partial`, and `NotAssessed` meanings distinct during any terminology
  change.
- Add per-control fields for intended population, attempted, observed, failed,
  excluded with rationale, evidence source, observed time, freshness, and limitations.
- Add an evidence manifest containing relative artifact paths and SHA-256 hashes, plus
  the ops-toolkit revision and redacted invocation context.
- Split the executive summary into known findings, partial observations, unassessed
  controls, and collection failures. Unknowns should remain visible beside known gaps,
  not be absorbed into a score.
- Link a finding to the exact collector artifact and supporting rows rather than only
  to the collector directory.
- Allow explicit operator-supplied attachments and scope decisions without treating
  an attachment's existence as proof that its contents are effective.
- Report run-over-run change as evidence freshness and posture movement, without
  converting two snapshots into a maturity score.

## What should not be pursued

- Do not build a clone or integration of the Certified Information Security platform.
- Do not copy or adapt its methodology, framework mappings, scoring, maturity or
  conformance rubrics, question text, evidence catalog, prompts, UI, or report format.
- Do not build a full NIST CSF 2.0 assessment, ISO/IEC 27001 conformity assessment,
  Statement of Applicability authoring tool, auditor override workflow, or certification
  readiness claim inside ops-toolkit.
- Do not assign NIST maturity or ISO conformity from automated configuration evidence.
- Do not treat absent evidence as a failed control, a zero score, or a reason to infer
  non-applicability. Preserve `NotAssessed`; add `NotApplicable` only through an explicit,
  justified scope decision.
- Do not send client or environment evidence to an external assessment site or add an
  upload/export integration. The value identified here is local report design, not data
  exchange.
- Do not create generic SIEM, vulnerability-platform, backup, supplier, policy, or GRC
  connectors before a real data source and operator need exist.

## User-story recommendation

Jon approved this story on 2026-08-30, and it is implemented in
`Export-SecurityControlEvidencePack.ps1` with synthetic and local integration coverage:

> As an operator assembling a security evidence pack, I want every control result to
> state its actual population, evidence provenance, freshness, and limitations, so that
> a reviewer can distinguish a supported technical observation from a partial or
> unassessed estate claim.

Suggested acceptance conditions:

- Given synthetic collector output, when a pack is built, then each control records
  intended scope, attempted and observed population, failed reads, exclusions with
  reasons, exact evidence artifacts, observation time, limitations, and integrity
  hashes.
- Given an unread required source, when the pack is summarized, then the affected
  result remains `NotAssessed` and no score or wording presents it as a pass.
- Given Defender management-plane output and at least two required inventory
  authorities, when endpoint coverage is reported, then the result uses those sources
  rather than a local Defender reading alone.
- Given a completed pack, when a reviewer opens the summary, then it explicitly states
  that it is technical evidence and makes no NIST maturity, ISO conformity, audit, or
  certification claim.

`LOG-03`, `LOG-04`, and `VULN-01` remain candidate backlog items until a named source
can be tested. The implementation does not add framework mappings, scoring, prompts,
UI, or report-format elements from the assessed platform.

## Sources

- [Certified Information Security assessment platform](https://www.certifiedinfosec.com/assessments),
  accessed 2026-08-29.
- [Certified Information Security Multi-Framework Assessment User Guide, version 2.5.42.96](https://www.certifiedinfosec.com/media/com_cisassess/docs/CIS%20Multi-Framework%20Assessment%20User%20Guide.pdf),
  accessed 2026-08-29.
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20),
  published 2024-02-26.
- [NIST SP 1301, Creating and Using Organizational Profiles](https://csrc.nist.gov/pubs/sp/1301/final),
  published 2024-02-26.
- [ISO/IEC 27001:2022 overview](https://www.iso.org/standard/27001), accessed
  2026-08-29.
