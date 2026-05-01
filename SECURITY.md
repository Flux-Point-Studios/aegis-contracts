# Security Policy

## Reporting a vulnerability

**Do NOT file a public GitHub issue for a security finding.**

Email: `security@fluxpointstudios.com`
PGP key: available on request.

For coordinated disclosure, please include:

- A description of the vulnerability and its impact.
- Steps to reproduce, ideally including a transaction body sketch or, if testing on Cardano preprod, the tx hash demonstrating the exploit.
- Suggested remediation, if any.
- Whether you'd like to be credited in the disclosure (we default to crediting unless you ask otherwise).

We commit to:

- Acknowledging receipt within 48 hours.
- Providing an initial assessment within 5 business days.
- Disclosing publicly only after a fix is deployed and you've had an opportunity to verify.

## Scope

The on-chain contracts in this repository (Aiken validators, lib helpers, mint policies) are in scope for vulnerability reports.

The off-chain backend (FastAPI server, monitoring bot, frontend, SDK) is **out of scope for this disclosure channel** because it has not yet been audited and lives in a separate private repository. If you have a finding that crosses both surfaces (e.g., the off-chain code constructs a tx the validators reject in a way that creates a denial-of-service), please report it here and we'll route the off-chain side to the appropriate team.

The Materios cross-chain attestation bridge is also out of scope here — refer to Materios's own security disclosure channel.

## Bounty

A bug-bounty program is being scoped for the post-external-audit / mainnet phase. Until that program is announced, severe findings will be acknowledged with attribution and a discretionary reward at the maintainer's option.

## Severity classification

We use a 5-tier scale aligned with the internal audit report:

- **Critical** — Direct loss of pool funds, or unconditional drain by any actor.
- **High** — Multi-step path to fund loss, or accounting corruption that converges to insolvency under realistic conditions.
- **Medium** — Limited financial impact, capacity or fairness griefing at meaningful cost-to-damage ratio.
- **Low** — Edge-case bugs with bounded impact (e.g., 1-lovelace over-leverage).
- **Info** — Documentation, scope, or process issues; not code-level vulnerabilities.

## Public disclosure timeline

For Critical / High findings, we target:

1. Acknowledgment within 48 hours.
2. Fix designed within 7 days.
3. Fix deployed within 21 days (longer if a redeploy + migration coordination is required).
4. Public disclosure within 90 days of receipt, or when the fix is verified — whichever is later.

For Medium / Low / Info, the timeline is more flexible; we'll align with you on disclosure.
