# @observer-protocol/l402-op-authorize

Observer Protocol's fourth enforcement engine: **authorization for L402 / Lightning agentic
commerce**, over the `lnget` (buyer) and Aperture (seller) seam of Lightning Labs' L402 stack.
Composes via a vendor-neutral env hook, with **no changes to any Lightning Labs repo**.

Same vendored verification core as [`ows-op-verify`](https://github.com/observer-protocol/ows-op-policy)
(x402/EVM, Solana) and [`mppx-op-account`](https://github.com/observer-protocol/mppx-op-account)
(MPP/Tempo). Only the decoder changed: here it speaks L402 / BOLT11 / Taproot-Asset USDT.

## What it does
- **Buyer side (`lnget`):** before paying an L402 invoice, verify the agent's signed, revocable
  `did:key` delegation against the proposed payment (amount in sats or Taproot-Asset USDT, the
  L402 origin as counterparty, per-payment + velocity limits), **fail closed**, then emit a
  signed `PolicyEvaluationCredential` and ingest the preimage into AT-ARS.
- **Seller side (Aperture), the wedge:** verify a **holder-bound** authorization credential — a
  W3C Verifiable Presentation signed by the subject `did:key` over a server challenge — before
  serving. This is the binding macaroons structurally cannot provide.

## Authorization, not personhood
Credentials assert *"X authorized this agent to do Y, valid until Z"* (X = a human, org, or
Sovereign certification). `did:key` subject/issuer, `eddsa-jcs-2022` proofs,
`BitstringStatusListEntry` revocation. No personhood, no trust-list, no new crypto.

## Install
```sh
npm install @observer-protocol/l402-op-authorize
```
Zero runtime dependencies. Node >= 18.

## Buyer side — drop in front of lnget (no Lightning Labs code changes)
Run the OP hook next to lnget and point lnget's `PRE_PAYMENT_HOOK_URL` at it:
```sh
node examples/hook-server.mjs            # serves POST /hook
```
```sh
curl -s -X POST http://127.0.0.1:8787/hook -H 'content-type: application/json' \
  -d '{"origin":"https://api.example.com/paid","invoice":"lnbc500u1..."}'
# → {"decision":"allow"|"deny","reason":"..."}   (HTTP 200 allow, 402 deny)
```
Or embed the handler directly:
```ts
import { handleL402PaymentHook } from '@observer-protocol/l402-op-authorize';
const { decision, reason } = await handleL402PaymentHook(config, {
  origin: 'https://api.example.com/paid', invoice: 'lnbc500u1...',
  // Taproot-Asset USDT: asset: { amount: '5000000', unit: 'USDT', decimals: 6 }
});
```
`config` is a `VerifierConfig` pinned to the principal's `did:key` (`issuerDid`), with the agent's
signed delegation at `credentialPath`, `schemaAllowlist`, and `rails: { lightning: { currency:'sat', decimals:0 } }`.
Out-of-mandate, over-limit, expired, revoked, or unestablishable amounts **fail closed** — lnget never pays.

## Seller side — Aperture, holder-bound (the wedge)
```ts
import { issueChallenge, verifyPresentationForServing } from '@observer-protocol/l402-op-authorize';
const ch = issueChallenge('api.example.com');                 // give to the requester
// agent returns a Verifiable Presentation signed by its subject did:key over ch.challenge
const d = await verifyPresentationForServing(config, vp, { challenge: ch.challenge, domain: ch.domain });
if (d.serve) serve(); else refuse(d.reason);
```
The agent builds the VP with `signPresentation({ credential, holderDid, holderPrivateKey, challenge })`.
A bare credential (no holder proof), a replayed challenge, a credential whose subject is not the
presenter, or an expired/revoked credential are all **refused**. This is the binding macaroons cannot give.

## Why holder binding (the §8 finding)
L402 tokens are bearer instruments and the agent never signs with its `did:key` in the native flow, so
a presented credential with no proof-of-possession would be replayable. The seller side requires a
holder-signed Verifiable Presentation over a challenge — standard W3C, no new crypto. Details:
[`docs/SPIKE-FINDING.md`](docs/SPIKE-FINDING.md). Scope + boundaries: [`docs/SCOPE.md`](docs/SCOPE.md),
[`docs/SUPPORT-MATRIX.md`](docs/SUPPORT-MATRIX.md).

## Develop
```sh
npm test                  # typecheck + build + 12 conformance cases (6 buyer, 6 seller)
npm run check:core-sync   # vendored core must be byte-identical to ows-op-verify
node demo/scenes.mjs      # the self-narrating buyer→seller demo
```

MIT.
