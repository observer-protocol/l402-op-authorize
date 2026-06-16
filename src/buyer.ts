// Buyer-side enforcement on the lnget payment path (SCOPE §6). Before an agent
// pays an L402 invoice, evaluate its signed, revocable did:key delegation against
// the proposed payment, fail-closed. Composed in front of lnget via a
// vendor-neutral env hook — no Lightning Labs repo changes.
//
// The signed PolicyEvaluationCredential and AT-ARS preimage ingestion are emitted
// by the OP adapter the hook posts to (the same /policy/evaluate surface the WDK
// and mppx engines use); this module is the local, in-process enforcement that
// produces the allow/deny the hook acts on.

import type { DecodedPayment } from './l402.js';
import type { PolicyContext, ResolvedTransfer, RailDef, VerifierConfig } from './core/types.js';
import { verifyCredential, enforceMandate, type Verdict } from './verify.js';

/** chain_id used for the Lightning rail in the verifier config + the mandate's
 * actionScope.allowed_rails. */
export const LIGHTNING_CHAIN_ID = 'lightning';

/** Default Lightning rail definition (sats, 0 decimals). The resolved transfer's
 * own assetSymbol/decimals override this per payment (sats vs Taproot-Asset USDT). */
export function lightningRail(): RailDef {
  return { currency: 'sat', decimals: 0 } as RailDef;
}

export interface L402AuthInput {
  decoded: DecodedPayment;
  /** Evaluation time (ms). Defaults to now. */
  nowMs?: number;
  /** Raw amount already spent today in the payment asset (sats or asset-raw), for
   * the velocity cap. Omit if no velocity counter is maintained — a mandate that
   * carries a velocity cap then fails closed. */
  dailyTotalRaw?: bigint;
  walletId?: string;
}

/** Build the single asset/amount/counterparty view the mandate enforces against,
 * from a decoded L402 payment. Fail-closed: an amount that cannot be established
 * (amountless invoice, or an asset amount with no decimals) is marked
 * unenforceable so the mandate denies under any per-payment / velocity cap. */
function resolvedFromL402(d: DecodedPayment): ResolvedTransfer {
  const recipient = d.counterparty;
  // Taproot-Asset USDT (from the lnget/tapd quote) takes precedence over sats.
  if (d.assetAmount !== undefined && d.assetUnit) {
    if (d.assetDecimals === undefined) {
      return { kind: 'native', assetSymbol: d.assetUnit, recipient, recipientKind: 'wallet', notes: [],
        unenforceable: `Taproot-Asset ${d.assetUnit} amount supplied without decimals — cannot scale against the mandate` };
    }
    return { kind: 'native', assetSymbol: d.assetUnit, amount: BigInt(d.assetAmount), decimals: d.assetDecimals,
      recipient, recipientKind: 'wallet', notes: [] };
  }
  if (d.amountSats === null) {
    return { kind: 'native', assetSymbol: 'sat', recipient, recipientKind: 'wallet', notes: [],
      unenforceable: 'amountless BOLT11 invoice — per-payment amount cannot be established' };
  }
  return { kind: 'native', assetSymbol: 'sat', amount: BigInt(d.amountSats), decimals: 0,
    recipient, recipientKind: 'wallet', notes: [] };
}

/**
 * Authorize (or deny) a proposed L402 payment against the agent's delegation.
 * Runs the full credential verification (did:key issuer, eddsa-jcs-2022 proof,
 * revocation) then the mandate enforcement (per-payment ceiling, counterparty =
 * the L402 origin, velocity). Fail-closed on any miss.
 */
export async function authorizeL402Payment(config: VerifierConfig, input: L402AuthInput): Promise<Verdict> {
  const nowMs = input.nowMs ?? Date.now();
  const credVerdict = await verifyCredential(config, nowMs);
  if (!credVerdict.allow || !credVerdict.cred) return credVerdict;

  const resolved = resolvedFromL402(input.decoded);
  const ctx: PolicyContext = {
    chain_id: LIGHTNING_CHAIN_ID,
    wallet_id: input.walletId ?? 'lnget',
    api_key_id: 'lnget',
    transaction: { to: input.decoded.counterparty },
    timestamp: new Date(nowMs).toISOString(),
  };
  const verdict = enforceMandate(ctx, credVerdict.cred, config, {
    resolvedOverride: resolved,
    ...(input.dailyTotalRaw !== undefined ? { dailyTotalRaw: input.dailyTotalRaw } : {}),
  });
  return { allow: verdict.allow, reason: verdict.reason, notes: [...credVerdict.notes, ...verdict.notes], cred: credVerdict.cred };
}
