// Test/demo issuance helpers for the L402 engine: did:key generation and
// eddsa-jcs-2022 VAC signing. The ENGINE only verifies; this is the issuer/holder
// side tooling (what a Sovereign issuer does server-side, and what tests + the
// demo use). Run standalone, it writes inspectable sample fixtures to ./out/.
import { generateKeyPairSync, sign as edSign, createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function b58(buf) {
  let x = 0n;
  for (const b of buf) x = x * 256n + BigInt(b);
  let o = '';
  while (x > 0n) { o = A[Number(x % 58n)] + o; x /= 58n; }
  for (const b of buf) { if (b === 0) o = '1' + o; else break; }
  return o;
}
function sortKeys(o) {
  if (Array.isArray(o)) return o.map(sortKeys);
  if (o && typeof o === 'object') return Object.keys(o).sort().reduce((a, k) => { a[k] = sortKeys(o[k]); return a; }, {});
  return o;
}
export function jcs(o) { return Buffer.from(JSON.stringify(sortKeys(o)), 'utf8'); }
const sha = (b) => createHash('sha256').update(b).digest();

/** Generate an Ed25519 did:key identity. Returns the DID, the node private
 * KeyObject (for signing), and the verificationMethod id. */
export function makeAgent() {
  const kp = generateKeyPairSync('ed25519');
  const pub = Buffer.from(kp.publicKey.export({ format: 'jwk' }).x, 'base64url');
  const did = 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pub]));
  return { did, privateKey: kp.privateKey, vm: did + '#' + did.slice('did:key:'.length) };
}

/** Issue a signed L402 authorization credential (VAC): X authorized agent to do
 * Y until Z, with a per-payment sat ceiling + an origin allowlist. */
export function issueVac({ issuerDid, issuerPriv, issuerVm, subjectDid, ceilingSats = 100000, allowList = ['api.example.com'], validUntil = '2027-01-01T00:00:00Z' }) {
  const doc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:l402-' + b58(sha(Buffer.from(subjectDid)).subarray(0, 8)),
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    issuer: issuerDid,
    validFrom: '2026-06-01T00:00:00Z',
    validUntil,
    credentialSchema: { id: 'https://observerprotocol.org/schemas/delegation/v2.1.json', type: 'JsonSchema' },
    credentialSubject: {
      id: subjectDid,
      authorizationLevel: 'policy',
      authorizationConfig: { policy: { policy_id: 'l402', rail_preference: ['lightning'] } },
      actionScope: { allowed_rails: ['lightning'], per_transaction_ceiling: { amount: String(ceilingSats), currency: 'sat' } },
      delegationScope: { may_delegate_further: false },
      enforcementMode: 'pre_transaction_check',
      tradingMandate: { unit: 'sat', maxNotionalPerOrder: ceilingSats, counterparty: { allowList } },
    },
  };
  const po = { '@context': doc['@context'], type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: '2026-06-15T00:00:00Z', verificationMethod: issuerVm, proofPurpose: 'assertionMethod' };
  const hashData = Buffer.concat([sha(jcs(po)), sha(jcs(doc))]);
  return { ...doc, proof: { ...po, proofValue: 'z' + b58(edSign(null, hashData, issuerPriv)) } };
}

/** A VerifierConfig pinned to the given issuer did:key. */
export function verifierConfig(issuerDid, dir, credentialPath) {
  return {
    credentialPath: credentialPath ?? join(dir, 'agent-delegation.json'),
    issuerDid,
    schemaAllowlist: ['https://observerprotocol.org/schemas/delegation/v2.1.json'],
    revocation: { maxStalenessHours: 24, onUnreachable: 'cache-then-deny', fetchTimeoutMs: 1500 },
    didCache: { maxStalenessHours: 24 },
    cacheDir: join(dir, 'cache'),
    auditLog: join(dir, 'decisions.jsonl'),
    rails: { lightning: { currency: 'sat', decimals: 0 } },
    allowContractCalls: false,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const here = dirname(fileURLToPath(import.meta.url));
  const out = join(here, 'out');
  mkdirSync(out, { recursive: true });
  const principal = makeAgent();
  const agent = makeAgent();
  writeFileSync(join(out, 'agent-delegation.json'),
    JSON.stringify(issueVac({ issuerDid: principal.did, issuerPriv: principal.privateKey, issuerVm: principal.vm, subjectDid: agent.did }), null, 2));
  writeFileSync(join(out, 'verifier-config.json'), JSON.stringify(verifierConfig(principal.did, out), null, 2));
  console.log('l402 fixtures written to', out, '(agent-delegation.json + verifier-config.json)');
}
