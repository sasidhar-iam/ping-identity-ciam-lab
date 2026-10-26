import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
export const challenge = verifier => {
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) throw new Error('invalid_verifier');
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
};
export function beginLogin({issuer, clientId, redirectUri}) {
  const base = new URL(issuer);
  if (base.protocol !== 'https:') throw new Error('https_required');
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(32).toString('base64url');
  const nonce = randomBytes(32).toString('base64url');
  const url = new URL('authorize', base.href.endsWith('/') ? base : base.href + '/');
  url.search = new URLSearchParams({client_id: clientId, redirect_uri: redirectUri,
    response_type:'code', scope:'openid profile', code_challenge:challenge(verifier),
    code_challenge_method:'S256', state, nonce}).toString();
  return {url:url.href, transaction:{verifier,state,nonce,createdAt:Date.now()}};
}
export function consumeCallback(params, session, now = Date.now()) {
  const tx = session.transaction;
  delete session.transaction; // Consume once, including failed callbacks.
  if (!tx || now < tx.createdAt || now - tx.createdAt > 300000) throw new Error('expired_transaction');
  const a = Buffer.from(params.state || ''); const b = Buffer.from(tx.state);
  if (a.length !== b.length || !timingSafeEqual(a,b)) throw new Error('invalid_state');
  if (params.error || !params.code) throw new Error('authorization_failed');
  return {code:params.code, verifier:tx.verifier, nonce:tx.nonce};
}
