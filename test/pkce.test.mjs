import {test} from 'node:test';
import assert from 'node:assert/strict';
import {challenge,beginLogin,consumeCallback} from '../src/pkce.mjs';
test('RFC 7636 known S256 vector',()=>assert.equal(challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'));
test('reject short verifier',()=>assert.throws(()=>challenge('short')));
const login=()=>beginLogin({issuer:'https://id.example.test/tenant/',clientId:'demo',redirectUri:'https://app.example.test/callback'});
test('authorization request uses code S256 and fresh state',()=>{const a=login(),b=login();const u=new URL(a.url);assert.equal(u.searchParams.get('code_challenge_method'),'S256');assert.equal(u.searchParams.get('response_type'),'code');assert.notEqual(a.transaction.state,b.transaction.state);});
test('valid callback consumed once',()=>{const s={transaction:login().transaction};const p={state:s.transaction.state,code:'sample'};assert.equal(consumeCallback(p,s).code,'sample');assert.throws(()=>consumeCallback(p,s));});
test('state mismatch consumes transaction',()=>{const s={transaction:login().transaction};assert.throws(()=>consumeCallback({state:'wrong',code:'x'},s),/invalid_state/);assert.equal(s.transaction,undefined);});
test('expired callback',()=>{const s={transaction:login().transaction};assert.throws(()=>consumeCallback({},s,s.transaction.createdAt+300001),/expired/);});
test('provider error rejected',()=>{const s={transaction:login().transaction};assert.throws(()=>consumeCallback({state:s.transaction.state,error:'access_denied'},s));});
test('insecure issuer rejected',()=>assert.throws(()=>beginLogin({issuer:'http://id.example.test'})));

test('verifier accepts both length boundaries', () => {
  assert.equal(challenge('a'.repeat(43)).length, 43);
  assert.equal(challenge('a'.repeat(128)).length, 43);
});
test('verifier rejects overlength and forbidden characters', () => {
  for (const value of ['a'.repeat(129), 'a'.repeat(42) + ' ', 'a'.repeat(42) + 'é']) {
    assert.throws(() => challenge(value), /invalid_verifier/);
  }
});
test('same-length incorrect state is rejected', () => {
  const s = {transaction: login().transaction};
  const wrong = (s.transaction.state[0] === 'A' ? 'B' : 'A') + s.transaction.state.slice(1);
  assert.throws(() => consumeCallback({state: wrong, code: 'sample'}, s), /invalid_state/);
  assert.equal(s.transaction, undefined);
});
test('missing authorization code consumes transaction', () => {
  const s = {transaction: login().transaction};
  assert.throws(() => consumeCallback({state: s.transaction.state}, s), /authorization_failed/);
  assert.equal(s.transaction, undefined);
});
test('future-dated transaction is rejected', () => {
  const s = {transaction: login().transaction};
  assert.throws(() => consumeCallback({state: s.transaction.state, code: 'sample'}, s, s.transaction.createdAt - 1), /expired_transaction/);
});
test('callback at the five-minute boundary preserves exchange fields', () => {
  const tx = login().transaction;
  const result = consumeCallback({state: tx.state, code: 'sample'}, {transaction: tx}, tx.createdAt + 300000);
  assert.deepEqual(result, {code: 'sample', verifier: tx.verifier, nonce: tx.nonce});
});
test('authorization URL preserves issuer path and registered redirect URI', () => {
  const {url, transaction} = login();
  const parsed = new URL(url);
  assert.equal(parsed.pathname, '/tenant/authorize');
  assert.equal(parsed.searchParams.get('redirect_uri'), 'https://app.example.test/callback');
  assert.equal(parsed.searchParams.get('code_challenge'), challenge(transaction.verifier));
  assert.equal(parsed.searchParams.get('nonce'), transaction.nonce);
});
