// Pure policy model. Caller must supply a verified principal, governed identity links,
// and fresh server-side lookup results. This is not a PingFederate adapter.
export function resolveEntitlements({principal,links,records,requiredSources,clientScopes,requestedScopes,mfa,now}) {
  const sources=new Set(['ldap','ad','db']);
  if(!principal || !sources.has(principal.source) || typeof principal.externalId!=='string' || !Number.isFinite(now))throw new Error('invalid_principal');
  if(!Array.isArray(links)||!Array.isArray(records)||!Array.isArray(requiredSources)||!requiredSources.length||requiredSources.some(x=>!sources.has(x)))throw new Error('invalid_policy');
  if(!Array.isArray(clientScopes)||!Array.isArray(requestedScopes)||[...clientScopes,...requestedScopes].some(x=>typeof x!=='string'))throw new Error('invalid_scopes');
  const matches=links.filter(x=>x.source===principal.source&&x.externalId===principal.externalId);
  if(matches.length!==1 || typeof matches[0].personId!=='string'||!matches[0].personId)throw new Error('unlinked_or_ambiguous_identity');
  const personId=matches[0].personId;
  const linked=links.filter(x=>x.personId===personId);
  if(linked.some(x=>links.filter(y=>y.source===x.source&&y.externalId===x.externalId).length!==1))throw new Error('ambiguous_link');
  const data={};
  for(const source of new Set([...requiredSources,principal.source])){
    const external=linked.filter(x=>x.source===source);
    if(external.length!==1)throw new Error('missing_or_ambiguous_source');
    const found=records.filter(x=>x.source===source&&x.externalId===external[0].externalId);
    if(found.length!==1)throw new Error('lookup_failed');
    const r=found[0];
    if(r.status!=='active')throw new Error('inactive_identity');
    if(!Number.isFinite(r.fetchedAt)||r.fetchedAt>now||now-r.fetchedAt>60)throw new Error('stale_lookup');
    if(!Array.isArray(r.groups)||r.groups.some(x=>typeof x!=='string'))throw new Error('malformed_groups');
    data[source]=new Set(r.groups);
  }
  const has=(source,group)=>data[source]?.has(group)===true;
  const eligible=new Set();
  if(has('ldap','customer-readers')||has('db','accounts-reader'))eligible.add('accounts:read');
  // Privileged approval requires independent AD and business entitlement evidence.
  if(has('ad','payments-approvers')&&has('db','approve-payments')&&mfa===true)eligible.add('payments:approve');
  return {subject:personId,scopes:[...new Set(requestedScopes)].filter(x=>clientScopes.includes(x)&&eligible.has(x)).sort()};
}
