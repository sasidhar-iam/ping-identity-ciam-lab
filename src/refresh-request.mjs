// Tokens are opaque strings. This helper neither validates nor decodes them.
export function refreshRequest(tokenEndpoint, clientId, refreshToken) {
  const endpoint=new URL(tokenEndpoint);
  if(endpoint.protocol!=='https:' || endpoint.username || endpoint.password || endpoint.hash)throw new Error('invalid_token_endpoint');
  if(typeof clientId!=='string'||!clientId.trim())throw new Error('client_id_required');
  if(typeof refreshToken!=='string'||!refreshToken||/[\r\n\0]/.test(refreshToken))throw new Error('invalid_refresh_token');
  return {url:endpoint.href,method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'refresh_token',client_id:clientId,refresh_token:refreshToken}).toString()};
}
