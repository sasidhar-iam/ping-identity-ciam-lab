# Ping Identity CIAM Integration Lab

OAuth request-building examples for future PingFederate, PingOne and Advanced Identity Cloud integrations. These are distinct products; check each provider's configuration and release model.

## Run

Requires Node.js 20 or later:

```sh
npm test
```

## Implemented

- S256 PKCE with random verifier, state and nonce.
- Single-use callback transaction checks and expiry handling.
- A refresh-request builder that treats refresh tokens as opaque strings and form-encodes them without decoding.

The helpers do not contact an identity provider. The refresh request does not apply confidential-client authentication: add the provider-approved authentication method in a trusted backend using an established OAuth/OIDC library. Configure the token endpoint from trusted provider metadata, never user input. Do not log the returned request body because it contains the refresh token.

Store transaction state in a secure server-side session. The callback example supports one transaction per session; use transaction-specific storage for multiple browser tabs. It is not a complete production callback handler.

## Integration acceptance criteria

Configure a licensed test provider, exact redirect URIs and secure client authentication. Add token exchange and ID-token signature/issuer/audience/nonce checks using a maintained library. Test PAR, wrong nonce, code replay, token expiry, key rotation, refresh reuse handling and dependency outages.

No vendor-backed login, token validation or FAPI/CDR certification is claimed. See the [dated release-impact guide](docs/UPGRADE-IMPACT.md) for upgrade considerations, including future cloud token changes.

Read [Contributing](CONTRIBUTING.md), [Security](SECURITY.md) and [MIT License](LICENSE).
