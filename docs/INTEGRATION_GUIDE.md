# Integration guide

This connects an application the same way Finance is connected.

## 1. Client

Create a confidential OpenID Connect client in the `northstar` realm.

- Standard flow enabled. Implicit flow disabled. Direct access grants disabled.
- Redirect URI: `https://app.example/auth/callback` exactly. For this demo, Finance uses `http://localhost:8101/auth/callback`.
- Web origins limited to the application origin.
- A protocol mapper that puts the client id in the access token audience.
- Full scope allowed may stay on for an interactive client so realm and client roles appear in the token. The provisioner client is the exception and must stay off.

Put the client secret in the server environment. Do not ship it to the browser.

## 2. Roles

Create client roles that match a row in `data/permission_matrix.json`, or add a new application block and use the same file from the application. Map a group to those roles in Keycloak. IdentityGate birthright uses the department groups in `data/access_catalog.json`.

## 3. Login

Send the browser to the authorization endpoint with `response_type=code`, `code_challenge_method=S256`, a random state, and a nonce. On the callback, compare state, exchange the code at the token endpoint with the verifier and the client secret, and validate both tokens. `demo-apps/common/oidc.py` is the reference implementation. Store the result in an HttpOnly session. Require a CSRF header on POST.

## 4. Authorisation

On every API route, validate the session and call:

```python
from policy.decision import is_allowed, load_matrix
is_allowed(load_matrix(), "northstar-finance", "payment:approve", roles)
```

Return 401 when there is no session and 403 when the decision is deny. Refresh the token before a sensitive action so session revocation is observed within one request rather than at the 300-second expiry.

## 5. Logout

Redirect to the realm end-session endpoint with `id_token_hint` and the registered post-logout URI. Document that other applications keep their cookies until they contact Keycloak again.

## 6. Provisioning

If the application also needs an account of its own, implement a SCIM subset or consume the outbound connector. Disabling the Keycloak user does not delete that account. The leaver workflow has to call the application and then read the account back.
