# SSO and OpenID Connect

All three browser applications use the authorization code flow with PKCE S256.

| Client | Redirect | Audience |
| --- | --- | --- |
| identitygate | http://localhost:5173/api/v1/auth/callback | identitygate-api |
| northstar-finance | http://localhost:8101/auth/callback | northstar-finance |
| northstar-projects | http://localhost:8102/auth/callback | northstar-projects |

Access tokens last 300 seconds. Keycloak's access token for this realm includes `preferred_username` and may omit `sub`; the ID token carries `sub`. IdentityGate verifies the signature, issuer, audience, and expiry of both, and rejects the pair when the usernames differ. Refresh tokens rotate. The API and the sample applications refresh before expiry. Finance approval and Projects administration refresh immediately before the privileged call, so a revoked Keycloak session fails that action even if a local access token has not yet expired.

Verification checks the signature against the realm JWKS, algorithm RS256 or ES256, issuer, audience, expiry, and the login nonce on the ID token. Unsigned tokens and the `none` algorithm are rejected. The decoded payload is never treated as proof of authentication.

## Session cookies

IdentityGate sets `ig_session`. Finance sets `finance_session`. Projects sets `projects_session`. Cookies are HttpOnly and SameSite=Lax. `COOKIE_SECURE` is false only for this HTTP demonstration. State-changing cookie requests require `X-CSRF-Token`.

## Single sign-on

1. Sign in at Finance as `elena.vasquez`.
2. Open Projects. Keycloak still has the browser session, so Projects completes the code flow without asking for the password again.
3. Finance allows report creation for her analyst role and denies payment approval.
4. Projects allows a project update because her time-boxed contributor role is still present, and denies project administration.

Signing out of Finance ends the Keycloak SSO session for that logout request. Projects keeps its own cookie until the next refresh or privileged call, which then fails. This demonstration does not claim front-channel single logout across every application.

Disabling a user, revoking Keycloak sessions, and waiting for already issued access tokens to expire are three different operations. Downstream accounts are disabled separately by the leaver workflow.
