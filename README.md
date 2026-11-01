# IdentityGate

A local identity governance demo for security and IAM engineers: Keycloak handles sign in, and a FastAPI and React console tracks joiner, mover and leaver workflows, access reviews, segregation of duties conflicts and audit evidence for a fictional company.

Portfolio: https://cv.omnitest.dev/

IdentityGate is a local identity governance console for the fictional company Northstar Digital. Keycloak is the identity provider. IdentityGate records lifecycle workflows, access reviews, segregation-of-duties conflicts, audit evidence, and security-control results. Two sample applications, Northstar Finance and Northstar Projects, sign in with OpenID Connect and enforce their own permissions on the server.

## What it answers

An operator can see who a person is, which applications they can reach, which group or direct assignment granted that access, whether the account was provisioned downstream, when they last signed in, and whether a review or departure actually removed the access. Those answers come from Keycloak, the downstream directory, or a stored workflow record.

## Stack

- Keycloak 26.8.1, realm `northstar`, native SCIM at `/realms/northstar/scim/v2`
- PostgreSQL 16 for Keycloak, IdentityGate, and an optional directory database
- FastAPI governance API
- React control centre
- Downstream SCIM directory
- Finance on port 8101 and Projects on port 8102

This is a workstation demonstration. Keycloak runs with `start-dev`. It is not a production deployment and it is not a certification of NIST, ISO, or FedRAMP.

## Start

```bash
python scripts/init_env.py
docker compose up --build -d
docker compose exec backend python -m app.bootstrap
```

Open `http://localhost:5173` and sign in as `elena.vasquez`. The password is `DEMO_USER_PASSWORD` in the generated `.env`. The Keycloak administrator password is `KC_ADMIN_PASSWORD` in the same file. Do not commit `.env`.

| Surface | URL |
| --- | --- |
| IdentityGate | http://localhost:5173 |
| Keycloak | http://localhost:8080 |
| Finance | http://localhost:8101 |
| Projects | http://localhost:8102 |
| Directory health | http://localhost:8103/health |
| API | http://localhost:8000/api/v1/system/health |

Postgres is published on port 5433 so it does not collide with a database already running on the workstation. The containers still talk to Postgres on the internal network.

## Tests

```bash
python -m pytest backend/tests scim-target/test_server.py -q --tb=short
```

Unit tests use an in-memory database and do not call Keycloak. A live SSO check is described in `docs/TESTING.md`.

## What was verified

Checked on 1 November 2026 on Linux with Python 3.12 and Node 20:

| Check | Result |
| --- | --- |
| `pip install "./backend[dev]"` in a fresh venv | installs |
| `ruff check backend policy scim-target demo-apps` | all checks passed |
| `pytest backend/tests scim-target/test_server.py` | 29 passed |
| `frontend`: `npm ci && npm run build` | builds, with a large chunk warning from Vite |
| `python scripts/init_env.py` | writes `.env` with freshly generated demo passwords |
| GitHub Actions `checks` workflow | green on the latest push |

```text
$ python -m pytest backend/tests scim-target/test_server.py -q --tb=short
29 passed, 2 warnings in 2.32s
```

Not run here: the full `docker compose` stack, Keycloak sign in, SCIM provisioning to the directory, and the Finance and Projects apps. The walkthrough in [docs/DEMO_WALKTHROUGH.md](docs/DEMO_WALKTHROUGH.md) describes those steps, but its screens and results were not reproduced for this README.

## Status and limitations

A single developer demonstration, version 0.1, with no real users or customers. Northstar Digital and every person in `data/` are fictional.

- Keycloak runs in `start-dev` mode with demo passwords; do not expose it beyond localhost.
- The unit tests use an in-memory database and never talk to Keycloak, so they cover policy and API logic, not the identity provider integration.
- Control results are evidence that a check ran in this demo, not an audit or certification against NIST, ISO or FedRAMP.

## Layout

`backend/` governance API, `frontend/` control centre, `policy/` shared allow and deny rules, `demo-apps/` Finance and Projects, `scim-target/` downstream directory, `keycloak/realm-config/` realm import, `data/` fictional directory and permission matrix.

Further reading is in `docs/`.

## Licence

MIT. See [LICENSE](LICENSE).
