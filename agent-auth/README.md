# Agent-to-Agent Authentication for a Personal Assistant

A small, working system in which a **personal assistant agent** delegates work
to a **calendar agent** and an **email agent**. Each agent proves who it is to
the others, and each call can do only what policy allows.

The project is built from real standards (OAuth 2.0, JWT, DPoP). What you learn
here applies directly to production systems.

```
                 ┌──────────────────────┐
                 │  Authorization Server │  policy.json: who may call whom,
                 │      (port 8000)      │  with which scopes
                 └──────────────────────┘
                   ▲ 1. signed assertion    │ 2. short-lived, audience-scoped,
                   │    "I am assistant"    ▼    key-bound access token
 you ──► ┌──────────────┐  3. token + fresh DPoP proof  ┌────────────────┐
         │  Assistant   │ ────────────────────────────► │ Calendar agent │ (8002)
         │  (port 8001) │ ────────────────────────────► │  Email agent   │ (8003)
         └──────────────┘                               └────────────────┘
                                                4. verify token, proof, scope
```

---

## Why agent-to-agent auth needs care

The simplest design gives every agent a shared API key. That design breaks down
quickly:

| Problem with shared API keys | What this project does instead |
|---|---|
| A leaked key works forever, everywhere | Tokens last **5 minutes** and work at **one** agent (`aud`) |
| Every caller can do everything | **Scopes** per call, granted from a deny-by-default **policy** |
| A stolen key or token is fully usable | Tokens are **bound to the caller's private key** (DPoP), so a stolen token alone is useless |
| A captured request can be replayed | Every proof has a unique `jti`, and replays are rejected |
| Secrets must be copied to both sides | **Asymmetric keys**: private keys never leave their agent |

This matters more for AI agents than for ordinary services. An LLM-driven
assistant can be manipulated, for example by a prompt injection hidden in an
email it reads. Least privilege limits what a tricked assistant can do. In this
project the assistant can *draft* email but cannot *send* it, however it is
persuaded.

---

## The protocol, step by step

### Step 0: Identity (`a2a_auth/keys.py`)
Each agent has an **Ed25519 key pair**. The public half is registered with the
Authorization Server (AS). A key's ID (`kid`) is its
[RFC 7638 thumbprint](https://www.rfc-editor.org/rfc/rfc7638), a hash of the
public key, so both sides compute the same ID independently.

*Why Ed25519?* It is fast and compact, and it has no parameters you can get
wrong (unlike RSA padding or ECDSA nonces).

### Step 1: The assistant authenticates to the AS (`client.py` → `auth_server.py`)
The assistant signs a short-lived JWT called a **client assertion**
([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523), "private_key_jwt"):

```json
{ "iss": "assistant", "sub": "assistant", "aud": "<AS issuer URL>",
  "iat": 1791076512, "exp": 1791076572, "jti": "<random uuid>" }
```

The AS verifies the signature against the assistant's **registered** public key
and runs these checks:
- `aud` must equal the AS's own issuer ID. An assertion made for a different
  server can't be redirected here.
- The assertion can live at most 60 s, and each `jti` can be used only once
  (replay protection, `replay.py`).
- `algorithms=["EdDSA"]` is fixed on the server side. A token never gets to
  choose its own algorithm, which blocks the classic `alg: none` attack.

### Step 2: The AS applies policy and issues a token
The request names a target (`resource=calendar-agent`,
[RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)) and scopes
(`calendar:read`). The AS checks `config/policy.json`, where anything not listed
is denied, then signs an access token
([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWT format):

```
iss        http://127.0.0.1:8000
sub        assistant
aud        calendar-agent             ← valid at exactly one agent
scope      calendar:read              ← only what was asked for AND allowed
exp        iat + 300                  ← 5 minutes
cnf.jkt    Omwq575G...                ← thumbprint of assistant's key
```

### Step 3: The assistant calls the calendar agent with a DPoP proof
A bearer token is like cash: whoever holds it can spend it. So every request
also carries a **DPoP proof** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)).
This is a fresh JWT, signed with the assistant's private key, that says
"GET http://…/events, right now, with *this* token":

```
Authorization: DPoP eyJ...token
DPoP:          eyJ...proof   { htm: "GET", htu: ".../events", iat, jti, ath: sha256(token) }
```

### Step 4: The calendar agent verifies (`verifier.py`)
It checks three questions, in order:
1. **Is the token genuine?** It must be signed by the AS (the key is fetched
   from the AS's JWKS endpoint and cached), with the right `iss`, `aud` = me,
   and not expired.
2. **Is the caller the token's owner?** The proof's key thumbprint must match
   `cnf.jkt`. The proof must be signed by that key, match this method and URL,
   be fresh, carry an unseen `jti`, and its `ath` must match this token.
3. **Is the action allowed?** The token must carry the endpoint's required
   scope. If it does not, the agent returns 403 `insufficient_scope`.

---

## Hands-on: build it and run it yourself

**1. Set up Python (3.10+)**
```bash
cd agent-auth
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**2. Run the guided demo.** It needs no servers, because all agents run in one
process and still talk real HTTP:
```bash
python scripts/demo.py
```
You'll see the happy path, the decoded contents of a real token, and **six
attacks failing**: a forbidden scope, a bearer token reused without its key, a
stolen token used with a thief's key, a replayed request, a wrong-audience
token, and an unregistered agent.

**3. Run the tests.** There are 15 tests, and each one pins down one security
property:
```bash
pytest -v
```

**4. Run it as four real services**
```bash
python scripts/gen_keys.py         # creates keys/ (gitignored, private keys 0600)
python scripts/run_all.py          # ports 8000-8003; Ctrl+C to stop
```
In a second terminal:
```bash
curl -X POST localhost:8001/schedule-meeting -H 'content-type: application/json' \
     -d '{"title":"Dentist","start":"2026-10-10T09:00","attendees":["me@example.com"]}'
curl localhost:8001/agenda
curl -X POST 'localhost:8001/send-email?to=a@b.c&subject=hi&body=x'   # denied by policy
curl localhost:8002/events                                            # 401: no token
```
FastAPI generates interactive docs at `http://localhost:8001/docs`.

**5. Experiments to try** (the best way to learn this material)
- Add `"email:send"` to the assistant's grants in `config/policy.json`, restart,
  and watch `/send-email` start working. Then remove it again.
- Set `access_token_ttl` in `config.py` to 5 seconds and add a `sleep` to the
  demo to watch the client fetch a fresh token.
- Run `python scripts/gen_keys.py --rotate` while the services are running.
  Callers start failing until you restart, because the AS loaded the public
  keys at startup. How would you design key rotation without downtime? (Hint:
  register two keys per agent during a changeover.)
- Add a new "weather agent": create its module, add it to `config.py` and
  `policy.json`, and generate its keys.

---

## Project layout

```
agent-auth/
├── a2a_auth/
│   ├── keys.py            Ed25519 keys, JWK export, RFC 7638 thumbprints
│   ├── config.py          service ids/URLs, token lifetimes
│   ├── replay.py          one-time jti cache
│   ├── auth_server.py     /token, /.well-known/jwks.json, policy enforcement
│   ├── client.py          AgentClient: get tokens, sign DPoP proofs, call agents
│   ├── verifier.py        AccessTokenVerifier: FastAPI dependency for callees
│   ├── local_network.py   run every agent in-process (demo + tests)
│   └── agents/
│       ├── assistant.py       the orchestrator you talk to
│       ├── calendar_agent.py  calendar:read / calendar:write
│       └── email_agent.py     email:draft / email:send
├── config/policy.json     who may call whom with which scopes
├── scripts/               gen_keys.py, run_all.py, demo.py
└── tests/                 one test per security property
```

---

## Going to production: what's deliberately simplified

| Here | In production |
|---|---|
| Private keys in PEM files | A KMS/HSM or OS keychain, so keys can't be exported |
| In-memory replay cache | A shared store (Redis `SET NX EX`) across replicas |
| Public keys loaded at AS startup | A registration API with key rotation and revocation |
| `http://127.0.0.1` | TLS everywhere (DPoP complements TLS; it doesn't replace it) |
| Assistant endpoints have no user login | Authenticate *you* to the assistant (passkeys / OAuth login) |
| Assistant acts as itself | **Delegation**: use OAuth Token Exchange ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) so tokens say "assistant acting **for Ron**" (`sub`=user, `act.sub`=assistant), and the user's consent caps the scopes |
| Static `policy.json` | A policy engine (OPA/Cedar) with audit logging of every grant |

Alternatives you'll see in the wild: **mTLS** with SPIFFE/SPIRE workload
identities (strong, but it needs certificate infrastructure), and plain
**OAuth client credentials with bearer tokens** (simpler, but weaker against
token theft). This design takes the middle path. It uses standard OAuth plus
DPoP sender-constraining and needs no certificate authority.
