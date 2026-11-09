# Wallet Provider Certificate Use: WIA and KA Carriage in Issuance (ETSI TS 119 472-3)

## Overview

This document specifies how a Wallet Unit conveys its **Wallet Instance Attestation (WIA)** and **Key Attestation (KA)** to a PID or Attestation Provider during issuance, and how the Wallet Provider's certificate in the Trusted List of Wallet Providers is used to validate them.

**Verified against:** ETSI TS 119 472-3 **V1.1.1 (2026-03)**.

The direction here is the inverse of the verifier and issuer cases. The Wallet Provider's certificate is **never presented to the wallet**: the wallet presents attestations *signed with it*, and the **issuer** validates them against the Trusted List of Wallet Providers.

| Entity | Certificate travels | Validated by |
|---|---|---|
| Verifier | verifier → wallet (`x5c` / `x5chain`, `verifier_info`) | the wallet |
| PID/EAA Provider | provider → wallet (`x5c` in signed metadata, `issuer_info`) | the wallet |
| **Wallet Provider** | **wallet → issuer** (WIA, KA signed with it) | **the issuer** |

> ### Terminology warning — "WUA" means two different things
>
> | Source | "WUA" means |
> |---|---|
> | [`task1-use-cases/terms-and-entities.md:47`](https://github.com/webuild-consortium/wp4-trust-group/blob/main/task1-use-cases/terms-and-entities.md) (ARF v3.0.0 Topic 9) | **umbrella term** covering WIA **and** KA |
> | ETSI TS 119 472-3 cl. 3.1 | a **specific artefact**: *"JWT signed by the Wallet Provider that describes the components of the Wallet Unit"* — and per **CRED-REQ-4.6.1.2-05** it *"shall be a key attestation in JWT format as specified in clause D.1 of OpenID4VCI"* |
>
> So **472-3's "WUA" is the ARF's "KA"**. This document uses **KA (= 472-3 WUA)** wherever the spec says WUA, and quotes the spec's wording verbatim in requirement text. Anyone mapping requirements across the two vocabularies must account for this collision.

---

## Normative References

| Reference | Document |
|-----------|----------|
| ETSI TS 119 472-3 V1.1.1 (2026-03) | Profiles for Electronic Attestation of Attributes; Part 3: Profiles for issuance of EAA or PID |
| ETSI TS 119 412-6 | Certificate profile requirements for PID, Wallet, EAA, QEAA and PSBEAA providers (clause 5) |
| ETSI TS 119 602 | Trusted Lists (LoTE); **Annex E, Table E.3** — Wallet Providers list |
| EUDI Wallet **TS03** | Specification of Wallet Unit Attestations used in issuance of PID and EAA (reference `[i.2]` in 472-3) |
| OpenID4VCI 1.0 | **Appendix E** (attestation-based client authentication), **Annex D.1** (key attestation), clause 3.5 (Authorisation Code Flow) |
| IETF draft-ietf-oauth-attestation-based-client-auth-07 (Sept 2025) | `OAuth-Client-Attestation` (reference `[5]` in 472-3) |
| OpenID4VC-HAIP | reference `[1]` in 472-3 |
| NIST SP 800-38D | `A128GCM`, `A256GCM` |
| ARF v3.0.0 | Topics 9, 31, 38; ISSU_19, ISSU_21, ISSU_28, ISSU_30, ISSU_30a; WPNot_02 |

---

## 1. The certificate

One **Wallet Solution sign/seal certificate** per Wallet Solution. Per [`certificate-profiles-pid-wallet-eaa-qeaa-psbeaa-providers-etsi-ts-119-412-6.md`](https://github.com/webuild-consortium/wp4-trust-group/blob/main/task3-x509-pki-etsi/certificate-profiles-pid-wallet-eaa-qeaa-psbeaa-providers-etsi-ts-119-412-6.md):

- a distinct **ECDSA P-256** key pair per Wallet Solution; the key pair and certificate **MUST NOT** be reused for another solution
- `keyUsage`: one and only one of Type A, B, C or F (TS 119 412-6 cl. 4.4.1)
- `qcStatements`: `QcType` = `0.4.0.194126.1.2` (`id-etsi-qct-wal`)
- `subjectAltName` REQUIRED; a URI in it is **contact information**, not the Wallet Solution identifier (changed by `6ad1ca5`, PR #148)

**Where it lives:** it *is* the trust anchor. On the Wallet Providers LoTE it is the `ServiceDigitalIdentity` of the
`http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance` service for the solution named by `ServiceName`
(TS 119 602 Annex E, Table E.3). Notified **MS → EC, no Registrar** (GenNot_01, WPNot_02); the Commission compiles the list (WPNot_04/_05). Per EC TS2 §2.4 the anchor is the signing chain itself, not a CA above it.

**What it signs:** the Wallet Solution's **WIA** and **KA**, with `ES256`. Optionally the Token Status Lists for `client_status` (WIA) and `key_storage_status` (KA); if a distinct revocation key is used, its certificate becomes the `ServiceDigitalIdentity` of the `…/SvcType/WalletSolution/Revocation` service (WPNot_02).

The Wallet Solution identifier on the list is `ServiceName` together with `ServiceUniqueIdentifier`; TS03 conveys the solution name in the WIA `wallet_name` claim.

---

## 2. WIA — carried as `OAuth-Client-Attestation`

Applies only to Providers implementing the Authorisation Code Flow (**AUTH-REQ-4.4.1-01**, OpenID4VCI cl. 3.5).

### 2.1 Pushed Authorisation Request (clause 4.4.2)

| Requirement | Text |
|---|---|
| **AUTH-REQ-4.4.2-01** | The Pushed Authorisation Request **shall** include the WIA as an **`OAuth-Client-Attestation`** parameter, as specified in Appendix E of OpenID4VCI and draft-ietf-oauth-attestation-based-client-auth-07. |
| **AUTH-REQ-4.4.2-02** | The PAR **shall** include a **Proof-of-Possession** of the public key included within the **`cnf`** claim. |

> **NOTE 2 (spec):** per TS03, WIAs are expected to have a **time-to-live of less than 24 hours** — `exp − iat < 24 h`.

WIA contents: EUDI Wallet **TS03 section 2.3.3**.

### 2.2 Token Request (clause 4.5.1)

| Requirement | Text |
|---|---|
| **TOKEN-REQ-4.5.1-01** | The Token Request **shall** include the WIA as an **`OAuth-Client-Attestation`** parameter (OpenID4VCI Appendix E; draft-ietf-oauth-attestation-based-client-auth-07). |
| **TOKEN-REQ-4.5.1-02** | The Token Request **shall** include a **Proof-of-Possession** of the public key in the `cnf` claim. |

The WIA is sent at **both** endpoints, not once.

### 2.3 Processing (clauses 4.4.3 and 4.5.2)

Identical triplet at both endpoints:

| PAR | Token | Check |
|---|---|---|
| **AUTH-REQ-PROC-4.4.3-01** | **TOKEN-REQ-PROC-4.5.2-01** | the JWT signature **shall** verify **under the Wallet Provider's public key as found on the Trusted List of Wallet Providers** |
| **-02** | **-02** | the WIA **shall** not have expired |
| **-03** | **-03** | the Proof-of-Possession signature **shall** verify under the public key in the WIA's `cnf` claim |

**TOKEN-REQ-PROC-4.5.2-04**: refresh tokens for credential refresh **may** be supported, with a security assessment (the spec notes the Provider cannot assume how or where the wallet stores them).

---

## 3. KA (472-3 "WUA") — carried in the Credential Request

### 3.1 Choice of mechanism (clause 4.6.1.1)

| Requirement | Text |
|---|---|
| **CRED-REQ-4.6.1.1-01** | If the PID/EAA is cryptographically bound to the device, the Credential Request **shall** include the `proofs` parameter. |
| **CRED-REQ-4.6.1.1-02** | `proofs` **shall** contain **either** the `jwt` child member **or** the `attestation` child member. |

The difference is proof of possession:

| Mechanism | What the wallet proves |
|---|---|
| `proofs` → `jwt` | possession of the private key(s) for the public key(s) the credential will be bound to |
| `proofs` → `attestation` | attestation of the public key(s) only — **no** proof of possession (spec NOTE) |

### 3.2 `proofs` → `jwt` (clause 4.6.1.2)

| Requirement | Text |
|---|---|
| **CRED-REQ-4.6.1.2-01** | The `jwt` JSON array member **shall** have **1** element. |
| **-02** | That element **shall** contain the `nonce` claim in its JWT Body, obtained from the Provider's **Nonce Endpoint**. |
| **-03** | That element **shall** contain the **`key_attestation`** parameter in the **Protected Header**. |
| **-04** | The `key_attestation` parameter **shall** be the KA, **signed by the Wallet Provider**. |
| **-05** | The KA **shall** be a key attestation in JWT format as specified in **clause D.1 of OpenID4VCI**. |
| **-06** | The **`attested_keys`** claim **shall** contain one or more public keys owned by the Wallet Unit. |
| **-07** | The `jwt` element **shall** be signed by the Wallet Unit using the private key corresponding to the public key in the **first element** of `attested_keys`. |

KA contents: EUDI Wallet **TS03 section 2.3.4**.

### 3.3 `proofs` → `attestation` (clause 4.6.1.3)

| Requirement | Text |
|---|---|
| **CRED-REQ-4.6.1.3-01** | The `attestation` array member **shall** contain **only one** element. |
| **-02** | That element **shall** contain the `nonce` claim in its JWT Body from the Nonce Endpoint. |
| **-03** | That element **shall be** the KA. |

### 3.4 Processing (clause 4.6.2)

With `proofs` → `jwt`:

| Requirement | Check |
|---|---|
| **CRED-REQ-PROC-4.6.2.1-01** | the `key_attestation` signature **shall** verify **under the Wallet Provider's public key as found on the Trusted List for Wallet Providers** |
| **-02** | the `jwt` element's signature **shall** verify under the public key in the **first position** of `attested_keys` |
| **-03** | the `jwt` element **shall** include a valid `nonce` from the Provider's Nonce endpoint |
| **-04** | the Provider **shall** generate **as many credentials as elements** in `attested_keys` |
| **-05** | each credential **shall** be bound to one of the `attested_keys` public keys |
| **-06** | there **shall not** be two credentials bound to the same public key |

With `proofs` → `attestation`: **CRED-REQ-PROC-4.6.2.2-01…04** — the same, minus the possession check (`-02` above).

---

## 4. Examples

### 4.1 Pushed Authorisation Request

```http
POST /par HTTP/1.1
Host: issuer.example.eu
Content-Type: application/x-www-form-urlencoded
OAuth-Client-Attestation: eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QiLCJ4NWMiOlsiTUlJQ3hEQ0MuLi4iXX0.
                          eyJpc3MiOiJodHRwczovL2t1YmUud2FsbGV0LmRldi50cml2ZXJpYS5pbyIsInN1YiI6Ii4uLiIsIndhbGxldF9uYW1lIjoiVHJpdmVyaWEgV2FsbGV0IChEZXYgRW52aXJvbm1lbnQpIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ii4uLiIsInkiOiIuLi4ifX0sImlhdCI6MTc5MzAwMDAwMCwiZXhwIjoxNzkzMDQzMjAwfQ.
                          <signature by the Wallet Solution sign/seal key>
OAuth-Client-Attestation-PoP: eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiIuLi4iLCJhdWQiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmV1IiwianRpIjoiLi4uIiwiaWF0IjoxNzkzMDAwMDAxfQ.
                          <signature by the private key in cnf.jwk>

response_type=code&client_id=...&scope=eu.europa.ec.eudi.pid.1&code_challenge=...&code_challenge_method=S256
```

Decoded WIA body (TS03 §2.3.3):

```json
{
  "iss": "https://kube.wallet.dev.triveria.io",
  "sub": "<wallet instance identifier>",
  "wallet_name": "Triveria Wallet (Dev Environment)",
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } },
  "iat": 1793000000,
  "exp": 1793043200,
  "status": { "status_list": { "idx": 412, "uri": "https://kube.wallet.dev.triveria.io/status/client" } }
}
```

`exp − iat` here is 12 h, inside the <24 h expectation. `status.status_list` is the `client_status` surface.

### 4.2 Token Request

Same two headers, per **TOKEN-REQ-4.5.1-01/02**:

```http
POST /token HTTP/1.1
Host: issuer.example.eu
Content-Type: application/x-www-form-urlencoded
OAuth-Client-Attestation: eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QiLC...
OAuth-Client-Attestation-PoP: eyJhbGciOiJFUzI1NiJ9...

grant_type=authorization_code&code=...&code_verifier=...
```

### 4.3 Credential Request — `proofs` → `jwt`

```json
{
  "credential_configuration_id": "eu.europa.ec.eudi.pid.1",
  "proofs": {
    "jwt": [
      "<compact JWS: see header and body below>"
    ]
  }
}
```

Protected Header of that single element (**-03**, **-04**):

```json
{
  "alg": "ES256",
  "typ": "openid4vci-proof+jwt",
  "key_attestation": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtleWF0dGVzdGF0aW9uK2p3dCJ9.eyJhdHRlc3RlZF9rZXlzIjpbey4uLn1dfQ.<signed by the Wallet Provider>"
}
```

Body (**-02**):

```json
{
  "aud": "https://issuer.example.eu",
  "iat": 1793000100,
  "nonce": "<from the Provider's Nonce Endpoint>"
}
```

Decoded `key_attestation` — the KA (TS03 §2.3.4, OpenID4VCI D.1):

```json
{
  "iss": "https://kube.wallet.dev.triveria.io",
  "iat": 1793000050,
  "exp": 1793003650,
  "attested_keys": [
    { "kty": "EC", "crv": "P-256", "kid": "k1", "x": "...", "y": "..." },
    { "kty": "EC", "crv": "P-256", "kid": "k2", "x": "...", "y": "..." }
  ],
  "key_storage": ["iso_18045_high"],
  "user_authentication": ["iso_18045_high"],
  "status": { "status_list": { "idx": 77, "uri": "https://kube.wallet.dev.triveria.io/status/keys" } }
}
```

Two `attested_keys` ⇒ the Provider issues **two** credentials, one bound to each, none twice (**PROC-4.6.2.1-04/05/06**). The outer `jwt` element is signed with the private key of `attested_keys[0]` (**-07**), which is what **PROC-4.6.2.1-02** checks. `status.status_list` here is the `key_storage_status` surface.

### 4.4 Credential Request — `proofs` → `attestation`

```json
{
  "credential_configuration_id": "eu.europa.ec.eudi.pid.1",
  "proofs": {
    "attestation": [
      "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtleWF0dGVzdGF0aW9uK2p3dCJ9.eyJub25jZSI6Ii4uLiIsImF0dGVzdGVkX2tleXMiOlt7Li4ufV19.<signed by the Wallet Provider>"
    ]
  }
}
```

Exactly one element (**4.6.1.3-01**), carrying `nonce` in its body (**-02**) and being the KA itself (**-03**). No possession proof.

---

## 5. Where the Trusted List enters

Three requirements, one phrase, three endpoints:

| Endpoint | Requirement | Phrase |
|---|---|---|
| PAR | AUTH-REQ-PROC-4.4.3-01 | *"verifies under the Wallet Provider's public key as found on the Trusted List of Wallet Providers"* |
| Token | TOKEN-REQ-PROC-4.5.2-01 | same |
| Credential | CRED-REQ-PROC-4.6.2.1-01 / 4.6.2.2-01 | *"…as found on the Trusted List for Wallet Providers"* |

ARF equivalents: **ISSU_19**/**ISSU_21** (PID Provider), **ISSU_28**/**ISSU_30**/**ISSU_30a** (Attestation Provider), with revocation of the Wallet Instance and WSCD/keystore per **Topic 38**.

### 5.1 Diagnosing a Token Endpoint `401 invalid_client`

`TOKEN-REQ-PROC-4.5.2-01` is the step that fails when the Wallet Provider trust anchor cannot be resolved. Distinguish:

| Symptom | Failing requirement | Cause |
|---|---|---|
| trust evaluation indeterminate, no certificate examined | **-01** | the Wallet Providers list could not be fetched, parsed or signature-validated — the anchor set is unavailable |
| trust evaluation negative, certificate examined | **-01** | the WIA signer is not on the list, or the entity/service status is Invalid/withdrawn |
| WIA rejected as stale | **-02** | `exp` passed; note the <24 h TTL means a cached WIA expires fast |
| PoP rejected | **-03** | PoP not signed by the key in `cnf`, or `aud`/`jti` mismatch |

The first two are indistinguishable from the `401` alone — the Provider's trust-evaluation log is the only place the difference shows. A list-level failure (unreachable endpoint, unsupported signature algorithm, a resolver that treats *unsupported algorithm* as *invalid signature*, or a registry configured to require a JWS signature on an XML LoTE) presents as **-01** without any certificate ever being compared.

---

## 6. Revocation

| Artefact | Status claim | Signed by |
|---|---|---|
| WIA | `client_status` | the Wallet Solution sign/seal key, **or** a distinct revocation key |
| KA | `key_storage_status` | same choice |

Where a distinct revocation certificate is used it is the trust anchor for WIA and KA Attestation Status Lists under **WPNot_02**, and the `ServiceDigitalIdentity` of the `…/SvcType/WalletSolution/Revocation` service.

---

## 7. Crypto suites

**CRYPTO-5-01**: in addition to the suites in OpenID4VC-HAIP, the Wallet and the PID/EAA Provider **shall** support `A128GCM` and `A256GCM` (NIST SP 800-38D).

WIA and KA signatures are `ES256` (repo profile, TS 119 412-6 cl. 5 — one P-256 key pair per Wallet Solution).

---

## 8. Gaps and corrections

| Item | Status |
|---|---|
| **TS 119 472-3 absent from `references/etsi/`** | ❌ add it — Parts 1 and 3 are both missing; only Part 2 (V1.1.1) is stored |
| **EUDI Wallet TS03 not referenced in this repo** | ❌ WIA contents (§2.3.3) and KA contents (§2.3.4) are normatively delegated to it |
| **"WUA" collides** between `terms-and-entities.md:47` (umbrella) and 472-3 cl. 3.1 (the key attestation) | ⚠️ document the mapping; requirement IDs cannot be cross-walked without it |
| `ServiceUniqueIdentifier` — Annex E `shall` | ❌ 0 occurrences in the deployed Wallet Providers list, so the Wallet Solution has no unique list identifier to match `wallet_name` against |
| Which `attested_keys` ordering a Provider must assume beyond element 0 | ⚠️ `-07` fixes only the first element's role |

---

## Source

ETSI TS 119 472-3 V1.1.1 (2026-03):
<https://etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf>
