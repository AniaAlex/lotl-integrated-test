# Verifier Certificate Carriage in Presentation Requests (ETSI TS 119 472-2)

## Overview

This document specifies how a Wallet-Relying Party (verifier) conveys its **access certificate (WRPAC)**, its **registration certificate (WRPRC)** and its **Registrar-provided data** to a Wallet Unit in a presentation request, for both the remote (OpenID4VP) and the proximity (ISO/IEC 18013-5) flows.

**Verified against:** ETSI TS 119 472-2 **V1.2.1 (2026-03)**.

> **Version warning.** `references/etsi/ts_11947202v010101p.md` in this repository is **V1.1.1 (2025-12)**. The requirement identifiers were renamed and renumbered in V1.2.1, and `registrar_dataset` does not exist in V1.1.1 at all. Every citation below is to V1.2.1. See [Version differences](#version-differences).

---

## Normative References

| Reference | Document |
|-----------|----------|
| ETSI TS 119 472-2 V1.2.1 (2026-03) | Profiles for Electronic Attestation of Attributes; Part 2: Profiles for EAA/PID Presentations to Relying Party |
| ETSI TS 119 475 | Relying party attributes supporting EUDI Wallet user's authorization decisions (reference `[14]` in 472-2) |
| ETSI TS 119 411-8 | Access Certificate Policy for EUDI Wallet Relying Parties |
| ETSI TS 119 612 | Trusted Lists (the `etsi_tl` Authority Key Identifier mechanism) |
| OpenID4VP 1.0 | `verifier_info` parameter |
| OpenID4VC High Assurance Interoperability Profile (HAIP) | reference `[11]` in 472-2 |
| ISO/IEC 18013-5 | `DeviceRequest`, `ReaderAuth`, `RequestInfo` |
| IETF RFC 9101 | JWT-Secured Authorization Request (Request Object) |
| IETF RFC 7515 | JSON Web Signature |

---

## 1. Remote flow (OpenID4VP)

### 1.1 Client identifier

| Requirement | Text |
|---|---|
| **OIDFVP-HAIP-COMMON-REQ-01** (cl. 6.3.2.1) | The Authorization Request **shall** use the Client Identifier Prefix **`x509_hash`**. |

This matters operationally: the verifier's identifier is the SHA-256 of its access certificate, so the identifier is cryptographically bound to the key rather than asserted by name.

### 1.2 Access certificate — `x5c` in the Request Object's JWS Protected Header

Clause 6.4.2, non-API-mediated (redirect) transmission:

| Requirement | Text |
|---|---|
| **OIDFVP-HAIP-REDIRECTS_RO-01** | The JWS Protected Header of the JWS signature on the RO **shall** incorporate the `x5c` header parameter. |
| **OIDFVP-HAIP-REDIRECTS_RO-02** | The `x5c` header parameter … **shall** contain the RP access certificate in its **first element**, and its certificate path **up to, but excluding, the trust anchor**. |
| **OIDFVP-HAIP-REDIRECTS_RO-03** | The JWS Protected Header … **shall** incorporate the `iat` header parameter. |

So: **a chain, leaf first, anchor excluded.** The trust anchor is resolved from the Access CA trusted list, not sent.

Related, clause 6.3.2.2:

| Requirement | Text |
|---|---|
| **OIDFVP-HAIP-COMMON-REQ-RO-17** | The Authority Key Identifier **shall** use the ETSI Trusted Lists mechanism (`"etsi_tl"` type). |
| **OIDFVP-HAIP-COMMON-REQ-RO-18** | The RO JWT body **shall** contain the `client_metadata` parameter. |
| **OIDFVP-HAIP-COMMON-REQ-RO-19** | `client_metadata` **shall** contain the `jwks` member. |
| **OIDFVP-HAIP-COMMON-REQ-RO-20** | The `jwks` member **shall** contain the `kid` and `use` parameters. |

### 1.3 `verifier_info` — mandatory, and what must be in it

Clause **6.3.2.2** (not 6.3.1.4 — see [Version differences](#version-differences)):

| Requirement | Text |
|---|---|
| **OIDFVP-HAIP-COMMON-REQ-RO-01** | The RO JWT body **shall** contain the `verifier_info` parameter. |
| **OIDFVP-HAIP-COMMON-REQ-RO-02** | `verifier_info` **shall** contain RP Registrar-provided data. |
| **OIDFVP-HAIP-COMMON-REQ-RO-03** | The element enclosing the Registrar-provided data **shall** be a JSON Object which **shall not** contain `credential_ids`. |
| **OIDFVP-HAIP-COMMON-REQ-RO-04** | Its `format` member **shall** be `"registrar_dataset"`. |
| **OIDFVP-HAIP-COMMON-REQ-RO-05** | Its `data` member **shall** be a non-empty JSON Object. |

`verifier_info` is therefore **unconditionally mandatory**, and the `registrar_dataset` element is mandatory within it. The registration certificate is the conditional part.

#### `registrar_dataset` `data` members

All member definitions are in ETSI TS 119 475 Annex B.

| Requirement | Member | Clause in TS 119 475 | Content |
|---|---|---|---|
| **REQ-RO-06** | `identifier` | B.2.2 | the RP's identifier |
| **REQ-RO-07** | `srvDescription` | B.2.2 (MultiLangString: B.2.6) | array of registered user-friendly service descriptions |
| **REQ-RO-08** | `registryURI` | B.2.1 | URI of the RP Registrar's API |
| **REQ-RO-09** | `intendedUseIdentifier` | B.2.7 | Registrar-provided identifier of the RP's intended use |
| **REQ-RO-10** | `purpose` | B.2.7 (MultiLangString: B.2.6) | array of registered purposes of the intended processing |
| **REQ-RO-11** | `policyURI` | B.2.8 | privacy policy URI of the registered intended use |
| **REQ-RO-12** | `credential` | B.2.7 (Credential: B.2.9) | **may** — attestations and attributes per attestation registered for the intended use |

Six `shall`, one `may`.

### 1.4 Registration certificate — conditional

| Requirement | Text |
|---|---|
| **OIDFVP-HAIP-COMMON-REQ-RO-13** | **If** the RP has a registration certificate, one of the elements of `verifier_info` **shall** include it. |
| **OIDFVP-HAIP-COMMON-REQ-RO-14** | That element **shall** be a JSON Object which **shall not** contain `credential_ids`. |
| **OIDFVP-HAIP-COMMON-REQ-RO-15** | Its `format` member **shall** be `"registration_cert"`. |
| **OIDFVP-HAIP-COMMON-REQ-RO-16** | Its `data` member **shall** be the **base64url encoding of the serialized** RP registration certificate. |

### 1.5 Example — remote presentation request

JWS Protected Header of the Request Object:

```json
{
  "alg": "ES256",
  "typ": "oauth-authz-req+jwt",
  "iat": 1793000000,
  "x5c": [
    "MIICxDCC...rp-access-certificate-leaf...",
    "MIIDfjCC...intermediate-if-any...        (anchor NOT included)"
  ]
}
```

Request Object body:

```json
{
  "client_id": "x509_hash:14b878ed229bf650d2303296ea1298a6366aca75cc6fe16054d13f4cdbe88289",
  "response_type": "vp_token",
  "response_mode": "direct_post.jwt",
  "nonce": "n-0S6_WzA2Mj",
  "dcql_query": { "credentials": [ "..." ] },

  "client_metadata": {
    "jwks": {
      "keys": [
        { "kty": "EC", "crv": "P-256", "kid": "rp-enc-1", "use": "enc", "x": "...", "y": "..." }
      ]
    }
  },

  "verifier_info": [
    {
      "format": "registrar_dataset",
      "data": {
        "identifier": "urn:eu:wrp:nl:67419925:0001",
        "srvDescription": [
          { "lang": "en", "value": "Age verification for alcohol sales" },
          { "lang": "nl", "value": "Leeftijdsverificatie voor alcoholverkoop" }
        ],
        "registryURI": "https://registrar.example.nl/wrp/api/v1",
        "intendedUseIdentifier": "urn:eu:wrp:nl:67419925:0001:use:1",
        "purpose": [
          { "lang": "en", "value": "Statutory age check under national alcohol legislation" }
        ],
        "policyURI": "https://example.nl/privacy",
        "credential": [
          {
            "credentialType": "eu.europa.ec.eudi.pid.1",
            "claims": [ { "path": ["age_over_18"] } ]
          }
        ]
      }
    },
    {
      "format": "registration_cert",
      "data": "eyJ0eXAiOiJyYy13cnArand0IiwiYWxnIjoiRVMzODQiLCJ4NWMiOlsiTUlJQy4uLiJdfQ...."
    }
  ]
}
```

`verifier_info[1].data` is base64url of the compact `rc-wrp+jwt`, per REQ-RO-16.

---

## 2. Proximity flow (ISO/IEC 18013-5)

Clause 5.3.2 / 5.x, `DeviceRequest`:

| Requirement | Text |
|---|---|
| **ISO/IEC 18013-REQ-02** | The signature in `readerAuth` **shall** be generated with the private key whose public key is enclosed within the **RP access certificate**. |
| **ISO/IEC 18013-REQ-03** | The `x5chain` **unprotected** header parameter **shall** contain the RP access certificate in its **first element**, and its certificate path **up to, but excluding, the trust anchor**. |
| **ISO/IEC 18013-REQ-04** | The `ItemsRequest` instances in `docRequests` **shall** contain a non-empty `requestInfo` member of type `RequestInfo`. |
| **ISO/IEC 18013-REQ-05** | `RequestInfo` **shall** be as the CDDL definition below. |
| **ISO/IEC 18013-REQ-06** | **If** the RP has a registration certificate, `requestInfo` **shall** contain a member labelled `"euWrprc"`. |
| **ISO/IEC 18013-REQ-07** | `"euWrprc"` **shall** map to a CBOR byte string. |
| **ISO/IEC 18013-REQ-08** | That byte string **shall** contain the serialization of the RP registration certificate. |
| **ISO/IEC 18013-REQ-09** | `requestInfo` **shall** contain a member labelled `"euWrpRegistrarInfo"`. |

CDDL as published:

```cddl
RequestInfo = {
    ?"eUWrprc": bstr,                        ; contains a registration certificate if available
    "euWrpRegistrarInfo": EUWrpRegistrarInfo ; RP's Registrar-provided information
}
```

> **Spec defect.** The CDDL writes the optional key as `"eUWrprc"` (capital U) while REQ-06, REQ-07 and REQ-08 all say `"euWrprc"`. Implementations must pick one; the requirement text is the three-to-one majority and matches the `euWrpRegistrarInfo` casing. Worth raising with ETSI.

Note the structural asymmetry with the remote flow: the registration certificate is sent **raw CBOR bytes** here, not base64url.

### 2.1 Example — proximity `requestInfo`

```
DeviceRequest
 └─ docRequests[0]
     ├─ itemsRequest (ItemsRequestBytes → ItemsRequest)
     │   └─ requestInfo:
     │        {
     │          "euWrprc":            h'A1...'          ; CBOR bstr, serialized WRPRC
     │          "euWrpRegistrarInfo": { identifier, srvDescription, registryURI, ... }
     │        }
     └─ readerAuth (COSE_Sign1)
         ├─ unprotected: { x5chain: [ <RP access cert>, <intermediates…> ] }   ; anchor excluded
         └─ signature over the key in that access certificate
```

---

## 3. Wallet-side validation sequence

1. **Access certificate** — take `x5c[0]` (remote) or `x5chain[0]` (proximity); build the path and anchor it to a CA in the **Access CA LoTE** with valid entity status; check revocation; check SCT where required (**CT_05**, TS 119 411-8).
2. **Client identifier** — confirm `client_id` is `x509_hash:<sha256 of the access certificate>` (**COMMON-REQ-01**).
3. **Request Object signature** — verify with the key in the access certificate.
4. **`registrar_dataset`** — present and non-empty; all six mandatory members present.
5. **`registration_cert`** — if present: base64url-decode, verify the JAdES B-B signature (ETSI TS 119 475 GEN-5.2.1-04), chain its `x5c[0]` to the **Registration Cert Provider LoTE**.
6. **Binding** — WRPRC `sub` **shall** equal the WRPAC `organizationIdentifier` (legal person) or `serialNumber` (natural person) (TS 119 475 GEN-5.1.1-02).
7. **Intermediary detection** — per 472-2 cl. 6.3.2.2 NOTE 2: where an intermediary is used, the `identifier` of **REQ-RO-06** differs from the identifier in the intermediary's access certificate. There is no `is_intermediary` flag.
8. **Over-request** — requested attributes within the WRPRC's registered `credential` set.
9. **Revocation** — WRPRC `status.status_list` (`uri` + `idx`).

---

## Version differences

Between the repository's stored V1.1.1 and the published V1.2.1:

| | V1.1.1 (2025-12) | V1.2.1 (2026-03) |
|---|---|---|
| Remote requirement IDs | `OIDFVP-HAIP_COMMON_RO_REQ-05…09` (underscores) | `OIDFVP-HAIP-COMMON-REQ-RO-01…20` (hyphens) |
| Proximity requirement IDs | `ISO/IEC 18013-5-REQ-09/10/11` | `ISO/IEC 18013-REQ-06/07/08` |
| `verifier_info` | conditional on having a registration certificate | **unconditionally mandatory** |
| `registrar_dataset` | **does not exist** | mandatory element, 6 mandatory members |
| `euWrpRegistrarInfo` | does not exist | mandatory |
| Clause | 6.3.1 "Common requirements" | **6.3.2.2** "Requirements for the Request Object" |

V1.2.1's own change history records: *"Make `verifier_info` mandatory in RO JWT body"*, *"`verifier_info` shall contain registrar-provided data"*, *"If registration certificate available, then `verifier_info` shall contain it"*.

### Corrections needed in this repository

| File | Current | Should be |
|---|---|---|
| `references/etsi/` | 472-2 **V1.1.1** only | add **V1.2.1** |
| `task2-trust-framework/eudi-wallet-trust-and-entitlement-discovery.md:433` | "ETSI TS 119 472-2 clause 6.3.1.4" | clause **6.3.2.2**; no `.4` subdivision exists in either version |
| `task2-trust-framework/rp-intermediary-openid4vp-technical-report.md:47` | "mandatory `verifier_info` with `registrar_dataset` and optional `registration_cert`" | correct **for V1.2.1**; cite the version, since the stored V1.1.1 contradicts it |
| same, `:161` | lists `registrar_dataset` | correct for V1.2.1; add requirement IDs `REQ-RO-04`/`-08` |

---

## Source

ETSI TS 119 472-2 V1.2.1 (2026-03):
<https://etsi.org/deliver/etsi_ts/119400_119499/11947202/01.02.01_60/ts_11947202v010201p.pdf>
