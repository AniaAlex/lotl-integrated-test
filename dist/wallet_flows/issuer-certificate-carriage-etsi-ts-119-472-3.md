# Issuer Certificate Carriage in Issuer Metadata (ETSI TS 119 472-3)

## Overview

This document specifies how a **PID Provider or Attestation Provider** (including a PuB-EAA Provider) conveys its **access certificate (WRPAC)**, its **registration certificate (WRPRC)** and its **Registrar-provided data** to a Wallet Unit during issuance.

**Verified against:** ETSI TS 119 472-3 **V1.1.1 (2026-03)**.

> **Missing reference.** TS 119 472-3 is **not** in `references/etsi/`. Part 1 is general requirements, Part 2 is presentation (stored, V1.1.1), **Part 3 is issuance** and is absent. This is why [`wallet-unit-evaluates-credential-issuer.md:20`](https://github.com/webuild-consortium/wp4-trust-group/blob/main/task1-use-cases/subtask1-2-trust-registry/wallet-unit-evaluates-credential-issuer.md) says only *"in Issuer metadata (e.g. OpenID4VCI)"* where a named normative binding exists.

---

## Normative References

| Reference | Document |
|-----------|----------|
| ETSI TS 119 472-3 V1.1.1 (2026-03) | Profiles for Electronic Attestation of Attributes; Part 3: Profiles for issuance of EAA or PID |
| ETSI TS 119 475 | Relying party attributes supporting EUDI Wallet user's authorization decisions (reference `[4]` in 472-3) |
| ETSI TS 119 411-8 | Access Certificate Policy for EUDI Wallet Relying Parties |
| OpenID4VCI 1.0 | Signed metadata (clause 12.2.3); Credential Format Identifiers (Annex A) |
| OpenID4VP 1.0 | `verifier_info` (clause 5.1) — the structure `issuer_info` reuses |
| IETF RFC 7515 | JSON Web Signature |
| IETF RFC 4648 | base64 |
| EUDI Wallet TS05 | `providesAttestations` member (clause 2.1), reference `[i.4]` in 472-3 |

---

## 1. General requirements (clause 4.2.1)

| Requirement | Text |
|---|---|
| **ISS-MDATA-4.2.1-01** | The Issuer Metadata **shall** be **signed metadata** according to clause **12.2.3 of OpenID4VCI**, with a JWS per IETF RFC 7515. |
| **ISS-MDATA-4.2.1-02** | The signing certificate of the signature on the Issuer Metadata **shall be the access certificate** of the PID/EAA Provider. |
| **ISS-MDATA-4.2.1-03** | The `format` values of `credential_configurations_supported` **shall** include one or more of the Credential Format Identifiers in Annex A of OpenID4VCI. |

The architectural consequence: the access certificate is **not a metadata member**. The metadata is a signed JWT, and the access certificate is its signing certificate.

---

## 2. Access certificate (clause 4.2.2)

| Requirement | Text |
|---|---|
| **ISS-MDATA-ACC_CERT-4.2.2-01** | The JWS signing the Issuer Metadata **shall** contain, in its **Protected Header**, the `x5c` header parameter. |
| **ISS-MDATA-ACC_CERT-4.2.2-02** | `x5c` **shall** contain the base64 (RFC 4648) encoding of the DER-encoded **access certificate**, which **shall also be the signing certificate**. |
| **ISS-MDATA-ACC_CERT-4.2.2-03** | `x5c` **should** contain the base64 encoding of the DER-encoded certificates in the signing certificate's path **until the trust anchor, but excluding it**. |

So: a **chain**, leaf first, anchor excluded — `should`, not `shall`. Identical in shape to the verifier side (472-2 `OIDFVP-HAIP-REDIRECTS_RO-02`), where it is a `shall`.

---

## 3. Registration certificate and Registrar data (clause 4.2.3)

| Requirement | Text |
|---|---|
| **ISS-MDATA-REG_CERT-4.2.3-01** | The Issuer Metadata **shall** contain the `issuer_info` metadata parameter. |
| **ISS-MDATA-REG_CERT-4.2.3-02** | `issuer_info` **shall** be placed at the **top level of the Signed JWT payload** used for retrieving the Issuer Metadata. |
| **ISS-MDATA-REG_CERT-4.2.3-03** | `issuer_info` **shall** have the **same structure as the `verifier_info` parameter** specified in clause 5.1 of OpenID4VP. |
| **ISS-MDATA-REG_CERT-4.2.3-04** | One of the elements of the `issuer_info` array **may** contain the Provider's registration certificate. |
| **ISS-MDATA-REG_CERT-4.2.3-05** | The `format` member of that element **shall** be `"registration_cert"`. |
| **ISS-MDATA-REG_CERT-4.2.3-06** | The `data` member of that element **shall** be the registration certificate of the Provider. |
| **ISS-MDATA-REG_CERT-4.2.3-07** | One of the elements of `issuer_info` **shall** contain the Provider's registration information provided by its Registrar. |
| **ISS-MDATA-REG_CERT-4.2.3-08** | The `format` member of that element **shall** be `"registrar_dataset"`. |
| **ISS-MDATA-REG_CERT-4.2.3-09** | The `data` member of that element **shall** be a non-empty JSON Object. |

**Note the modality split.** The registration certificate is `may` (-04); the `registrar_dataset` is `shall` (-07). The Registrar fallback is the *mandatory* element, which is the wire-level expression of **ISSU_24a** / **ISSU_34a** — "either the registration certificate or the registration information from the Registrar".

### 3.1 `registrar_dataset` `data` members

Member definitions in ETSI TS 119 475 Annex B.

| Requirement | Member | Clause in TS 119 475 | Content |
|---|---|---|---|
| **-10** | `identifier` | B.2.2 | the Provider's identifier |
| **-11** | `srvDescription` | B.2.2 (MultiLangString: B.2.6) | array of registered user-friendly service descriptions |
| **-12** | `registryURI` | B.2.1 | URI of the Provider's Registrar |
| **-13** | `providesAttestations` | EUDI Wallet TS05 cl. 2.1 | attestation types the Provider intends to issue to Wallet Units |

All four are `shall`.

> **NOTE 3 of the spec, worth quoting in full for implementers:** `providesAttestations` is *"typically expected to contain same attestation or attestations, or a superset of the attestation types that are communicated to the Wallet Unit in the related Credential Offer message of OpenID4VCI and its `credential_configuration_ids` parameter"*. It *"tells the Wallet Unit what credentials the issuer is **registered** for in its national Registrar"*, whereas `credential_configuration_ids` tells it *"what credentials are under **active offer**"*. The two are not interchangeable.

### 3.2 Difference from the verifier's `registrar_dataset`

The two `registrar_dataset` payloads are **not** the same shape:

| Member | Verifier (472-2) | Issuer (472-3) |
|---|---|---|
| `identifier` | ✅ REQ-RO-06 | ✅ -10 |
| `srvDescription` | ✅ REQ-RO-07 | ✅ -11 |
| `registryURI` | ✅ REQ-RO-08 | ✅ -12 |
| `intendedUseIdentifier` | ✅ REQ-RO-09 | — |
| `purpose` | ✅ REQ-RO-10 | — |
| `policyURI` | ✅ REQ-RO-11 | — |
| `credential` | `may`, REQ-RO-12 | — |
| `providesAttestations` | — | ✅ -13 |

A verifier declares *why it is asking*; an issuer declares *what it is registered to issue*.

---

## 4. Example — Issuer Metadata

`GET /.well-known/openid-credential-issuer` returns signed metadata (OpenID4VCI cl. 12.2.3).

### 4.1 JWS Protected Header

```json
{
  "alg": "ES256",
  "x5c": [
    "MIICnDCC...provider-access-certificate-leaf...",
    "MIIDfjCC...intermediates, anchor EXCLUDED..."
  ]
}
```

Per **ISS-MDATA-4.2.1-02** this leaf is simultaneously the signing certificate and the access certificate.

### 4.2 Payload

```json
{
  "credential_issuer": "https://itb.issuance.wallet-connect.eu",
  "credential_endpoint": "https://itb.issuance.wallet-connect.eu/credential",
  "credential_configurations_supported": {
    "eu.europa.ec.eudi.pid.1": {
      "format": "dc+sd-jwt",
      "scope": "eu.europa.ec.eudi.pid.1"
    }
  },

  "issuer_info": [
    {
      "format": "registrar_dataset",
      "data": {
        "identifier": "urn:eu:wrp:nl:27322631:0001",
        "srvDescription": [
          { "lang": "en", "value": "Company register attestation issuance" },
          { "lang": "nl", "value": "Uitgifte van handelsregisterattestaties" }
        ],
        "registryURI": "https://registrar.example.nl/wrp/api/v1",
        "providesAttestations": [
          { "credentialType": "eu.europa.ec.eudi.pid.1" },
          { "credentialType": "org.example.company_registration.1" }
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

> **Encoding caveat.** **-06** says the `data` member *"shall be the registration certificate"* without specifying an encoding, where the verifier side's **REQ-RO-16** explicitly says *"the base64url encoding of the serialized RP registration certificate"*. Since **-03** mandates the same structure as `verifier_info`, base64url of the compact `rc-wrp+jwt` is the defensible reading — but it is an underspecification in 472-3 and worth raising.

---

## 5. Wallet-side validation sequence

1. Fetch Issuer Metadata; confirm it is **signed** metadata (**ISS-MDATA-4.2.1-01**).
2. Take `x5c[0]` from the JWS Protected Header — this is the **access certificate**. Build the path and anchor it to a CA in the **Access CA LoTE** with valid entity status; check revocation and SCT (**ISSU_24** PID / **ISSU_34** Attestation Provider; **CT_05**).
3. Verify the metadata JWS with the key in that certificate.
4. Read `issuer_info`; locate the `registrar_dataset` element (mandatory) and validate its four members.
5. If a `registration_cert` element is present: decode, verify its **JAdES B-B** signature (TS 119 475 **GEN-5.2.1-04**), chain its `x5c[0]` to the **Registration Cert Provider LoTE**, check revocation (**RPRC_02**).
6. **Binding:** WRPRC `sub` **shall** equal the access certificate's `organizationIdentifier` (legal person) or `serialNumber` (natural person) (TS 119 475 **GEN-5.1.1-02**).
7. **Entitlement:** confirm the requested attestation type appears in the WRPRC, or else in `providesAttestations`, or else query the Registrar at `registryURI` (**ISSU_24a** / **ISSU_34a**).
8. Confirm Provider entity status in the relevant LoTE is not Invalid (**GenNot_05**).

---

## 6. PuB-EAA Providers: what differs

For a PuB-EAA Provider the metadata binding above is **identical**. What differs is the **attestation signature**, not the metadata:

| | Production model | WE BUILD as deployed |
|---|---|---|
| Who seals the attestation | an external **QTSP** (eIDAS Art. 32; CIR 2025/1569 Annex III notifies **no** signing certificate) | the **provider's own** leaf, published as `ServiceDigitalIdentity` of its `…/SvcType/PubEAA/Issuance` service |
| Where the signer certificate is found | the national **QTSP TL** (TS 119 612 XML) | the **PuB-EAA Provider LoTE** (TS 119 602 Annex H) |
| Lists needed to validate | **2** (OIA_14, ISSU_09) | 1 |
| Qualified certificate (Art. 45f(1)(b)) | required | not met — no `qcStatements` on the deployed certificates |

Both are permitted by **TS 119 602 Annex H, Table H.3**, which says the `ServiceDigitalIdentity` *"may contain one or more X.509 certificates that can be used to verify the signature or seal created by the Pub-EAA provider"* and notes this *"can be the X.509 certificate corresponding to the private key used to sign or seal … or … a CA issuing such X.509 certificates"*.

> **Correction for this repository.** [`docs/pub_eaa_registration_and_qtsp.md`](https://github.com/webuild-consortium/wp4-trust-group/blob/main/docs/pub_eaa_registration_and_qtsp.md) states the PuB-EAA TL *"Lists: Authorization data (NOT signing cert)"*, citing CIR 2025/1569 Annex III. That regulation governs what the **Member State notifies**, not what the **list carries**. Annex H governs the list and expects a signature-verification certificate. The document conflates the two.

---

## 7. Gaps

| Item | Status |
|---|---|
| Encoding of `issuer_info[].data` for `registration_cert` | ⚠️ unspecified in -06; inferable from -03 |
| PuB-EAA Provider ↔ QTSP sealing protocol | ❌ unspecified in ARF, CIR 2025/1569 and TS 119 475 — contractual; industry uses CSC API v2.2 / ETSI EN 319 432 |
| How the PuB-EAA TL references the QTSP TL | ⚠️ partial (ISSU_09, OIA_14) |
| CSR submission protocol and Registrar `.cnf` template | ❌ not in any spec |

The requirement identifiers in clause 4.2.3 are **actively being reworded** — the document's own change history records rewording of `-02` and `-08`, and the replacement of an old `-15`. Check for a version later than V1.1.1 before citing.

---

## Source

ETSI TS 119 472-3 V1.1.1 (2026-03):
<https://etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf>
