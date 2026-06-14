# ES256-DH

A signature algorithm for use with JSON Web Signatures (JWS), suitable for
signing components that accept only a limited, fixed-size input.

- **Status:** Draft.
- **Algorithm identifier (`alg` value):**
  `https://github.com/OwnYourData/pace-dpp/blob/main/ES256-DH.md`

## 1. Overview

`ES256-DH` is a profile of ECDSA over NIST P-256 with SHA-256 (the JOSE
`ES256` primitive, RFC 7518 §3.4).

It differs from plain `ES256` in exactly one respect: the message that is
ECDSA-signed is **`SHA-256` of the JWS Signing Input**, rather than the JWS
Signing Input itself. This additional hashing reduces the data to be signed to
a fixed 32 bytes, which allows the signature to be produced by signing
components that accept only a small, bounded input.

Everything else — the JWS Compact Serialization structure, the signature
encoding, and `kid`-based key resolution — follows the standard JOSE rules, so
the result remains a structurally valid JWS (RFC 7515).

`ES256-DH` uses its own algorithm identifier (a URI) so that generic JOSE
implementations do not mistake it for standard `ES256`.

## 2. Keys

- **Curve:** NIST P-256 (secp256r1 / prime256v1).
- **Private key:** 32-byte big-endian scalar.
- **Public key:** 65-byte uncompressed point `0x04 || X || Y`, published in the
  issuer's DID document under the verification method referenced by `kid`.

## 3. JOSE Protected Header

The Protected Header is a JSON object with exactly these members:

| Member | Value |
|--------|-------|
| `alg`  | `https://github.com/OwnYourData/pace-dpp/blob/main/ES256-DH.md` |
| `typ`  | `JWT` |
| `kid`  | the issuer DID from the payload, with the fragment `#key-doc` appended (e.g. `did:web:example.com#key-doc`) |

`kid` MUST resolve to the issuer's P-256 public key. Per RFC 7515 the `alg`
value is a `StringOrURI`; a URI is used here to identify this non-registered
algorithm.

## 4. Payload

The JWS Payload is the credential document encoded with Base64URL **over its
exact byte sequence**. Implementations MUST NOT re-serialize the JSON, because
the signature is computed over these exact bytes; any whitespace change would
invalidate the signature.

## 5. Signing Input

As defined in RFC 7515 §5.1:

```
SigningInput = ASCII( BASE64URL(UTF8(Protected Header)) || '.' || BASE64URL(Payload) )
```

The header is part of the Signing Input and is therefore covered by the
signature.

## 6. Signature generation

```
1.  M     = SHA-256(SigningInput)            # 32 bytes
2.  (R,S) = ECDSA_P256_sign(privateKey, M)   # ECDSA-with-SHA-256 over M
3.  JWS Signature = BASE64URL( R || S )       # R and S each 32 bytes, big-endian, fixed length
```

The complete JWS (Compact Serialization) is:

```
BASE64URL(UTF8(Protected Header)) || '.' ||
BASE64URL(Payload)                || '.' ||
BASE64URL(R || S)
```

Because step 2 uses ECDSA-with-SHA-256, the effective digest signed is
`SHA-256(M) = SHA-256(SHA-256(SigningInput))`. Verifiers do not need to treat
this specially: they simply ECDSA-with-SHA-256-verify with the message set to
`M` (see §7).

## 7. Signature verification

```
1.  Split the JWS into header_b64, payload_b64, sig_b64.
2.  Resolve the issuer public key via the header's `kid`.
3.  M = SHA-256( ASCII(header_b64 || '.' || payload_b64) )
4.  Decode sig_b64 -> 64 bytes -> R = bytes[0..31], S = bytes[32..63].
5.  Accept iff ECDSA_P256_verify(publicKey, M, (R,S)) succeeds
    (ECDSA-with-SHA-256, i.e. the curve operation hashes M with SHA-256).
6.  Apply application checks to the decoded payload (issuer == kid DID, dates, etc.).
```

## 8. Security considerations

- The Protected Header is included in the Signing Input, so `alg`, `typ` and
  `kid` are integrity-protected; altering them invalidates the signature.
- `R || S` is fixed-length (64 bytes) as required by RFC 7518 §3.4. If the
  signing component emits a DER-encoded signature, it MUST be converted to
  `R || S` before Base64URL encoding.
- ECDSA uses a per-signature nonce; signatures are non-deterministic but each
  is independently verifiable.
- This profile is **not** interoperable with generic JOSE verifiers, which
  expect `alg:"ES256"` and sign the Signing Input directly (without the extra
  `SHA-256`). Only verifiers implementing this document can validate the JWS.

## 9. Test vector

The private key below is for testing only and MUST NOT be used in production.
The final signature is non-deterministic (ECDSA uses a per-signature nonce);
the values shown are one valid example. Any valid ECDSA-with-SHA-256 signature
over `M` under the issuer key verifies.

Key (NIST P-256):

```
Private key (hex, 32 bytes):
96fe0f41947d645c7a1858c48c7a0560e7e5bd3d45125b57a611a3a9a103626b

Public key (uncompressed, hex, 65 bytes):
04bcad0c43ac859d0552d95b639156073f9c1c4fb1aa9490f3639a8cf0a2aaadaa47701058367e000770437b32b35530848039317d963679927ab4112832b1838f
```

Payload (the credential document, signed over its exact bytes):

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:83b0aafa-7f42-4d3d-94e3-43c1c7b5c211",
  "type": [ "VerifiableCredential" ],
  "issuer": "did:oyd:zQmWLt1m6QuApNgVqFRg1VVJcs3zzkKQjVYpta2ZEJBbsvE",
  "validFrom": "2025-07-01T00:00:00Z",
  "credentialSubject": {
    "namePlate": {
      "manufacturerName": "Hikari GmbH",
      "modelName": "Hikari LED Pannel X2",
      "serialNumber": "SN20250729001",
      "dateOfManufacture": "2025-07-01"
    },
    "operationalStatus": {
      "DeviceUptimeSeconds": 36000,
      "NumberOfOperations": 1234
    }
  }
}
```

Protected Header (JSON):

```
{"alg":"https://github.com/OwnYourData/pace-dpp/blob/main/ES256-DH.md","typ":"JWT","kid":"did:oyd:zQmWLt1m6QuApNgVqFRg1VVJcs3zzkKQjVYpta2ZEJBbsvE#key-doc"}
```

Intermediate and output values:

```
M = SHA-256(SigningInput):
bc90b9a308b9fdf8f37656070575a03c487758abd0407fdf1461f034c5210e23

Signature (R || S, hex, 64 bytes):
98623061792039757edf49a400e5fdd7e98043193e41ac38679b871f30ccb9f62ed4807ff897e2d3048ce360bc9736820eeb1b969001d1420935af6eeaf0b35b
```

Complete JWS (Compact Serialization):

```
eyJhbGciOiJodHRwczovL2dpdGh1Yi5jb20vT3duWW91ckRhdGEvcGFjZS1kcHAvYmxvYi9tYWluL0VTMjU2LURILm1kIiwidHlwIjoiSldUIiwia2lkIjoiZGlkOm95ZDp6UW1XTHQxbTZRdUFwTmdWcUZSZzFWVkpjczN6emtLUWpWWXB0YTJaRUpCYnN2RSNrZXktZG9jIn0.ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLAogICAgImh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy9leGFtcGxlcy92MiIKICBdLAogICJpZCI6ICJ1cm46dXVpZDo4M2IwYWFmYS03ZjQyLTRkM2QtOTRlMy00M2MxYzdiNWMyMTEiLAogICJ0eXBlIjogWyAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiIF0sCiAgImlzc3VlciI6ICJkaWQ6b3lkOnpRbVdMdDFtNlF1QXBOZ1ZxRlJnMVZWSmNzM3p6a0tRalZZcHRhMlpFSkJic3ZFIiwKICAidmFsaWRGcm9tIjogIjIwMjUtMDctMDFUMDA6MDA6MDBaIiwKICAiY3JlZGVudGlhbFN1YmplY3QiOiB7CiAgICAibmFtZVBsYXRlIjogewogICAgICAibWFudWZhY3R1cmVyTmFtZSI6ICJIaWthcmkgR21iSCIsCiAgICAgICJtb2RlbE5hbWUiOiAiSGlrYXJpIExFRCBQYW5uZWwgWDIiLAogICAgICAic2VyaWFsTnVtYmVyIjogIlNOMjAyNTA3MjkwMDEiLAogICAgICAiZGF0ZU9mTWFudWZhY3R1cmUiOiAiMjAyNS0wNy0wMSIKICAgIH0sCiAgICAib3BlcmF0aW9uYWxTdGF0dXMiOiB7CiAgICAgICJEZXZpY2VVcHRpbWVTZWNvbmRzIjogMzYwMDAsCiAgICAgICJOdW1iZXJPZk9wZXJhdGlvbnMiOiAxMjM0CiAgICB9CiAgfQp9Cg.mGIwYXkgOXV-30mkAOX91-mAQxk-Qaw4Z5uHHzDMufYu1IB_-Jfi0wSM42C8lzaCDusblpAB0UIJNa9u6vCzWw
```

## 10. References

- RFC 7515 — JSON Web Signature (JWS)
- RFC 7518 §3.4 — ECDSA (P-256/SHA-256, `R || S` encoding)
- RFC 7519 — JSON Web Token (JWT)
