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
| `typ`  | `vp+jwt` |
| `kid`  | the signer's DID, with the fragment `#key-doc` appended (the holder DID for a presentation, e.g. `did:web:oydid.ownyourdata.eu:zQmYmDf3nBJEGy9qznPMEsxi5CrGA9Ha61o5Gfgk5yX2XtD#key-doc`) |

`kid` MUST resolve to the signer's P-256 public key. Per RFC 7515 the `alg`
value is a `StringOrURI`; a URI is used here to identify this non-registered
algorithm.

## 4. Payload

The JWS Payload is the secured document encoded with Base64URL **over its
exact byte sequence**. In the PACE-DPP demo this profile secures the
*Verifiable Presentation*; the algorithm is, however, payload-agnostic.
Implementations MUST NOT re-serialize the JSON, because the signature is
computed over these exact bytes; any whitespace change would invalidate the
signature.

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

The private keys below are for testing only and MUST NOT be used in
production. The final signature is non-deterministic (ECDSA uses a
per-signature nonce); the values shown are one valid example. Any valid
ECDSA-with-SHA-256 signature over `M` under the holder key verifies.

This worked example is a **Verifiable Presentation** — the object that ES256-DH
secures in this demo. The presentation embeds a credential that is itself
signed with standard `ES256` by the issuer (resolvable separately).

Holder / signing component (the ES256-DH signer of the presentation, NIST P-256):

```
Holder DID:
did:web:oydid.ownyourdata.eu:zQmYmDf3nBJEGy9qznPMEsxi5CrGA9Ha61o5Gfgk5yX2XtD

Private key (hex, 32 bytes):
96fe0f41947d645c7a1858c48c7a0560e7e5bd3d45125b57a611a3a9a103626b

Public key (uncompressed, hex, 65 bytes):
04bcad0c43ac859d0552d95b639156073f9c1c4fb1aa9490f3639a8cf0a2aaadaa47701058367e000770437b32b35530848039317d963679927ab4112832b1838f
```

Issuer of the embedded credential (signs the inner VC with standard ES256):

```
Issuer DID:
did:web:oydid.ownyourdata.eu:zQmVPmNLuo9ntbyvSsJNVHA3xJY5DHw8mf86AWaikssKvM7

Public key (uncompressed, hex, 65 bytes):
04ef172dbaab962cff5153bd77d168ed02129caa53b5e721545e452a4e5caa23e5bd84dc2c3e66895aa4ce406fb0e0f569185fb99abf9cf01e2b77381e2755d34b
```

Protected Header of the presentation (JSON):

```
{"alg":"https://github.com/OwnYourData/pace-dpp/blob/main/ES256-DH.md","typ":"vp+jwt","kid":"did:web:oydid.ownyourdata.eu:zQmYmDf3nBJEGy9qznPMEsxi5CrGA9Ha61o5Gfgk5yX2XtD#key-doc"}
```

Intermediate and output values:

```
M = SHA-256(SigningInput):
98b33a8b9350d7d7bca261bc1a80158c3b96c0e1c7ce057271c8729a2bfc42fe

Signature (R || S, hex, 64 bytes):
012e83520e1d4b94a84cbd793733fc8175ab251ac96f5bcfd4570fee7f6868609164521061f3732e27ceb993785108fe85c9130100725e9e4c6180319bf22ce9
```

Complete presentation JWS (Compact Serialization; the payload embeds the
ES256-signed credential as an `EnvelopedVerifiableCredential`):

```
eyJhbGciOiJodHRwczovL2dpdGh1Yi5jb20vT3duWW91ckRhdGEvcGFjZS1kcHAvYmxvYi9tYWluL0VTMjU2LURILm1kIiwidHlwIjoidnArand0Iiwia2lkIjoiZGlkOndlYjpveWRpZC5vd255b3VyZGF0YS5ldTp6UW1ZbURmM25CSkVHeTlxem5QTUVzeGk1Q3JHQTlIYTYxbzVHZmdrNXlYMlh0RCNrZXktZG9jIn0.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sImhvbGRlciI6ImRpZDp3ZWI6b3lkaWQub3dueW91cmRhdGEuZXU6elFtWW1EZjNuQkpFR3k5cXpuUE1Fc3hpNUNyR0E5SGE2MW81R2ZnazV5WDJYdEQiLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6W3siQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJa3BYVkNJc0ltdHBaQ0k2SW1ScFpEcDNaV0k2YjNsa2FXUXViM2R1ZVc5MWNtUmhkR0V1WlhVNmVsRnRWbEJ0VGt4MWJ6bHVkR0o1ZGxOelNrNVdTRUV6ZUVwWk5VUklkemh0WmpnMlFWZGhhV3R6YzB0MlRUY2phMlY1TFdSdll5SjkuZXdvZ0lDSkFZMjl1ZEdWNGRDSTZJRnNLSUNBZ0lDSm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQW9nSUNBZ0ltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OXVjeTlqY21Wa1pXNTBhV0ZzY3k5bGVHRnRjR3hsY3k5Mk1pSUtJQ0JkTEFvZ0lDSnBaQ0k2SUNKMWNtNDZkWFZwWkRvNE0ySXdZV0ZtWVMwM1pqUXlMVFJrTTJRdE9UUmxNeTAwTTJNeFl6ZGlOV015TVRFaUxBb2dJQ0owZVhCbElqb2dXeUFpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUlGMHNDaUFnSW1semMzVmxjaUk2SUNKa2FXUTZkMlZpT205NVpHbGtMbTkzYm5sdmRYSmtZWFJoTG1WMU9ucFJiVlpRYlU1TWRXODViblJpZVhaVGMwcE9Wa2hCTTNoS1dUVkVTSGM0YldZNE5rRlhZV2xyYzNOTGRrMDNJaXdLSUNBaWRtRnNhV1JHY205dElqb2dJakl3TWpVdE1EY3RNREZVTURBNk1EQTZNREJhSWl3S0lDQWlZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPaUI3Q2lBZ0lDQWljMlZ5YVdGc0lqb2dJbE5PTFRReU5Ua3pOemd6T0NJc0NpQWdJQ0FpYm1GdFpTSTZJQ0pGYkdWamRISnZibWxqSUVSbGRtbGpaU0lzQ2lBZ0lDQWlkMlZwWjJoMElqb2dOREV5TGpVc0NpQWdJQ0FpWTI4eWNISnZaSFZqZEdsdmJpSTZJRE0wTUN3S0lDQWdJQ0p3Y205a2RXTjBhVzl1UkdGMFpTSTZJQ0l5TURJekxUQTFMVEl3SWdvZ0lIMEtmUS53QUJoV1ZwVWJoVTBYMkFpamxqbmtsbHJ4UEVxbW5mNUFQcHRHMk5GYWxrVjdpbFFNdUxRb0l5alJEWTc2cmltTkRJdVUyMFZJNEtteGIxSXVORjlUZyJ9XX0.AS6DUg4dS5SoTL15NzP8gXWrJRrJb1vP1FcP7n9oaGCRZFIQYfNzLifOuZN4UQj-hckTAQByXp5MYYAxm_Is6Q
```

## 10. References

- RFC 7515 — JSON Web Signature (JWS)
- RFC 7518 §3.4 — ECDSA (P-256/SHA-256, `R || S` encoding)
- RFC 7519 — JSON Web Token (JWT)
