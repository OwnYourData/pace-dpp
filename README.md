# JWS mit ES256-DH

Diese Demo signiert eine **Verifiable Credential (VC)** und verpackt sie in eine
**Verifiable Presentation (VP)**. Zwei verschiedene Signaturverfahren kommen zum
Einsatz:

- Die **VC** wird vom **Hersteller** (Issuer) mit seinem normalen Software-Key
  signiert – normales **`ES256`** (ECDSA P-256 / SHA-256), voll JOSE-interoperabel.
- Die **VP** wird vom **Signierbaustein / Chip** (Holder) signiert. Der Chip
  verarbeitet nur kleine Datenmengen (max. 255 Byte), deshalb wird nicht der
  ganze Token signiert, sondern dessen Hash. Dieses Verfahren heißt hier
  **ES256-DH** – im Kern ES256, aber mit einem zusätzlichen Hash-Schritt davor
  (Double-Hashing).

## Die Bausteine

- **[`build_jws.rb`](build_jws.rb)** – signiert die VC in einem Schritt mit dem
  Hersteller-Key (Standard-ES256).
- **[`verify_jws.rb`](verify_jws.rb)** – prüft die VC.
- **[`sig_stub.rb`](sig_stub.rb)** – simuliert den Chip: bekommt einen
  32-Byte-Hash und gibt eine Signatur (R||S) zurück. An dieser Stelle wäre der
  echte Chip.
- **[`build_vp.rb`](build_vp.rb)** – baut die VP um die VC herum und lässt sie
  vom Chip signieren (ES256-DH, zwei Schritte).
- **[`verify_vp.rb`](verify_vp.rb)** – prüft beide Lagen der VP.

## Teil 1 – Verifiable Credential (Hersteller, Standard-ES256)

**0. Vorbereitung** – mit [`oydid`](https://github.com/ownYourData/oydid) eine
did:oyd / did:web für den Hersteller erzeugen (das ist der `issuer` in
`input_vc.json`):

Hinweis: Der erzeugte Schlüssel liegt multibase-kodiert (`z…`) in der Datei
`<id>_private_key.enc`. Die Ruby-Scripts brauchen den **rohen Hex** – daher den
Dateinamen aus der DID ableiten, die Datei lesen (`SK`) und per `oydid mb2hex`
nach Hex wandeln (`SK_HEX`):

```bash
DID=$(echo '{}' | oydid create --key-type p256 --json-output | jq -r '.did')
SK=$(cat "$(cut -c1-10 <<< "${DID#did:oyd:}")_private_key.enc")
SK_HEX=$(oydid mb2hex <<< "$SK" | sed 's/.*: //')
DID="${DID/did:oyd:/did:web:oydid.ownyourdata.eu:}"
echo $DID
# did:web:oydid.ownyourdata.eu:zQmVPmNLuo9ntbyvSsJNVHA3xJY5DHw8mf86AWaikssKvM7
```

**1. VC signieren** – der `kid` ergibt sich aus dem `issuer`-Feld der VC; der
Schlüssel kommt als **Hex** aus `ISSUER_SK` (oder als Argument):

```bash
cat input_vc.json | ISSUER_SK=$SK_HEX ./build_jws.rb > credential.jws
```

**2. VC prüfen** – der Verifier baut die Signing Input nach und prüft die
Signatur gegen den über die `kid`-DID aufgelösten Public Key:

```bash
cat credential.jws | ./verify_jws.rb
```

## Teil 2 – Verifiable Presentation (Chip, ES256-DH)

Die VP verpackt die VC, ohne sie zu entpacken: die komplette VC-JWS wird als
String in ein Objekt vom Typ `EnvelopedVerifiableCredential` eingebettet
(`id: "data:application/vc+jwt,<VC-JWS>"`). Das VP-JSON wird dann selbst zur
Payload eines JWS und vom Chip signiert.

**0. Vorbereitung** – Holder-DID (das Gerät) erzeugen. Der Chip signiert mit
seinem eigenen, **fest vorgegebenen** Schlüssel (`BSK` in `sig_stub.rb`); dieser
muss zum `#key-doc` der Holder-DID passen. Der Key-Hex ist hier fix (nicht aus
einer Datei) und entspricht dem Default in `sig_stub.rb`:

```bash
HOLDER_SK_HEX="96fe0f41947d645c7a1858c48c7a0560e7e5bd3d45125b57a611a3a9a103626b"
HOLDER_SK=$(echo "$HOLDER_SK_HEX" | oydid hex2mb -k p256 | sed 's/private key: //')   # Multibase fuer oydid
HOLDER_DID=$(echo '{}' | oydid create --key-type p256 --doc-enc "$HOLDER_SK" --json-output | jq -r '.did')
HOLDER_DID="${HOLDER_DID/did:oyd:/did:web:oydid.ownyourdata.eu:}"
echo $HOLDER_DID
# did:web:oydid.ownyourdata.eu:zQmYmDf3nBJEGy9qznPMEsxi5CrGA9Ha61o5Gfgk5yX2XtD
```

**1. VP-Signing-Input hashen** (für den Chip):

```bash
cat credential.jws | ./build_vp.rb hash $HOLDER_DID > vp_hash.txt
# optional: AUD=<verifier> NONCE=<zufall> voranstellen (in beiden build_vp-Aufrufen identisch!)
```

**2. Chip signiert** (mit seinem eigenen `BSK`, Double-Hashing):

```bash
cat vp_hash.txt | ./sig_stub.rb > vp_sig.txt
```

**3. VP zusammensetzen:**

```bash
cat credential.jws | ./build_vp.rb assemble $HOLDER_DID vp_sig.txt > presentation.jws
```

**4. VP prüfen** – zwei Lagen: erst die äußere VP (ES256-DH, Public Key über die
Holder-DID), dann die eingebettete VC, die an `verify_jws.rb` (Standard-ES256,
Issuer-DID) delegiert wird:

```bash
cat presentation.jws | ./verify_vp.rb
# optional Erwartungswerte: EXPECT_AUD=... EXPECT_NONCE=...
```

Beide Signaturen müssen gültig sein und der `holder` im VP-Payload muss zum
VP-Signierschlüssel (`kid`) passen. Hinweis: Die innere VC ist mit Standard-
`ES256` voll JOSE-interoperabel; nur die äußere VP braucht einen
ES256-DH-fähigen Verifier.

## Warum der Header mitsigniert wird

Würde man nur den Inhalt allein signieren, könnte jemand den Header (z.B. den
`kid`, also den Schlüsselverweis) austauschen, ohne die Signatur zu brechen.
Weil sowohl bei VC als auch VP die *komplette* Signing Input (Header + Payload)
signiert wird, ist auch der Header geschützt.

## Schlüssel

Gearbeitet wird mit NIST-P-256-Schlüsselpaaren. Die VC wird mit dem
Hersteller-/Issuer-Key signiert (`ISSUER_SK`), die VP mit dem Chip-Key (`BSK` in
`sig_stub.rb`). Die Verifier bekommen den öffentlichen Schlüssel **nicht**
vorgegeben, sondern lösen ihn über die `kid`-DID im jeweiligen Header auf: das
DID-Dokument wird abgerufen und der Schlüssel aus der Verification Method
`#key-doc` (`publicKeyJwk`, P-256) gelesen. Unterstützt werden `did:web`
(Auflösung nach W3C-Regel) und `did:oyd` (über den oyd-Resolver, Basis via
`OYD_RESOLVER` änderbar).

## Mehr Details

Die genaue Algorithmus-Definition samt Test-Vektor steht in [`ES256-DH.md`](ES256-DH.md).
