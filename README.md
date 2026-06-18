# JWS mit ES256-DH

Kurz gesagt: Wir packen eine Verifiable Credential in ein JWS, aber die
eigentliche Signatur kommt von einem externen Signierbaustein, der nur kleine
Datenmengen (max. 255 Byte) verarbeiten kann. Deshalb wird nicht der ganze
Token signiert, sondern dessen Hash. Das Verfahren heißt hier **ES256-DH** –
im Kern ganz normales ECDSA über P-256 mit SHA-256, nur mit einem zusätzlichen
Hash-Schritt davor.

## Die drei Bausteine

- **[`sig_stub.rb`](sig_stub.rb)** – simuliert den Signierbaustein. Bekommt einen 32-Byte-Hash
  (als Hex) und gibt eine Signatur aus. Ein echter Chip könnte z.B. an dieser
  Stelle stehen.
- **[`build_jws.rb`](build_jws.rb)** – baut das JWS. Läuft in zwei Schritten: erst rechnet es aus,
  *was* signiert werden muss, am Ende setzt es alles zusammen.
- **[`verify_jws.rb`](verify_jws.rb)** – prüft am Ende, ob die Signatur stimmt.

## Der Ablauf in drei Schritten

**0. Vorbereitung**
Mit [`oydid`](https://github.com/ownYourData/oydid) ein did:oyd / did:web für die Verwendung in der JWS erzeugen:
```bash
SK=$(echo "96fe0f41947d645c7a1858c48c7a0560e7e5bd3d45125b57a611a3a9a103626b" | \
  oydid hex2mb -k p256 | sed 's/private key: //')
DID=$(echo '{}' | oydid create --key-type p256 --doc-enc "$SK" --json-output | jq -r '.did')
DID="${DID/did:oyd:/did:web:oydid.ownyourdata.eu:}"
echo $DID
# did:web:oydid.ownyourdata.eu:zQmSUfZw3pmTKsDCJL7STB66SusH3wswhBFz73eWkfYTGWd
```
überprüfen:
```bash
oydid read zQmSUfZw3pmTKsDCJL7STB66SusH3wswhBFz73eWkfYTGWd
echo z4oJ8dYxWkgUe1bxnyhhiSRrhF19baQncEdr8JYgaJtAAJYVUhSBWMdqcJwpEZdLmBXVe7HKfZeRXJ5HfPKFpZNe1iPta | \
  oydid mb2hex
# must match public key in hex
```

**1. Ausrechnen, was signiert wird**

`build_jws.rb` baut den Header (mit `alg`, `typ` und der Issuer-DID als `kid`)
und die Payload (die Credential), klebt beides zum sogenannten *Signing Input*
zusammen und hasht das Ergebnis. Heraus kommt ein 32-Byte-Hash – genau die
Größe, die der Signierbaustein braucht.

```bash
cat input_vc.json | ./build_jws.rb hash > input_hash.txt
```

**2. Signieren**

Der Hash geht an den Baustein (hier: den Stub), zurück kommt die Signatur als
rohes R||S (64 Byte).

```bash
cat input_hash.txt | ./sig_stub.rb > output_sig.txt
```

**3. Zusammensetzen**

`build_jws.rb` fügt Header, Payload und Signatur zum fertigen JWS zusammen.

```bash
./build_jws.rb assemble input_vc.json output_sig.txt > credential.jws
```

Fertig ist das JWS in der Form `Header.Payload.Signatur` (jeweils Base64URL).

## Gegenprüfen

```bash
cat credential.jws | ./verify_jws.rb
```

Der Verifier baut die Signing Input genauso wieder zusammen, hasht sie und
prüft die Signatur gegen den Public Key. Wird am Token irgendwas verändert –
sei es in der Payload oder im Header – fällt die Prüfung durch.

## Eine Verifiable Presentation bauen

Die VC oben wird vom Issuer signiert. Eine **Verifiable
Presentation (VP)** verpackt diese VC und wird vom **Hersteller** (Holder)
signiert. Rollen in dieser Demo:

- Issuer der VC (signiert mit ES256-DH wegen des 255-Byte-Limits)
- Hersteller/Holder der VP (signiert mit *normalem* `ES256`, da der
  Holder-Key kein Hardware-Limit hat)

Die VC wird dabei nicht entpackt: die komplette VC-JWS wird als String in ein
Objekt vom Typ `EnvelopedVerifiableCredential` eingebettet
(`id: "data:application/vc+jwt,<VC-JWS>"`), das VP-JSON wird dann selbst zur
Payload eines JWS. Die VC-Signatur steckt also als drittes Segment der
eingebetteten VC-JWS-Zeichenkette mit im signierten VP-Payload.

### Ablauf
**0. Vorbereitung**
Mit [`oydid`](https://github.com/ownYourData/oydid) ein did:oyd / did:web für den Holder erzeugen:
```bash
HOLDER_DID=$(echo '{}' | oydid create --key-type p256 --json-output | jq -r '.did')
HOLDER_DID="${HOLDER_DID/did:oyd:/did:web:oydid.ownyourdata.eu:}"
echo $HOLDER_DID
# did:web:oydid.ownyourdata.eu:zQmPRxEdMp8up4vkigLcVmF7CprTzL345iBtiAugc8Czr9V

HOLDER_SK=$(cat zQmPRxEdMp_private_key.enc | oydid mb2hex)
```

**1. VP aus VC erstellen**
```bash
cat credential.jws | ./build_vp.rb $HOLDER_DID $HOLDER_SK > presentation.jws
# optional: AUD=<verifier> NONCE=<zufall> als Replay-Schutz voranstellen
```

**2. VP prüfen**
Prüfen mit [`verify_vp.rb`](verify_vp.rb) – zwei Lagen: erst die äußere VP
(ES256, Public Key über die Holder-DID), dann die eingebettete VC, die an
`verify_jws.rb` (ES256-DH, Issuer-DID) delegiert wird:

```bash
cat presentation.jws | ./verify_vp.rb
# optional Erwartungswerte: EXPECT_AUD=... EXPECT_NONCE=...
```

Beide Signaturen müssen gültig sein und der `holder` im VP-Payload muss zum
VP-Signierschlüssel (`kid`) passen. Hinweis: Die äußere VP ist mit Standard-
`ES256` voll JOSE-interoperabel; nur die innere VC braucht einen
ES256-DH-fähigen Verifier.

## Warum der Header mitsigniert wird

Würde man nur die Credential allein signieren, könnte jemand den Header
(z.B. den `kid`, also den Schlüsselverweis) austauschen, ohne die Signatur zu
brechen. Weil hier die *komplette* Signing Input (Header + Payload) gehasht und
signiert wird, ist auch der Header geschützt.

## Schlüssel

Gearbeitet wird mit einem NIST-P-256-Schlüsselpaar. Der Stub nimmt den
privaten Schlüssel aus `BSK` (Hex) bzw. einem Default. Der Verifier bekommt
den öffentlichen Schlüssel **nicht** vorgegeben, sondern löst ihn über die
`kid`-DID im Header auf: das DID-Dokument wird abgerufen und der Schlüssel aus
der Verification Method `#key-doc` (`publicKeyJwk`, P-256) gelesen. Unterstützt
werden `did:web` (Auflösung nach W3C-Regel) und `did:oyd` (über den
oyd-Resolver, Basis via `OYD_RESOLVER` änderbar).

## Mehr Details

Die genaue Algorithmus-Definition samt Test-Vektor steht in [`ES256-DH.md`](ES256-DH.md).