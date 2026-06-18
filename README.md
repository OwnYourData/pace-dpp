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
Mit [`oydid`](https://github.com/ownYourData/oydid) ein did:oyd für die Verwendung in der JWS erzeugen:
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

## Warum der Header mitsigniert wird

Würde man nur die Credential allein signieren, könnte jemand den Header
(z.B. den `kid`, also den Schlüsselverweis) austauschen, ohne die Signatur zu
brechen. Weil hier die *komplette* Signing Input (Header + Payload) gehasht und
signiert wird, ist auch der Header geschützt.

## Schlüssel

Gearbeitet wird mit einem NIST-P-256-Schlüsselpaar. Der Stub nimmt den
privaten Schlüssel aus `BSK` (Hex) bzw. einem Default; der Verifier nimmt
den öffentlichen Schlüssel aus `PUBKEY`, `PUBKEY_FILE`, aus `BSK`
(abgeleitet) oder einem Default. Im echten Betrieb löst man den Public Key
über die `kid`-DID auf.

## Mehr Details

Die genaue Algorithmus-Definition samt Test-Vektor steht in [`ES256-DH.md`](ES256-DH.md).