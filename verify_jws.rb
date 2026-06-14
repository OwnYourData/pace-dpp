#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Verwendung:
#   cat credential.jws | ./verify_jws.rb
#
# Public Key (NIST P-256, unkomprimiert 04||X||Y) wird gesucht in:
#   1. ENV['PUBKEY']        -> Hex (65 Byte, 04...)
#   2. ENV['PUBKEY_FILE']   -> Pfad zu Datei mit dem Hex
#   3. ENV['BSK']           -> Privatkey-Hex, Pubkey wird abgeleitet
#   4. Eingebauter Test-Public-Key (siehe DEFAULT_PUBKEY_HEX)
#
# Exit-Code: 0 = gueltig, 1 = ungueltig/Fehler.

require 'json'
require 'base64'
require 'openssl'
require 'digest'

# Test-Public-Key (gehoert zum Test-Privatkey aus ES256-DH.md, nur fuer Tests).
DEFAULT_PUBKEY_HEX =
  '04bcad0c43ac859d0552d95b639156073f9c1c4fb1aa9490f3639a8cf0a2aaadaa4' \
  '7701058367e000770437b32b35530848039317d963679927ab4112832b1838f'

def b64url_decode(str)
  Base64.urlsafe_decode64(str + '=' * ((4 - str.length % 4) % 4))
end

# Public Key (unkomprimiert, Hex) -> OpenSSL EC-Objekt (via SubjectPublicKeyInfo)
def load_public_key(hex)
  hex = hex.delete_prefix('0x')
  group = OpenSSL::PKey::EC::Group.new('prime256v1')
  point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(hex, 16))
  asn1 = OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
      OpenSSL::ASN1::ObjectId('prime256v1')
    ]),
    OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed))
  ])
  OpenSSL::PKey::EC.new(asn1.to_der)
end

# Pubkey aus Privatkey-Skalar ableiten (Fallback fuer ENV['BSK']).
def pubkey_from_bsk(bsk_hex)
  d = OpenSSL::BN.new(bsk_hex.delete_prefix('0x'), 16)
  group = OpenSSL::PKey::EC::Group.new('prime256v1')
  group.generator.mul(d).to_octet_string(:uncompressed).unpack1('H*')
end

def resolve_public_key
  if (h = ENV['PUBKEY']) && !h.strip.empty?
    load_public_key(h.strip)
  elsif (path = ENV['PUBKEY_FILE']) && !path.strip.empty?
    load_public_key(File.read(path.strip).strip)
  elsif (bsk = ENV['BSK']) && !bsk.strip.empty?
    load_public_key(pubkey_from_bsk(bsk.strip))
  else
    load_public_key(DEFAULT_PUBKEY_HEX)
  end
end

# Signatur (R||S, 64 Byte) -> DER. Akzeptiert auch bereits DER-kodierte Sig.
def sig_to_der(sig)
  return sig if sig.bytesize > 64 && sig.getbyte(0) == 0x30 # bereits DER

  unless sig.bytesize == 64
    raise "Signatur hat #{sig.bytesize} Byte (erwartet 64 fuer R||S)."
  end

  r = OpenSSL::BN.new(sig[0, 32].unpack1('H*'), 16)
  s = OpenSSL::BN.new(sig[32, 32].unpack1('H*'), 16)
  OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
end

def issuer_did(vc)
  iss = vc['issuer'] || (vc['vc'] && vc['vc']['issuer'])
  case iss
  when String then iss
  when Hash   then iss['id']
  end
end

# --- Einlesen ---------------------------------------------------------------
jws = (ARGV[0] ? File.read(ARGV[0]) : $stdin.read).strip
parts = jws.split('.')
unless parts.length == 3
  warn 'Fehler: keine gueltige JWS Compact Serialization (erwartet 3 Teile).'
  exit 1
end
header_b64, payload_b64, sig_b64 = parts

# --- Verifikation (ES256-DH) ------------------------------------------------
# M = SHA-256(SigningInput); SigningInput = header_b64 + "." + payload_b64
# Die Signatur wird VOR dem Parsen der Payload geprueft, damit auch
# manipulierte/ungueltige Payloads sauber als UNGUELTIG gemeldet werden.
valid =
  begin
    m       = Digest::SHA256.digest("#{header_b64}.#{payload_b64}")
    pubkey  = resolve_public_key
    der_sig = sig_to_der(b64url_decode(sig_b64))
    # ECDSA-with-SHA-256: verify hasht M intern mit SHA-256.
    pubkey.verify(OpenSSL::Digest.new('SHA256'), der_sig, m)
  rescue StandardError => e
    warn "Hinweis: Verifikation fehlgeschlagen (#{e.message})."
    false
  end

# --- Header / Anwendungs-Checks (Abschnitt 7.6) -----------------------------
header    = (JSON.parse(b64url_decode(header_b64)) rescue {})
payload   = (JSON.parse(b64url_decode(payload_b64)) rescue {})
kid       = header['kid'].to_s
iss_did   = issuer_did(payload).to_s
kid_did   = kid.split('#').first
issuer_ok = !iss_did.empty? && kid_did == iss_did

# --- Ausgabe ----------------------------------------------------------------
puts "alg:           #{header['alg']}"
puts "kid:           #{kid}"
puts "issuer:        #{iss_did}"
puts "kid == issuer: #{issuer_ok ? 'ja' : 'NEIN'}"
puts "Signatur:      #{valid ? 'GUELTIG' : 'UNGUELTIG'}"

exit(valid && issuer_ok ? 0 : 1)