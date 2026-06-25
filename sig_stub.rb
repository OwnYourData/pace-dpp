#!/usr/bin/env ruby
# frozen_string_literal: true
#
# sig_stub.rb  --  Signierbaustein (Chip) fuer das ES256-DH-Verfahren
#
# Emuliert den hardware-beschraenkten Signierbaustein: liest einen 32-Byte-Hash
# (als Hex) von stdin und gibt eine ECDSA-P256/SHA-256-Signatur in roher
# R||S-Form (64 Byte, Hex) aus. Da der Chip seinen Input intern noch einmal mit
# SHA-256 hasht, entsteht das charakteristische Double-Hashing.
#
# In dieser Demo signiert der Chip die *Verifiable Presentation* (siehe
# build_vp.rb) mit seinem eigenen Schluessel (BSK / Default).
#
# Verwendung:
#   cat vp_hash.txt | ./sig_stub.rb > vp_sig.txt

require 'openssl'

DEFAULT_BSK_HEX = '96fe0f41947d645c7a1858c48c7a0560e7e5bd3d45125b57a611a3a9a103626b'

# --- BSK (privater Schlüssel) ermitteln ------------------------------------
def resolve_bsk_hex
  if (h = ENV['BSK']) && !h.strip.empty?
    return h.strip
  end
  if (path = ENV['BSK_FILE']) && !path.strip.empty?
    return File.read(path.strip).strip
  end
  DEFAULT_BSK_HEX
end

# Baut ein OpenSSL EC-Privatkey-Objekt aus einem rohen 32-Byte-Skalar.
# Portabel über Ruby/OpenSSL-Versionen via ASN.1 ECPrivateKey (SEC1).
def load_private_key(bsk_hex)
  bsk_hex = bsk_hex.delete_prefix('0x')
  raise "BSK ist kein gueltiger Hex-String" unless bsk_hex.match?(/\A\h+\z/)

  d = OpenSSL::BN.new(bsk_hex, 16)
  group = OpenSSL::PKey::EC::Group.new('prime256v1')

  # Oeffentlichen Punkt aus dem Skalar berechnen: Q = d * G
  pub_point = group.generator.mul(d)

  # Privatkey-Skalar auf exakt 32 Byte auffuellen
  priv_octets = [bsk_hex.rjust(64, '0')].pack('H*')

  asn1 = OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::Integer(1),
    OpenSSL::ASN1::OctetString(priv_octets),
    OpenSSL::ASN1::ASN1Data.new(
      [OpenSSL::ASN1::ObjectId('prime256v1')], 0, :CONTEXT_SPECIFIC
    ),
    OpenSSL::ASN1::ASN1Data.new(
      [OpenSSL::ASN1::BitString(pub_point.to_octet_string(:uncompressed))],
      1, :CONTEXT_SPECIFIC
    )
  ])

  OpenSSL::PKey::EC.new(asn1.to_der)
end

# DER-ECDSA-Signatur -> rohe R||S Form (je 32 Byte fixed length, RFC 7518 3.4)
def der_to_raw(der)
  asn1 = OpenSSL::ASN1.decode(der)
  r = asn1.value[0].value.to_s(2) # OpenSSL::BN -> big-endian Bytes
  s = asn1.value[1].value.to_s(2)
  r.rjust(32, "\x00") + s.rjust(32, "\x00")
end

# --- Hauptlogik -------------------------------------------------------------
def main
  raw = $stdin.read.to_s

  # Whitespace/Zeilenumbrueche entfernen (z.B. aus `awk '{print $2}'`)
  hex = raw.gsub(/\s+/, '').delete_prefix('0x')

  if hex.empty?
    warn 'Fehler: keine Eingabe auf stdin.'
    exit 1
  end
  unless hex.match?(/\A\h+\z/) && hex.length.even?
    warn 'Fehler: Eingabe ist kein gueltiger Hex-String (gerade Anzahl Hex-Ziffern erwartet).'
    exit 1
  end

  challenge = [hex].pack('H*')

  # Challenge muss 1..255 Byte sein (Lc-Validierung, sonst 6700h)
  unless (1..255).cover?(challenge.bytesize)
    warn "Fehler: Challenge ist #{challenge.bytesize} Byte (erlaubt: 1..255)."
    exit 1
  end

  key = load_private_key(resolve_bsk_hex)

  # ECDSA mit SHA-256, Ergebnis ist DER-kodiert (beginnt mit 0x30).
  der_sig = key.sign(OpenSSL::Digest.new('SHA256'), challenge)

  # JWS in rohes R||S (64 Byte) umwandeln und als Hex ausgeben.
  $stdout.puts der_to_raw(der_sig).unpack1('H*')
end

main if $PROGRAM_NAME == __FILE__