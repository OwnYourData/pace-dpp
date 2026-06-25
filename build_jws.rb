#!/usr/bin/env ruby
# frozen_string_literal: true
#
# build_jws.rb  --  Verifiable Credential (VC) als JWS signieren
#
# Signiert eine Verifiable Credential mit dem Private Key der Hersteller-DID
# (Issuer) als JWS. Es wird *Standard-ES256* (RFC 7518) verwendet - der
# Hersteller-Key ist ein normaler Software-Schluessel ohne Größenlimit, daher
# wird in einem Schritt direkt über die JWS Signing Input signiert.
#
# (Das spezielle ES256-DH-Verfahren mit Double-Hashing wird in dieser
# Demo nur fuer die *Verifiable Presentation* genutzt - siehe build_vp.rb.)
#
# Verwendung:
#   cat input_vc.json | ./build_jws.rb [issuer-privkey-hex] > credential.jws
#
# VC          : von stdin (oder Datei als 2. Argument nach dem Key entfällt)
# Issuer-Key  : ARGV[0] oder ENV['ISSUER_SK'] (Hex) oder ENV['ISSUER_SK_FILE']
#
# Header:
#   alg : "ES256"
#   typ : "JWT"
#   kid : <issuer-DID aus input_vc.json> + "#key-doc"
# Payload:
#   BASE64URL der *exakten* Bytes von input_vc.json.

require 'json'
require 'base64'
require 'openssl'

ALG = 'ES256'
TYP = 'JWT'
KEY_FRAGMENT = '#key-doc'

def b64url(bytes)
  Base64.urlsafe_encode64(bytes, padding: false)
end

def issuer_did(vc)
  iss = vc['issuer'] || (vc['vc'] && vc['vc']['issuer'])
  did =
    case iss
    when String then iss
    when Hash   then iss['id']
    end
  raise 'Konnte issuer-DID nicht aus input_vc.json lesen (Feld "issuer").' if did.nil? || did.empty?

  did
end

def protected_header(vc_json)
  JSON.generate('alg' => ALG, 'typ' => TYP, 'kid' => issuer_did(vc_json) + KEY_FRAGMENT)
end

# JWS Signing Input = b64url(header) + "." + b64url(payload)
def signing_input(vc_bytes)
  vc_json = JSON.parse(vc_bytes)
  b64url(protected_header(vc_json)) + '.' + b64url(vc_bytes)
end

# EC-Privatkey (P-256) aus rohem 32-Byte-Skalar (Hex). Portabel via ASN.1 SEC1.
def load_private_key(sk_hex)
  sk_hex = sk_hex.delete_prefix('0x')
  unless sk_hex.match?(/\A\h+\z/)
    raise "Issuer-Privatkey ist kein gueltiger Hex-String (erwartet rohen 32-Byte-Hex). " \
          "Multibase wie 'z...' wird nicht unterstuetzt - vorher mit `oydid mb2hex` nach Hex wandeln."
  end

  d = OpenSSL::BN.new(sk_hex, 16)
  group = OpenSSL::PKey::EC::Group.new('prime256v1')
  pub_point = group.generator.mul(d)
  priv_octets = [sk_hex.rjust(64, '0')].pack('H*')

  asn1 = OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::Integer(1),
    OpenSSL::ASN1::OctetString(priv_octets),
    OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId('prime256v1')], 0, :CONTEXT_SPECIFIC),
    OpenSSL::ASN1::ASN1Data.new(
      [OpenSSL::ASN1::BitString(pub_point.to_octet_string(:uncompressed))], 1, :CONTEXT_SPECIFIC
    )
  ])
  OpenSSL::PKey::EC.new(asn1.to_der)
end

# DER-ECDSA-Signatur -> rohe R||S Form (RFC 7518 3.4)
def der_to_raw(der)
  asn1 = OpenSSL::ASN1.decode(der)
  r = asn1.value[0].value.to_s(2)
  s = asn1.value[1].value.to_s(2)
  r.rjust(32, "\x00") + s.rjust(32, "\x00")
end

# --- Eingaben ---------------------------------------------------------------
sk_hex = ARGV[0] || ENV['ISSUER_SK'] ||
         (ENV['ISSUER_SK_FILE'] && !ENV['ISSUER_SK_FILE'].strip.empty? ? File.read(ENV['ISSUER_SK_FILE'].strip).strip : nil)
abort 'Fehler: Issuer-Privatkey fehlt (ARGV[0] oder ENV ISSUER_SK / ISSUER_SK_FILE).' if sk_hex.nil? || sk_hex.strip.empty?

$stdin.binmode
vc_bytes = $stdin.read.to_s
abort 'Fehler: keine VC auf stdin (erwartet: cat input_vc.json | ...).' if vc_bytes.strip.empty?

# --- Signieren (Standard-ES256) ---------------------------------------------
si  = signing_input(vc_bytes)
key = load_private_key(sk_hex.strip)
# Standard-ES256: ECDSA-SHA256 direkt ueber die Signing Input (kein Vor-Hash).
der_sig = key.sign(OpenSSL::Digest.new('SHA256'), si)

$stdout.puts si + '.' + b64url(der_to_raw(der_sig))
