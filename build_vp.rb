#!/usr/bin/env ruby
# frozen_string_literal: true
#
# build_vp.rb  --  Verifiable Presentation (VP) aus einer enveloped VC bauen
#
# Verpackt eine bestehende VC-JWS (credential.jws, per ES256-DH
# signiert) in eine Verifiable Presentation und signiert die VP mit dem
# Schluessel des Holders (Hersteller). Die aeussere VP-Huelle verwendet
# *Standard-ES256* (RFC 7518) - der Holder-Key hat kein 255-Byte-Limit.
#
# Die VC wird nach W3C "Securing VCs using JOSE and COSE" als enveloped
# Credential eingebettet: die komplette VC-JWS steht als data:-URI im Feld
# `id` eines Objekts vom Typ `EnvelopedVerifiableCredential`.
#
# Verwendung:
#   cat credential.jws | ./build_vp.rb <holder-DID> [holder-privkey-hex] > presentation.jws
#
# VC-JWS      : von stdin
# Holder-DID  : ARGV[0] oder ENV['HOLDER_DID']
# Holder-Key  : ARGV[1] oder ENV['HOLDER_SK'] (Hex) oder ENV['HOLDER_SK_FILE']
# Optional    : ENV['AUD'] (Ziel-Verifier), ENV['NONCE'] (Replay-Schutz)
#
# Ausgabe: VP-JWS (Compact Serialization) auf stdout.

require 'json'
require 'base64'
require 'openssl'

ALG = 'ES256'                 # Standard-JOSE fuer die aeussere VP-Huelle
TYP = 'vp+jwt'
KEY_FRAGMENT = '#key-doc'
VC_MEDIA_TYPE = 'application/vc+jwt'
VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2'

def b64url(bytes)
  Base64.urlsafe_encode64(bytes, padding: false)
end

# EC-Privatkey (P-256) aus rohem 32-Byte-Skalar (Hex). Portabel via ASN.1 SEC1.
def load_private_key(bsk_hex)
  bsk_hex = bsk_hex.delete_prefix('0x')
  raise 'Holder-Privatkey ist kein gueltiger Hex-String' unless bsk_hex.match?(/\A\h+\z/)

  d = OpenSSL::BN.new(bsk_hex, 16)
  group = OpenSSL::PKey::EC::Group.new('prime256v1')
  pub_point = group.generator.mul(d)
  priv_octets = [bsk_hex.rjust(64, '0')].pack('H*')

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
# Die VC-JWS kommt von stdin; Holder-DID und -Key als Argumente bzw. ENV.
holder_did = ARGV[0] || ENV['HOLDER_DID']
sk_hex     = ARGV[1] || ENV['HOLDER_SK'] ||
             (ENV['HOLDER_SK_FILE'] && !ENV['HOLDER_SK_FILE'].strip.empty? ? File.read(ENV['HOLDER_SK_FILE'].strip).strip : nil)

abort 'Fehler: Holder-DID fehlt (ARGV[0] oder ENV HOLDER_DID).' if holder_did.nil? || holder_did.strip.empty?
abort 'Fehler: Holder-Privatkey fehlt (ARGV[1] oder ENV HOLDER_SK / HOLDER_SK_FILE).' if sk_hex.nil? || sk_hex.strip.empty?

vc_jws = $stdin.read.to_s.strip
abort 'Fehler: keine VC-JWS auf stdin (erwartet: cat credential.jws | ...).' unless vc_jws.count('.') == 2

# --- VP-Dokument ------------------------------------------------------------
vp = {
  '@context' => [VC_CONTEXT],
  'type' => ['VerifiablePresentation'],
  'holder' => holder_did,
  'verifiableCredential' => [
    {
      '@context' => VC_CONTEXT,
      'type' => 'EnvelopedVerifiableCredential',
      'id' => "data:#{VC_MEDIA_TYPE},#{vc_jws}"
    }
  ]
}
vp['aud']   = ENV['AUD']   if ENV['AUD'] && !ENV['AUD'].strip.empty?
vp['nonce'] = ENV['NONCE'] if ENV['NONCE'] && !ENV['NONCE'].strip.empty?

# --- JWS (Standard-ES256) ---------------------------------------------------
header  = JSON.generate('alg' => ALG, 'typ' => TYP, 'kid' => holder_did + KEY_FRAGMENT)
payload = JSON.generate(vp)
signing_input = b64url(header) + '.' + b64url(payload)

key = load_private_key(sk_hex.strip)
# Standard-ES256: ECDSA-SHA256 direkt ueber die Signing Input (kein Vor-Hash).
der_sig = key.sign(OpenSSL::Digest.new('SHA256'), signing_input)

$stdout.puts signing_input + '.' + b64url(der_to_raw(der_sig))
