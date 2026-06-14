#!/usr/bin/env ruby
# frozen_string_literal: true
#
# build_jws.rb  --  ES256-DH JWS Builder
#
# Erzeugt eine JWS (Compact Serialization) ueber eine Verifiable Credential,
# bei der der Protected Header MIT signiert wird. Da die Signatur extern
# erzeugt wird und nur <=255 Byte verarbeitet, laeuft der Vorgang in 2 Phasen:
#
#   # Phase 1: Hash der JWS Signing Input erzeugen (das, was signiert wird)
#   cat input_vc.json | ./build_jws.rb hash > input_hash.txt
#
#   # Phase 2: extern signieren -> rohes R||S als Hex
#   cat input_hash.txt | ./sig_stub.rb > output_sig.txt
#
#   # Phase 3: JWS zusammensetzen
#   ./build_jws.rb assemble input_vc.json output_sig.txt > credential.jws
#
# JWS Signing Input (RFC 7515, 5.1):
#   ASCII( BASE64URL(UTF8(Protected Header)) || '.' || BASE64URL(Payload) )
# Der ausgegebene Hash ist SHA-256(SigningInput) -> 32 Byte ( <= 255Bytes)
#
# Header:
#   alg : ES256-DH (URL, siehe ALG)
#   typ : "JWT"
#   kid : <issuer-DID aus input_vc.json> + "#key-doc"
#
# Payload:
#   BASE64URL der *exakten* Bytes von input_vc.json (byte-identisch zu dem,
#   was gehasht/signiert wurde).

require 'json'
require 'base64'
require 'openssl'
require 'digest'

ALG = 'https://github.com/OwnYourData/pace-dpp/blob/main/ES256-DH.md'
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

# Deterministischer Protected Header (in hash- und assemble-Phase identisch).
def protected_header(vc_json)
  JSON.generate(
    'alg' => ALG,
    'typ' => TYP,
    'kid' => issuer_did(vc_json) + KEY_FRAGMENT
  )
end

# JWS Signing Input = b64url(header) + "." + b64url(payload)
def signing_input(vc_bytes)
  vc_json = JSON.parse(vc_bytes)
  b64url(protected_header(vc_json)) + '.' + b64url(vc_bytes)
end

# Signatur in rohes R||S (64 Byte) normalisieren
# Akzeptiert R||S (64 Byte) oder DER (beginnt mit 0x30)
def normalize_sig(bytes)
  return bytes if bytes.bytesize == 64

  if bytes.getbyte(0) == 0x30
    asn1 = OpenSSL::ASN1.decode(bytes)
    r = asn1.value[0].value.to_s(2)
    s = asn1.value[1].value.to_s(2)
    return r.rjust(32, "\x00") + s.rjust(32, "\x00")
  end
  raise "Unerwartetes Signaturformat (#{bytes.bytesize} Byte, kein R||S, kein DER)."
end

def read_sig_hex(path)
  hex = File.read(path).gsub(/\s+/, '').delete_prefix('0x')
  raise 'Signaturdatei enthaelt kein gueltiges Hex.' unless hex.match?(/\A\h+\z/) && hex.length.even?

  [hex].pack('H*')
end

# --- CLI --------------------------------------------------------------------
mode = ARGV[0]

case mode
when 'hash'
  vc_path = ARGV[1] || 'input_vc.json'
  vc_bytes = File.binread(vc_path)
  # SHA-256 der Signing Input -> Hex
  $stdout.puts Digest::SHA256.hexdigest(signing_input(vc_bytes))

when 'assemble'
  vc_path  = ARGV[1] || 'input_vc.json'
  sig_path = ARGV[2] || 'output_sig.txt'
  vc_bytes = File.binread(vc_path)
  sig_raw  = normalize_sig(read_sig_hex(sig_path))

  jws = signing_input(vc_bytes) + '.' + b64url(sig_raw)
  $stdout.puts jws

else
  warn <<~USAGE
    Usage:
      ruby build_jws.rb hash     [input_vc.json]                 > input_hash.txt
      ruby build_jws.rb assemble [input_vc.json] [output_sig.txt] > credential.jws
  USAGE
  exit 1
end