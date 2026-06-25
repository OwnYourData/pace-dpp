#!/usr/bin/env ruby
# frozen_string_literal: true
#
# build_vp.rb  --  Verifiable Presentation (VP) aus einer enveloped VC bauen
#
# Verpackt eine bestehende VC-JWS (credential.jws) in eine Verifiable
# Presentation und signiert die VP mit dem speziellen *ES256-DH*-Verfahren
# (Double-Hashing). Die Signatur wird extern vom Signierbaustein (Chip,
# sig_stub.rb) erzeugt, der nur <=255 Byte verarbeitet - daher zwei Phasen:
#
#   # Phase 1: Hash der VP Signing Input erzeugen (das, was signiert wird)
#   cat credential.jws | ./build_vp.rb hash <holder-DID> > vp_hash.txt
#
#   # Phase 2: extern signieren (Chip mit eigenem Key) -> rohes R||S als Hex
#   cat vp_hash.txt | ./sig_stub.rb > vp_sig.txt
#
#   # Phase 3: VP-JWS zusammensetzen
#   cat credential.jws | ./build_vp.rb assemble <holder-DID> vp_sig.txt > presentation.jws
#
# Der Holder-Key liegt im Chip (sig_stub.rb); build_vp.rb braucht daher
# keinen privaten Schluessel - nur die Holder-DID fuer den `kid`.
#
# Die VC wird nach W3C "Securing VCs using JOSE and COSE" als enveloped
# Credential eingebettet (data:-URI im Feld `id`, Typ
# EnvelopedVerifiableCredential).
#
# VC-JWS      : von stdin
# Holder-DID  : ARGV[1] oder ENV['HOLDER_DID']
# Optional    : ENV['AUD'] (Ziel-Verifier), ENV['NONCE'] (Replay-Schutz)
#
# Header der VP:
#   alg : ES256-DH (URL, siehe ALG)   -> Double-Hash-Verfahren
#   typ : "vp+jwt"
#   kid : <holder-DID> + "#key-doc"

require 'json'
require 'base64'
require 'openssl'
require 'digest'

ALG = 'https://github.com/OwnYourData/pace-dpp/blob/main/ES256-DH.md'
TYP = 'vp+jwt'
KEY_FRAGMENT = '#key-doc'
VC_MEDIA_TYPE = 'application/vc+jwt'
VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2'

def b64url(bytes)
  Base64.urlsafe_encode64(bytes, padding: false)
end

# Deterministische VP Signing Input aus VC-JWS und Holder-DID (in hash- und
# assemble-Phase identisch, sofern AUD/NONCE gleich gesetzt sind).
def vp_signing_input(vc_jws, holder_did)
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

  header = JSON.generate('alg' => ALG, 'typ' => TYP, 'kid' => holder_did + KEY_FRAGMENT)
  b64url(header) + '.' + b64url(JSON.generate(vp))
end

# Signatur in rohes R||S (64 Byte) normalisieren (R||S oder DER akzeptiert).
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
mode       = ARGV[0]
holder_did = ARGV[1] || ENV['HOLDER_DID']
vc_jws     = $stdin.read.to_s.strip

abort 'Fehler: Holder-DID fehlt (ARGV[1] oder ENV HOLDER_DID).' if holder_did.nil? || holder_did.strip.empty?
abort 'Fehler: keine VC-JWS auf stdin (erwartet: cat credential.jws | ...).' unless vc_jws.count('.') == 2

case mode
when 'hash'
  # SHA-256 der VP Signing Input -> Hex (Eingabe fuer Chip / sig_stub.rb)
  $stdout.puts Digest::SHA256.hexdigest(vp_signing_input(vc_jws, holder_did))

when 'assemble'
  sig_path = ARGV[2] || 'vp_sig.txt'
  sig_raw  = normalize_sig(read_sig_hex(sig_path))
  $stdout.puts vp_signing_input(vc_jws, holder_did) + '.' + b64url(sig_raw)

else
  warn <<~USAGE
    Usage:
      cat credential.jws | ruby build_vp.rb hash     <holder-DID>            > vp_hash.txt
      cat credential.jws | ruby build_vp.rb assemble <holder-DID> vp_sig.txt > presentation.jws
  USAGE
  exit 1
end
