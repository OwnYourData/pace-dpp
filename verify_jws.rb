#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Verwendung:
#   cat credential.jws | ./verify_jws.rb
#   ./verify_jws.rb credential.jws
#
# Der Public Key wird aus der DID im Header (`kid`) aufgeloest: 
# die DID wird zum DID-Dokument aufgeloest und der oeffentliche
# Schluessel aus der passenden Verification Method (publicKeyJwk, EC P-256)
# entnommen. Unterstuetzte DID-Methoden:
#   - did:web  -> Aufloesung nach W3C-Regel (HTTPS / did.json)
#   - did:oyd  -> Aufloesung ueber den oyd-Resolver
#
# oyd-Resolver-Basis ueber ENV['OYD_RESOLVER'] aenderbar
#   (Default: https://oydid.ownyourdata.eu/1.0/identifiers/).
#
# Exit-Code: 0 = gueltig, 1 = ungueltig/Fehler.

require 'json'
require 'base64'
require 'openssl'
require 'digest'
require 'net/http'
require 'uri'
require 'cgi'

OYD_RESOLVER = (ENV['OYD_RESOLVER'] && !ENV['OYD_RESOLVER'].strip.empty? ? ENV['OYD_RESOLVER'].strip : 'https://oydid.ownyourdata.eu/1.0/identifiers/')

def b64url_decode(str)
  Base64.urlsafe_decode64(str + '=' * ((4 - str.length % 4) % 4))
end

# EC-Public-Key (P-256) aus unkomprimiertem Punkt-Hex (04||X||Y) bauen.
def load_public_key(point_hex)
  group = OpenSSL::PKey::EC::Group.new('prime256v1')
  point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(point_hex, 16))
  asn1 = OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
      OpenSSL::ASN1::ObjectId('prime256v1')
    ]),
    OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed))
  ])
  OpenSSL::PKey::EC.new(asn1.to_der)
end

# EC-Public-Key aus einem JWK (kty=EC, crv=P-256, x/y base64url) bauen.
def public_key_from_jwk(jwk)
  raise "publicKeyJwk fehlt" if jwk.nil?
  raise "unerwarteter Schluesseltyp #{jwk['kty']}/#{jwk['crv']}" unless jwk['kty'] == 'EC' && jwk['crv'] == 'P-256'

  x = b64url_decode(jwk['x'])
  y = b64url_decode(jwk['y'])
  raise "ungueltige Koordinatenlaenge" unless x.bytesize == 32 && y.bytesize == 32

  load_public_key('04' + x.unpack1('H*') + y.unpack1('H*'))
end

# did:web -> HTTPS-URL des DID-Dokuments (W3C did:web Method Spec).
#   did:web:host                 -> https://host/.well-known/did.json
#   did:web:host:a:b:c           -> https://host/a/b/c/did.json
# (ein evtl. als %3A kodierter Port im Host-Segment wird dekodiert)
def did_web_url(did)
  segs = did.split(':')[2..] || []
  raise 'ungueltige did:web' if segs.empty?

  host = CGI.unescape(segs.shift)
  path = segs.empty? ? '.well-known/did.json' : "#{segs.join('/')}/did.json"
  "https://#{host}/#{path}"
end

# DID-Methode bestimmen und Dokument-URL ableiten.
def did_document_url(did)
  case did.split(':')[1]
  when 'web' then did_web_url(did)
  when 'oyd' then OYD_RESOLVER + did
  else raise "nicht unterstuetzte DID-Methode: #{did.split(':')[1]}"
  end
end

# HTTP GET mit JSON-Antwort (folgt bis zu 3 Redirects).
def fetch_json(url, redirects = 3)
  res = Net::HTTP.get_response(URI.parse(url))
  if res.is_a?(Net::HTTPRedirection) && redirects.positive?
    return fetch_json(res['location'], redirects - 1)
  end
  raise "Resolver-HTTP #{res.code}" unless res.is_a?(Net::HTTPSuccess)

  JSON.parse(res.body)
end

# DID-Dokument aufloesen und den Public Key zur Verification Method `kid`
# zurueckgeben.
def resolve_public_key(kid)
  did = kid.split('#').first
  doc = fetch_json(did_document_url(did))
  # Sowohl rohes DID-Dokument als auch DIF-Wrapper ({didDocument: ...}) unterstuetzen.
  doc = doc['didDocument'] if doc.is_a?(Hash) && doc.key?('didDocument')
  vms = doc['verificationMethod'] || []

  frag = kid.split('#', 2)[1]
  vm = vms.find { |m| m['id'] == kid } ||
       vms.find { |m| m['id'].to_s.end_with?("##{frag}") }
  raise "Verification Method '#{kid}' nicht im DID-Dokument gefunden" if vm.nil?

  public_key_from_jwk(vm['publicKeyJwk'])
end

# Signatur (R||S, 64 Byte) -> DER. Akzeptiert auch bereits DER-kodierte Sig.
def sig_to_der(sig)
  return sig if sig.bytesize > 64 && sig.getbyte(0) == 0x30 # bereits DER

  raise "Signatur hat #{sig.bytesize} Byte (erwartet 64 fuer R||S)." unless sig.bytesize == 64

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

header  = (JSON.parse(b64url_decode(header_b64)) rescue {})
payload = (JSON.parse(b64url_decode(payload_b64)) rescue {})
kid     = header['kid'].to_s

# --- Verifikation (ES256-DH) ------------------------------------------------
# M = SHA-256(SigningInput); SigningInput = header_b64 + "." + payload_b64
# Public Key wird ueber die DID im `kid` aufgeloest.
valid =
  begin
    raise 'kein "kid" im Header' if kid.empty?

    pubkey  = resolve_public_key(kid)
    m       = Digest::SHA256.digest("#{header_b64}.#{payload_b64}")
    der_sig = sig_to_der(b64url_decode(sig_b64))
    # ECDSA-with-SHA-256: verify hasht M intern mit SHA-256.
    pubkey.verify(OpenSSL::Digest.new('SHA256'), der_sig, m)
  rescue StandardError => e
    warn "Hinweis: Verifikation fehlgeschlagen (#{e.message})."
    false
  end

# --- Anwendungs-Checks ------------------------------------------------------
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
