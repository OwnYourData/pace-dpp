#!/usr/bin/env ruby
# frozen_string_literal: true
#
# verify_vp.rb  --  Verifiable Presentation (VP) pruefen
#
# Zwei Lagen:
#   1. Aeussere VP-Huelle: ES256-DH (Double-Hash), Public Key ueber die
#      Holder-DID (`kid`) aufgeloest. Plus Struktur-/Bindungs-Checks.
#   2. Eingebettete VC (EnvelopedVerifiableCredential, data:application/vc+jwt):
#      wird extrahiert und an verify_jws.rb (Standard-ES256) delegiert.
#
# Verwendung:
#   cat presentation.jws | ./verify_vp.rb
#
# Optionale Erwartungswerte: ENV['EXPECT_AUD'], ENV['EXPECT_NONCE'].
# Exit-Code: 0 = beide Lagen gueltig & Checks ok, sonst 1.

require 'json'
require 'base64'
require 'openssl'
require 'net/http'
require 'uri'
require 'cgi'
require 'open3'

OYD_RESOLVER = (ENV['OYD_RESOLVER'] && !ENV['OYD_RESOLVER'].strip.empty? ? ENV['OYD_RESOLVER'].strip : 'https://oydid.ownyourdata.eu/1.0/identifiers/')

def b64url_decode(str)
  Base64.urlsafe_decode64(str + '=' * ((4 - str.length % 4) % 4))
end

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

def public_key_from_jwk(jwk)
  raise 'publicKeyJwk fehlt' if jwk.nil?
  raise "unerwarteter Schluesseltyp #{jwk['kty']}/#{jwk['crv']}" unless jwk['kty'] == 'EC' && jwk['crv'] == 'P-256'

  x = b64url_decode(jwk['x'])
  y = b64url_decode(jwk['y'])
  load_public_key('04' + x.unpack1('H*') + y.unpack1('H*'))
end

def did_web_url(did)
  segs = did.split(':')[2..] || []
  raise 'ungueltige did:web' if segs.empty?

  host = CGI.unescape(segs.shift)
  path = segs.empty? ? '.well-known/did.json' : "#{segs.join('/')}/did.json"
  "https://#{host}/#{path}"
end

def did_document_url(did)
  case did.split(':')[1]
  when 'web' then did_web_url(did)
  when 'oyd' then OYD_RESOLVER + did
  else raise "nicht unterstuetzte DID-Methode: #{did.split(':')[1]}"
  end
end

def fetch_json(url, redirects = 3)
  res = Net::HTTP.get_response(URI.parse(url))
  return fetch_json(res['location'], redirects - 1) if res.is_a?(Net::HTTPRedirection) && redirects.positive?
  raise "Resolver-HTTP #{res.code}" unless res.is_a?(Net::HTTPSuccess)

  JSON.parse(res.body)
end

def resolve_public_key(kid)
  did = kid.split('#').first
  doc = fetch_json(did_document_url(did))
  doc = doc['didDocument'] if doc.is_a?(Hash) && doc.key?('didDocument')
  vms = doc['verificationMethod'] || []
  frag = kid.split('#', 2)[1]
  vm = vms.find { |m| m['id'] == kid } || vms.find { |m| m['id'].to_s.end_with?("##{frag}") }
  raise "Verification Method '#{kid}' nicht im DID-Dokument gefunden" if vm.nil?

  public_key_from_jwk(vm['publicKeyJwk'])
end

def sig_to_der(sig)
  return sig if sig.bytesize > 64 && sig.getbyte(0) == 0x30
  raise "Signatur hat #{sig.bytesize} Byte (erwartet 64 fuer R||S)." unless sig.bytesize == 64

  r = OpenSSL::BN.new(sig[0, 32].unpack1('H*'), 16)
  s = OpenSSL::BN.new(sig[32, 32].unpack1('H*'), 16)
  OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
end

# --- VP einlesen ------------------------------------------------------------
vp_jws = (ARGV[0] ? File.read(ARGV[0]) : $stdin.read).strip
parts = vp_jws.split('.')
unless parts.length == 3
  warn 'Fehler: keine gueltige JWS Compact Serialization (erwartet 3 Teile).'
  exit 1
end
h_b64, p_b64, s_b64 = parts

header  = (JSON.parse(b64url_decode(h_b64)) rescue {})
payload = (JSON.parse(b64url_decode(p_b64)) rescue {})
kid     = header['kid'].to_s

# --- Lage 1: aeussere VP-Signatur (ES256-DH, Double-Hash) -------------------
outer_valid =
  begin
    raise 'kein "kid" im VP-Header' if kid.empty?

    pubkey  = resolve_public_key(kid)
    der_sig = sig_to_der(b64url_decode(s_b64))
    # ES256-DH: signierte Nachricht ist M = SHA-256(SigningInput).
    m = OpenSSL::Digest::SHA256.digest("#{h_b64}.#{p_b64}")
    pubkey.verify(OpenSSL::Digest.new('SHA256'), der_sig, m)
  rescue StandardError => e
    warn "Hinweis: VP-Verifikation fehlgeschlagen (#{e.message})."
    false
  end

# --- Struktur- & Bindungs-Checks --------------------------------------------
types       = Array(payload['type'])
is_vp       = types.include?('VerifiablePresentation')
holder      = payload['holder'].to_s
holder_bind = !holder.empty? && holder == kid.split('#').first

aud_ok   = ENV['EXPECT_AUD'].nil?   || ENV['EXPECT_AUD']   == payload['aud'].to_s
nonce_ok = ENV['EXPECT_NONCE'].nil? || ENV['EXPECT_NONCE'] == payload['nonce'].to_s

# --- eingebettete VC extrahieren --------------------------------------------
vc_entry = Array(payload['verifiableCredential']).find { |e| e.is_a?(Hash) && Array(e['type']).include?('EnvelopedVerifiableCredential') }
inner_jws = nil
if vc_entry && vc_entry['id'].to_s.start_with?('data:')
  inner_jws = vc_entry['id'].to_s.sub(/\Adata:[^,]*,/, '')
end

# --- Lage 2: innere VC an verify_jws.rb delegieren --------------------------
inner_valid = false
inner_report = '(keine eingebettete VC gefunden)'
if inner_jws
  script = File.join(__dir__, 'verify_jws.rb')
  inner_report, status = Open3.capture2e('ruby', script, stdin_data: inner_jws)
  inner_valid = status.success?
end

# --- Ausgabe ----------------------------------------------------------------
puts '== VP (aeussere Huelle, ES256-DH / Double-Hash) =='
puts "alg / typ:            #{header['alg']} / #{header['typ']}"
puts "holder (kid):         #{kid}"
puts "type=VerifiablePresentation: #{is_vp ? 'ja' : 'NEIN'}"
puts "holder == VP-Signer:  #{holder_bind ? 'ja' : 'NEIN'}"
puts "aud erwartet:         #{ENV['EXPECT_AUD'] ? (aud_ok ? 'ok' : 'MISMATCH') : '-'}"
puts "nonce erwartet:       #{ENV['EXPECT_NONCE'] ? (nonce_ok ? 'ok' : 'MISMATCH') : '-'}"
puts "VP-Signatur:          #{outer_valid ? 'GUELTIG' : 'UNGUELTIG'}"
puts
puts '== eingebettete VC (Lage 2, Standard-ES256 via verify_jws.rb) =='
puts inner_report.gsub(/^/, '  ').rstrip
puts "VC gesamt:            #{inner_valid ? 'GUELTIG' : 'UNGUELTIG'}"

ok = outer_valid && is_vp && holder_bind && aud_ok && nonce_ok && inner_valid
puts
puts "Gesamtergebnis:       #{ok ? 'GUELTIG' : 'UNGUELTIG'}"
exit(ok ? 0 : 1)
