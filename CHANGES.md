0.5.0 (2015-12-04):
* avoid dependency on sexplib.syntax (#55)
* document how to combine extensions and a CSR into a certificate (@reynir, #63 #64)
* expose `fingerprint : t -> hash -> Cstruct.t`, the hash of the certificate (@cfcs, #66)
* trust_fingerprint / server_fingerprint are renamed to trust_cert_fingerprint / server_cert_fingerprint (now deprecated!)
* fingerprint public keys (rather than certificates): trust_key_fingerprint / server_key_fingerprint
* build certificate paths from the received set (RFC 4158) instead of requiring a strict chain (#74)

0.4.0 (2015-07-02):
* certificate signing request support (PKCS10)
* basic CA functionality (in CA module): create and sign certificate signing requests
* PEM encoding of X.509 certificates, RSA public and private keys, and certificate signing requests
* new module Extension contains X509v3 extensions as polymorphic variants
* expose distinguished_name as polymorphic variant
* type pubkey is now public_key
* function cert_pubkey is now public_key
* functions supports_usage, supports_extended_usage are now in Extension module
* types key_usage, extended_key_usage are now in Extension module
* Encoding.Pem.Cert has been renamed to Encoding.Pem.Certificate
* Encoding.Pem.PK has been renamed to Encoding.Pem.Private_key (now uses type private_key instead of Nocrypto.Rsa.priv)

0.3.1 (2015-05-02):
* PKCS8 private key info support (only unencrypted keys so far)

0.3.0 (2015-03-19):
* more detailed error messages (type certificate_failure modified)
* no longer Printf.printf debug messages
* error reporting: `Ok of certificate option | `Fail of certificate_failure
* fingerprint verification can work with None as host (useful for client authentication where host is not known upfront)
* API reshape: X509 is the only public module, X509.t is the abstract certificate

0.2.1 (2014-12-21):
* server_fingerprint authenticator which validates the server certificate based on a hash algorithm and (server_name * fingerprint) list instead of a set of trust anchors
* whitelist CAcert certificates (which do not include mandatory X.509v3 KeyUsage extension)

0.2.0 (2014-10-30):
* expose Certificate.cert_hostnames, wildcard_matches
* Certificate.verify_chain_of_trust and X509.authenticate both return now
  [ `Ok of certificate | `Fail of certificate_failure ], where [certificate] is the trust anchor

0.1.0 (2014-07-08):
* initial beta release
